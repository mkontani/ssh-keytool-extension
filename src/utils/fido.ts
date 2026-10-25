/**
 * fido.ts — FIDO/U2F security-key backed SSH keys (OpenSSH "sk-" key types).
 *
 * sshpk has no support for sk-* key types, so this module reads the SSH wire
 * format directly (see OpenSSH PROTOCOL.u2f and PROTOCOL.key):
 *
 *  - Public key blob:
 *      sk-ssh-ed25519@openssh.com:          string type, string pk, string application
 *      sk-ecdsa-sha2-nistp256@openssh.com:  string type, string curve, string Q, string application
 *  - "openssh-key-v1" private key file: the private section repeats the public
 *    fields, followed by uint8 flags, string key_handle, string reserved.
 *    The "private key" is only a handle; signing still needs the authenticator.
 *
 * Uses Node's crypto (polyfilled in browser by vite-plugin-node-polyfills) and
 * bcrypt-pbkdf (the same KDF implementation sshpk uses for OpenSSH keys).
 */

import { createHash, createDecipheriv } from 'crypto';
import bcryptPbkdf from 'bcrypt-pbkdf';
import { hasUnsafeChars } from './text';

export const FIDO_KEY_TYPES = [
    'sk-ssh-ed25519@openssh.com',
    'sk-ecdsa-sha2-nistp256@openssh.com',
] as const;

export type FidoKeyType = typeof FIDO_KEY_TYPES[number];

export interface FidoFlags {
    raw: number;
    /** Touch required for every signature (cleared by `-O no-touch-required`). */
    userPresenceRequired: boolean;
    /** PIN required for every signature (`-O verify-required`). */
    userVerificationRequired: boolean;
    /** Discoverable credential stored on the authenticator (`-O resident`). */
    residentKey: boolean;
}

export interface FidoPublicKeyInfo {
    type: FidoKeyType;
    application: string;
    comment: string;
    /** `SHA256:<base64>` exactly as printed by `ssh-keygen -l`. */
    fingerprint: string;
    /** One-line OpenSSH public key. */
    publicKey: string;
}

export interface FidoKeyDetails {
    flags: FidoFlags;
    keyHandleLength: number;
}

export interface FidoPrivateKeyInfo extends FidoPublicKeyInfo {
    /** `none` for unencrypted keys. */
    cipher: string;
    /** bcrypt KDF rounds (`ssh-keygen -a`); null for unencrypted keys. */
    kdfRounds: number | null;
    /** Null when the key is encrypted and no passphrase was given. */
    details: FidoKeyDetails | null;
}

export type FidoInspection =
    | { kind: 'public'; key: FidoPublicKeyInfo }
    | { kind: 'private'; key: FidoPrivateKeyInfo };

// Flag bits from OpenSSH sk-api.h
const SK_USER_PRESENCE_REQD = 0x01;
const SK_USER_VERIFICATION_REQD = 0x04;
const SK_RESIDENT_KEY = 0x20;

const PRIVATE_KEY_BEGIN = '-----BEGIN OPENSSH PRIVATE KEY-----';
const PRIVATE_KEY_END = '-----END OPENSSH PRIVATE KEY-----';
const AUTH_MAGIC = Buffer.from('openssh-key-v1\0', 'binary');

/** Guards the UI against keys whose KDF cost would freeze the page (ssh-keygen defaults to 24, 32 in newer releases). */
const MAX_BCRYPT_ROUNDS = 1024;

interface CipherSpec {
    nodeName: string;
    keyLength: number;
    ivLength: number;
    blockSize: number;
}

const CIPHERS: Record<string, CipherSpec> = {
    'aes128-ctr': { nodeName: 'aes-128-ctr', keyLength: 16, ivLength: 16, blockSize: 16 },
    'aes192-ctr': { nodeName: 'aes-192-ctr', keyLength: 24, ivLength: 16, blockSize: 16 },
    'aes256-ctr': { nodeName: 'aes-256-ctr', keyLength: 32, ivLength: 16, blockSize: 16 },
    'aes128-cbc': { nodeName: 'aes-128-cbc', keyLength: 16, ivLength: 16, blockSize: 16 },
    'aes192-cbc': { nodeName: 'aes-192-cbc', keyLength: 24, ivLength: 16, blockSize: 16 },
    'aes256-cbc': { nodeName: 'aes-256-cbc', keyLength: 32, ivLength: 16, blockSize: 16 },
};

/** Block size OpenSSH pads unencrypted private sections to. */
const UNENCRYPTED_BLOCK_SIZE = 8;

const PUBLIC_KEY_RE =
    /(?:^|\s)(sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)\s+([A-Za-z0-9+/]+={0,2})(?:[ \t]+([^\r\n]*))?/;
const FIDO_CERT_RE = /sk-[a-z0-9-]+-cert-v01@openssh\.com/;
const OTHER_PUBLIC_KEY_RE = /(?:^|\s)((?:ssh|ecdsa)-[A-Za-z0-9@.-]+)\s+AAAA/;

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/** Sequential reader for SSH wire-format (RFC 4251) data. */
class WireReader {
    private readonly buf: Buffer;
    private pos = 0;

    constructor(buf: Buffer) {
        this.buf = buf;
    }

    get offset(): number {
        return this.pos;
    }

    get remaining(): number {
        return this.buf.length - this.pos;
    }

    uint8(): number {
        return this.take(1)[0];
    }

    uint32(): number {
        return this.take(4).readUInt32BE(0);
    }

    string(): Buffer {
        return this.take(this.uint32());
    }

    text(): string {
        return this.string().toString('utf8');
    }

    rest(): Buffer {
        return this.take(this.remaining);
    }

    slice(start: number, end: number): Buffer {
        return this.buf.subarray(start, end);
    }

    private take(n: number): Buffer {
        if (n > this.remaining) throw new Error('Invalid key data: truncated.');
        const out = this.buf.subarray(this.pos, this.pos + n);
        this.pos += n;
        return out;
    }
}

const isFidoKeyType = (type: string): type is FidoKeyType =>
    (FIDO_KEY_TYPES as readonly string[]).includes(type);

/** Key type names are short printable ASCII; anything else is shown generically. */
const describeKeyType = (type: string): string =>
    /^[\x21-\x7e]{1,64}$/.test(type) ? type : '(unrecognized key type)';

interface FidoPublicFields {
    type: FidoKeyType;
    application: string;
    /** The raw public key blob covering exactly the fields read. */
    blob: Buffer;
}

/** Read the public fields shared by the public blob and the private section. */
function readFidoPublicFields(r: WireReader): FidoPublicFields {
    const start = r.offset;
    const type = r.text();
    if (!isFidoKeyType(type)) {
        throw new Error(`Not a FIDO (sk-) key: ${describeKeyType(type)}`);
    }
    if (type === 'sk-ecdsa-sha2-nistp256@openssh.com') {
        const curve = r.text();
        if (curve !== 'nistp256') throw new Error(`Invalid key data: unexpected curve "${describeKeyType(curve)}".`);
        const q = r.string();
        if (q.length !== 65 || q[0] !== 0x04) throw new Error('Invalid key data: malformed ECDSA public point.');
    } else {
        const pk = r.string();
        if (pk.length !== 32) throw new Error('Invalid key data: malformed Ed25519 public key.');
    }
    const application = r.text();
    return { type, application, blob: r.slice(start, r.offset) };
}

const fingerprintOf = (blob: Buffer): string =>
    `SHA256:${createHash('sha256').update(blob).digest('base64').replace(/=+$/, '')}`;

const publicKeyLine = (type: FidoKeyType, blob: Buffer, comment: string): string =>
    comment ? `${type} ${blob.toString('base64')} ${comment}` : `${type} ${blob.toString('base64')}`;

const toPublicInfo = (fields: FidoPublicFields, comment: string): FidoPublicKeyInfo => {
    // A newline in the comment would smuggle an extra entry into copied authorized_keys lines.
    if (hasUnsafeChars(comment)) {
        throw new Error('Invalid key data: the comment contains control or invisible formatting characters.');
    }
    return {
        type: fields.type,
        application: fields.application,
        comment,
        fingerprint: fingerprintOf(fields.blob),
        publicKey: publicKeyLine(fields.type, fields.blob, comment),
    };
};

const decodeFlags = (raw: number): FidoFlags => ({
    raw,
    userPresenceRequired: (raw & SK_USER_PRESENCE_REQD) !== 0,
    userVerificationRequired: (raw & SK_USER_VERIFICATION_REQD) !== 0,
    residentKey: (raw & SK_RESIDENT_KEY) !== 0,
});

interface PrivateKeyContainer {
    cipher: string;
    kdf: string;
    kdfOptions: Buffer;
    publicBlob: Buffer;
    privateSection: Buffer;
    trailingBytes: number;
}

/** Decode the PEM armor and the unencrypted "openssh-key-v1" header. */
function readContainer(input: string): PrivateKeyContainer {
    const begin = input.indexOf(PRIVATE_KEY_BEGIN);
    const end = input.indexOf(PRIVATE_KEY_END);
    if (begin === -1 || end < begin) {
        throw new Error('Not an OpenSSH private key (expected "-----BEGIN OPENSSH PRIVATE KEY-----").');
    }
    const body = input.slice(begin + PRIVATE_KEY_BEGIN.length, end).replace(/\s+/g, '');
    const raw = Buffer.from(body, 'base64');
    if (!raw.subarray(0, AUTH_MAGIC.length).equals(AUTH_MAGIC)) {
        throw new Error('Not an OpenSSH private key: missing "openssh-key-v1" header.');
    }
    const r = new WireReader(raw.subarray(AUTH_MAGIC.length));
    const cipher = r.text();
    const kdf = r.text();
    const kdfOptions = r.string();
    const keyCount = r.uint32();
    if (keyCount !== 1) throw new Error(`Unsupported key file: contains ${keyCount} keys (expected 1).`);
    const publicBlob = r.string();
    const privateSection = r.string();
    return { cipher, kdf, kdfOptions, publicBlob, privateSection, trailingBytes: r.remaining };
}

function readPublicBlob(blob: Buffer): FidoPublicFields {
    const r = new WireReader(blob);
    const fields = readFidoPublicFields(r);
    if (r.remaining !== 0) throw new Error('Invalid key data: trailing bytes after public key.');
    return fields;
}

interface BcryptOptions {
    salt: Buffer;
    rounds: number;
}

function readBcryptOptions(kdfOptions: Buffer): BcryptOptions {
    const r = new WireReader(kdfOptions);
    const salt = r.string();
    const rounds = r.uint32();
    return { salt, rounds };
}

function decryptPrivateSection(c: PrivateKeyContainer, passphrase: string): Buffer {
    const spec = CIPHERS[c.cipher];
    if (!spec) {
        throw new Error(
            `Unsupported cipher: ${describeKeyType(c.cipher)}. ` +
            'Re-encrypt the key with "ssh-keygen -p -Z aes256-ctr -f <file>" and try again.'
        );
    }
    if (c.kdf !== 'bcrypt') throw new Error(`Unsupported KDF: ${describeKeyType(c.kdf)}.`);
    if (c.trailingBytes !== 0) throw new Error('Invalid key data: trailing bytes after private section.');
    if (c.privateSection.length % spec.blockSize !== 0) {
        throw new Error('Invalid key data: encrypted section is not block aligned.');
    }

    const { salt, rounds } = readBcryptOptions(c.kdfOptions);
    if (rounds < 1 || rounds > MAX_BCRYPT_ROUNDS) {
        throw new Error(`Unsupported KDF rounds: ${rounds} (supported: 1-${MAX_BCRYPT_ROUNDS}).`);
    }

    const pass = Buffer.from(passphrase, 'utf8');
    const derived = Buffer.alloc(spec.keyLength + spec.ivLength);
    if (bcryptPbkdf.pbkdf(pass, pass.length, salt, salt.length, derived, derived.length, rounds) !== 0) {
        throw new Error('Key derivation (bcrypt_pbkdf) failed.');
    }

    const decipher = createDecipheriv(
        spec.nodeName,
        derived.subarray(0, spec.keyLength),
        derived.subarray(spec.keyLength),
    );
    decipher.setAutoPadding(false);
    return Buffer.concat([decipher.update(c.privateSection), decipher.final()]);
}

interface PrivateSectionContents {
    details: FidoKeyDetails;
    comment: string;
}

function readPrivateSection(plain: Buffer, publicBlob: Buffer, encrypted: boolean): PrivateSectionContents {
    const r = new WireReader(plain);
    const check1 = r.uint32();
    const check2 = r.uint32();
    if (check1 !== check2) {
        throw new Error(encrypted ? 'Incorrect passphrase.' : 'Invalid key data: check bytes do not match.');
    }
    const fields = readFidoPublicFields(r);
    if (!fields.blob.equals(publicBlob)) {
        throw new Error('Invalid key data: private section does not match the public key.');
    }
    const flags = r.uint8();
    const keyHandle = r.string();
    r.string(); // reserved
    const comment = r.text();
    const padding = r.rest();
    if (!padding.every((byte, i) => byte === ((i + 1) & 0xff))) {
        throw new Error('Invalid key data: bad padding.');
    }
    return { details: { flags: decodeFlags(flags), keyHandleLength: keyHandle.length }, comment };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Parse a FIDO public key line (`sk-... AAAA... [comment]`).
 * A leading authorized_keys options field is tolerated and ignored.
 */
export const parseFidoPublicKey = (input: string): FidoPublicKeyInfo => {
    const match = PUBLIC_KEY_RE.exec(input);
    if (!match) {
        if (FIDO_CERT_RE.test(input)) {
            throw new Error('FIDO certificates are not supported yet. Paste the plain public key instead.');
        }
        const other = OTHER_PUBLIC_KEY_RE.exec(input);
        throw new Error(other
            ? `Not a FIDO (sk-) key: ${other[1]}`
            : 'Not a FIDO public key. Expected "sk-ssh-ed25519@openssh.com AAAA..." or "sk-ecdsa-sha2-nistp256@openssh.com AAAA...".'
        );
    }
    const [, textType, base64, comment = ''] = match;
    const fields = readPublicBlob(Buffer.from(base64, 'base64'));
    if (fields.type !== textType) {
        throw new Error(`Key type mismatch: the line says ${textType} but the key data is ${fields.type}.`);
    }
    return toPublicInfo(fields, comment.trim());
};

/**
 * Parse an OpenSSH FIDO private key file (the key handle file written by
 * `ssh-keygen -t ed25519-sk|ecdsa-sk`).
 *
 * Without a passphrase, an encrypted key still yields its public data
 * (type, application, fingerprint), but `details` is null and the comment
 * is empty because both live in the encrypted section.
 */
export const parseFidoPrivateKey = (input: string, passphrase?: string): FidoPrivateKeyInfo => {
    const container = readContainer(input);
    const fields = readPublicBlob(container.publicBlob);
    const encrypted = container.cipher !== 'none';
    const kdfRounds = container.kdf === 'bcrypt' ? readBcryptOptions(container.kdfOptions).rounds : null;

    if (encrypted && !passphrase) {
        return { ...toPublicInfo(fields, ''), cipher: container.cipher, kdfRounds, details: null };
    }

    let plain: Buffer;
    if (encrypted) {
        plain = decryptPrivateSection(container, passphrase as string);
    } else {
        if (container.kdf !== 'none') throw new Error(`Invalid key data: KDF "${describeKeyType(container.kdf)}" without a cipher.`);
        if (container.trailingBytes !== 0) throw new Error('Invalid key data: trailing bytes after private section.');
        if (container.privateSection.length % UNENCRYPTED_BLOCK_SIZE !== 0) {
            throw new Error('Invalid key data: private section is not block aligned.');
        }
        plain = container.privateSection;
    }

    const { details, comment } = readPrivateSection(plain, container.publicBlob, encrypted);
    return { ...toPublicInfo(fields, comment), cipher: container.cipher, kdfRounds, details };
};

/** Cheap check (no decryption) for an OpenSSH private key file holding an sk-* key. */
export const isFidoPrivateKey = (input: string): boolean => {
    try {
        const container = readContainer(input);
        return isFidoKeyType(new WireReader(container.publicBlob).text());
    } catch {
        return false;
    }
};

/** Inspect either a FIDO public key line or a FIDO private key file. */
export const inspectFidoKey = (input: string, passphrase?: string): FidoInspection =>
    input.includes(PRIVATE_KEY_BEGIN)
        ? { kind: 'private', key: parseFidoPrivateKey(input, passphrase) }
        : { kind: 'public', key: parseFidoPublicKey(input) };

/** Derive the one-line public key from a FIDO private key file. */
export const deriveFidoPublicKey = (input: string, passphrase?: string): string => {
    const info = parseFidoPrivateKey(input, passphrase);
    if (!info.details) throw new Error('This FIDO key is encrypted. Enter its passphrase.');
    return info.publicKey;
};
