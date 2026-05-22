/**
 * ppk.ts — PuTTY Private Key (PPK) format support.
 *
 * PPK v2 read + write (full support).
 * PPK v3 read-only (Argon2id KDF requires a native module not available here;
 *   sshpk's built-in putty reader throws for encrypted v3 keys, which is the
 *   only case we can't handle — unencrypted v3 structure is identical to v2).
 *
 * Implementation notes:
 *  - Uses sshpk's built-in putty format reader for parsePpk (it supports both
 *    v2 and unencrypted v3).
 *  - encodePpk hand-rolls the PPK v2 text format because sshpk's putty writer
 *    only exports public keys, not full private key PPK files.
 *  - PPK v2 private blob layout mirrors sshpk's rfc4253 wire format helpers.
 *  - Uses Node's crypto (polyfilled in browser by vite-plugin-node-polyfills).
 */

import sshpk from 'sshpk';
import { createHash, createCipheriv, createHmac } from 'crypto';

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/** Derive a 32-byte AES-256-CBC encryption key from a PPK v2 passphrase. */
function derivePPK2Key(passphrase: string): Buffer {
    const pass = Buffer.from(passphrase, 'utf8');
    const h1 = createHash('sha1').update(Buffer.concat([Buffer.from([0, 0, 0, 0]), pass])).digest();
    const h2 = createHash('sha1').update(Buffer.concat([Buffer.from([0, 0, 0, 1]), pass])).digest();
    return Buffer.concat([h1, h2]).subarray(0, 32);
}

/** Wrap a base64 string at 64 chars per line. */
function wrapBase64(data: Buffer): string {
    const b64 = data.toString('base64');
    const lines: string[] = [];
    for (let i = 0; i < b64.length; i += 64) {
        lines.push(b64.slice(i, i + 64));
    }
    return lines.join('\n');
}

/** Write a uint32 big-endian into a new 4-byte Buffer. */
function uint32BE(n: number): Buffer {
    const buf = Buffer.alloc(4);
    buf.writeUInt32BE(n, 0);
    return buf;
}

/** Write a length-prefixed binary string (SSH wire format). */
function sshString(data: Buffer): Buffer {
    return Buffer.concat([uint32BE(data.length), data]);
}

/** Write a length-prefixed mpint (SSH wire format, minimal positive encoding). */
function sshMpint(data: Buffer): Buffer {
    // Strip leading zero bytes, but keep at least one byte
    let start = 0;
    while (start < data.length - 1 && data[start] === 0) start++;
    let trimmed = data.slice(start);
    // If high bit is set, prepend 0x00
    if (trimmed[0] & 0x80) {
        trimmed = Buffer.concat([Buffer.from([0x00]), trimmed]);
    }
    return sshString(trimmed);
}

// ---------------------------------------------------------------------------
// Build private blobs for PPK v2 (SSH wire format for the private portion)
// ---------------------------------------------------------------------------

/** Raw accessor for sshpk private key parts (not in @types/sshpk). */
type SshpkPart = { name: string; data: Buffer };

function getKeyParts(key: sshpk.PrivateKey): SshpkPart[] {
    return (key as unknown as { parts: SshpkPart[] }).parts;
}

function getPart(key: sshpk.PrivateKey, name: string): Buffer {
    const parts = getKeyParts(key);
    const p = parts.find(x => x.name === name);
    if (!p) throw new Error(`PPK: key part '${name}' not found in ${key.type} key`);
    return p.data;
}

/**
 * Build the public blob (rfc4253 wire format) for a PPK file.
 * sshpk's toPublic().toBuffer('rfc4253') gives exactly this.
 */
function buildPublicBlob(key: sshpk.PrivateKey): Buffer {
    return key.toPublic().toBuffer('rfc4253');
}

/**
 * Build the private blob for a PPK v2 file.
 * Layout is key-type specific, defined by PuTTY source.
 */
function buildPrivateBlob(key: sshpk.PrivateKey): Buffer {
    switch (key.type) {
        case 'rsa': {
            // PPK private blob for RSA: d, p, q, iqmp (all mpints)
            const d = getPart(key, 'd');
            const p = getPart(key, 'p');
            const q = getPart(key, 'q');
            const iqmp = getPart(key, 'iqmp');
            return Buffer.concat([
                sshMpint(d),
                sshMpint(p),
                sshMpint(q),
                sshMpint(iqmp),
            ]);
        }
        case 'ed25519': {
            // PPK private blob for ED25519: just k (32-byte scalar)
            const k = getPart(key, 'k');
            return sshString(k);
        }
        case 'ecdsa': {
            // PPK private blob for ECDSA: d (mpint)
            const d = getPart(key, 'd');
            return sshMpint(d);
        }
        default:
            throw new Error(`encodePpk: unsupported key type: ${key.type}`);
    }
}

/**
 * Compute the PPK v2 MAC.
 * HMAC-SHA1 over: alg + encryption + comment + public blob + private blob.
 */
function computePPK2Mac(
    alg: string,
    encryption: string,
    comment: string,
    publicBlob: Buffer,
    privateBlob: Buffer,
    passphrase?: string
): string {
    // The MAC key for PPK v2 is SHA-1("putty-private-key-file-mac-key" + passphrase)
    const macKeyData = passphrase
        ? Buffer.concat([Buffer.from('putty-private-key-file-mac-key'), Buffer.from(passphrase, 'utf8')])
        : Buffer.from('putty-private-key-file-mac-key');
    const macKey = createHash('sha1').update(macKeyData).digest();

    // MAC input: each field as a uint32-length-prefixed string
    const algBuf = Buffer.from(alg, 'utf8');
    const encBuf = Buffer.from(encryption, 'utf8');
    const comBuf = Buffer.from(comment, 'utf8');

    const macInput = Buffer.concat([
        uint32BE(algBuf.length), algBuf,
        uint32BE(encBuf.length), encBuf,
        uint32BE(comBuf.length), comBuf,
        uint32BE(publicBlob.length), publicBlob,
        uint32BE(privateBlob.length), privateBlob,
    ]);

    return createHmac('sha1', macKey).update(macInput).digest('hex');
}

/** Map sshpk key type to PPK algorithm string. */
function keyTypeToAlg(key: sshpk.PrivateKey): string {
    switch (key.type) {
        case 'rsa': return 'ssh-rsa';
        case 'ed25519': return 'ssh-ed25519';
        case 'ecdsa': {
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            const curve = (key as any).part?.curve?.data?.toString() ||
                getPart(key, 'curve').toString('ascii').replace(/\0/g, '');
            return `ecdsa-sha2-${curve}`;
        }
        default:
            throw new Error(`encodePpk: unsupported key type: ${key.type}`);
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Parse a PuTTY PPK v2 or v3 private key file.
 *
 * PPK v3 with passphrase is not supported (sshpk throws for encrypted v3).
 * PPK v3 without passphrase parses identically to v2.
 */
export const parsePpk = (text: string, passphrase?: string): sshpk.PrivateKey => {
    const opts: { passphrase?: string } = {};
    if (passphrase && passphrase.length > 0) {
        opts.passphrase = passphrase;
    }
    // sshpk's built-in putty reader handles v2 (encrypted + unencrypted) and v3 (unencrypted).
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const key = sshpk.parsePrivateKey(Buffer.from(text, 'utf8'), 'putty' as any, opts);
    return key;
};

/**
 * Encode a private key as a PuTTY PPK v2 file.
 *
 * PPK v3 write is intentionally NOT supported (Argon2id KDF would require a
 * heavy dependency). Only `version: 2` is accepted to make the constraint a
 * compile-time error rather than a silent downgrade.
 */
export const encodePpk = (
    key: sshpk.PrivateKey,
    opts?: { passphrase?: string; comment?: string; version?: 2 }
): string => {
    const passphrase = opts?.passphrase && opts.passphrase.length > 0 ? opts.passphrase : undefined;
    const comment = opts?.comment ?? key.comment ?? '';
    const alg = keyTypeToAlg(key);
    const encryption = passphrase ? 'aes256-cbc' : 'none';

    const publicBlob = buildPublicBlob(key);
    let privateBlob = buildPrivateBlob(key);

    if (passphrase) {
        // PPK v2 private encryption: AES-256-CBC, no padding (pad to 16-byte boundary with zeros)
        const paddedLen = Math.ceil(privateBlob.length / 16) * 16;
        const padded = Buffer.alloc(paddedLen, 0);
        privateBlob.copy(padded);

        const iv = Buffer.alloc(16, 0);
        const cipher = createCipheriv('aes-256-cbc', derivePPK2Key(passphrase), iv);
        cipher.setAutoPadding(false);
        privateBlob = Buffer.concat([cipher.update(padded), cipher.final()]);
    }

    const mac = computePPK2Mac(alg, encryption, comment, publicBlob, privateBlob, passphrase);

    const lines: string[] = [
        `PuTTY-User-Key-File-2: ${alg}`,
        `Encryption: ${encryption}`,
        `Comment: ${comment}`,
        `Public-Lines: ${Math.ceil(publicBlob.toString('base64').length / 64)}`,
        wrapBase64(publicBlob),
        `Private-Lines: ${Math.ceil(privateBlob.toString('base64').length / 64)}`,
        wrapBase64(privateBlob),
        `Private-MAC: ${mac}`,
    ];

    return lines.join('\n') + '\n';
};
