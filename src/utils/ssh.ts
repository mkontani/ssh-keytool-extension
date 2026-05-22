import sshpk from 'sshpk';
import { parsePpk, encodePpk } from './ppk';
import { randomBytes, pbkdf2Sync, createCipheriv } from 'crypto';

// ---------------------------------------------------------------------------
// PKCS#5v2 encrypted PKCS#8 helper (PBKDF2-SHA256 + AES-256-CBC)
// Produces a valid "BEGIN ENCRYPTED PRIVATE KEY" PEM that can be parsed back.
// ---------------------------------------------------------------------------

/** Write a DER tag+length+value triple. */
function derTLV(tag: number, content: Buffer): Buffer {
    const len = content.length;
    let lenBytes: Buffer;
    if (len < 0x80) {
        lenBytes = Buffer.from([len]);
    } else if (len < 0x100) {
        lenBytes = Buffer.from([0x81, len]);
    } else if (len <= 0xFFFF) {
        lenBytes = Buffer.from([0x82, (len >> 8) & 0xff, len & 0xff]);
    } else {
        throw new Error(`DER length ${len} exceeds implementation limit (65535)`);
    }
    return Buffer.concat([Buffer.from([tag]), lenBytes, content]);
}

/** DER SEQUENCE wrapper. */
const derSEQ = (c: Buffer) => derTLV(0x30, c);
/** DER OCTET STRING. */
const derOCT = (c: Buffer) => derTLV(0x04, c);
/** DER INTEGER (arbitrary bytes). */
const derINT = (c: Buffer) => derTLV(0x02, c);
/** DER OID from dot-notation string (pre-encoded as hex for known OIDs). */
const derOID = (hex: string) => derTLV(0x06, Buffer.from(hex, 'hex'));

/** Encode a positive integer as a minimal DER INTEGER. */
function derPositiveInt(n: number): Buffer {
    const hex = n.toString(16).padStart(n < 0x80 ? 2 : n < 0x8000 ? 4 : 8, '0');
    let buf = Buffer.from(hex, 'hex');
    if (buf[0] & 0x80) buf = Buffer.concat([Buffer.from([0x00]), buf]);
    return derINT(buf);
}

/**
 * Encrypt a PKCS#8 private key using PKCS#5v2 (PBKDF2-SHA256 + AES-256-CBC).
 * Returns a PEM string with "BEGIN ENCRYPTED PRIVATE KEY" header.
 *
 * ASN.1 structure (RFC 5958):
 *   EncryptedPrivateKeyInfo ::= SEQUENCE {
 *     encryptionAlgorithm  AlgorithmIdentifier { PBES2-Algs },
 *     encryptedData        OCTET STRING
 *   }
 */
function encryptPkcs8(key: sshpk.PrivateKey, passphrase: string): string {
    // sshpk's toBuffer('pkcs8') returns PEM TEXT bytes (header + base64), not raw DER.
    // Strip the PEM wrapper to obtain the raw PrivateKeyInfo DER that PBES2 expects.
    const pkcs8Pem = key.toBuffer('pkcs8').toString('utf8');
    const pkcs8B64 = pkcs8Pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
    const pkcs8Der = Buffer.from(pkcs8B64, 'base64');

    // Generate salt and IV
    const salt = randomBytes(16);
    const iv = randomBytes(16);

    // Derive key: PBKDF2-SHA256, 210,000 iterations (OWASP 2023 recommendation
    // for PBKDF2-HMAC-SHA256), 32 bytes.
    const iterations = 210000;
    const derivedKey = pbkdf2Sync(passphrase, salt, iterations, 32, 'sha256');

    // Encrypt. Node's createCipheriv applies PKCS#7 padding automatically
    // (autoPadding defaults to true) — do NOT pre-pad or output is unparseable.
    const cipher = createCipheriv('aes-256-cbc', derivedKey, iv);
    const encrypted = Buffer.concat([cipher.update(pkcs8Der), cipher.final()]);

    // --- Build PKCS#5v2 ASN.1 structure ---
    // OID hex encodings (DER):
    //   PBES2           1.2.840.113549.1.5.13   2a864886f70d01050d
    //   PBKDF2          1.2.840.113549.1.5.12   2a864886f70d01050c
    //   hmacWithSHA256  1.2.840.113549.2.9      2a864886f70d0209
    //   AES-256-CBC     2.16.840.1.101.3.4.1.42 60864801650304012a

    // PRF AlgorithmIdentifier: SEQUENCE { hmacWithSHA256, NULL }
    const hmacAlgId = derSEQ(Buffer.concat([
        derOID('2a864886f70d0209'),
        derTLV(0x05, Buffer.alloc(0)), // NULL
    ]));

    // PBKDF2 params: SEQUENCE { salt, iterations, PRF }
    const pbkdf2Params = derSEQ(Buffer.concat([
        derOCT(salt),
        derPositiveInt(iterations),
        hmacAlgId,
    ]));

    // PBKDF2 AlgorithmIdentifier: SEQUENCE { PBKDF2 OID, pbkdf2Params }
    const pbkdf2AlgId = derSEQ(Buffer.concat([
        derOID('2a864886f70d01050c'),
        pbkdf2Params,
    ]));

    // AES-256-CBC AlgorithmIdentifier: SEQUENCE { AES-256-CBC OID, IV }
    const aesAlgId = derSEQ(Buffer.concat([
        derOID('60864801650304012a'),
        derOCT(iv),
    ]));

    // PBES2 params: SEQUENCE { PBKDF2 AlgId, AES AlgId }
    const pbes2Params = derSEQ(Buffer.concat([pbkdf2AlgId, aesAlgId]));

    // Outer algorithm identifier: SEQUENCE { PBES2 OID, PBES2 params }
    const outerAlgId = derSEQ(Buffer.concat([
        derOID('2a864886f70d01050d'),
        pbes2Params,
    ]));

    // EncryptedPrivateKeyInfo: SEQUENCE { outerAlgId, encryptedData }
    const epki = derSEQ(Buffer.concat([outerAlgId, derOCT(encrypted)]));

    // Wrap in PEM
    const b64 = epki.toString('base64');
    const lines = b64.match(/.{1,64}/g)!.join('\n');
    return `-----BEGIN ENCRYPTED PRIVATE KEY-----\n${lines}\n-----END ENCRYPTED PRIVATE KEY-----\n`;
}

export interface KeyPair {
    privateKey: string;
    publicKey: string;
}

export type KeyType = 'rsa' | 'ed25519' | 'ecdsa';

// ============================================================
// Key Convert types and exports
// ============================================================

export type PrivateKeyFormat = 'openssh' | 'pkcs1' | 'pkcs8' | 'ppk';

export interface ConvertOptions {
    targetFormat: PrivateKeyFormat;
    sourcePassphrase?: string;
    targetPassphrase?: string;
    comment?: string;
}

export interface ConvertResult {
    privateKey: string;
    format: PrivateKeyFormat;
    keyType: KeyType;
    notes?: string[];
}

export const detectPrivateKeyFormat = (input: string): PrivateKeyFormat | 'unknown' => {
    const trimmed = input.trimStart();
    if (trimmed.startsWith('PuTTY-User-Key-File-')) return 'ppk';
    if (trimmed.startsWith('-----BEGIN OPENSSH PRIVATE KEY-----')) return 'openssh';
    if (
        trimmed.startsWith('-----BEGIN RSA PRIVATE KEY-----') ||
        trimmed.startsWith('-----BEGIN EC PRIVATE KEY-----') ||
        trimmed.startsWith('-----BEGIN DSA PRIVATE KEY-----')
    ) return 'pkcs1';
    if (
        trimmed.startsWith('-----BEGIN PRIVATE KEY-----') ||
        trimmed.startsWith('-----BEGIN ENCRYPTED PRIVATE KEY-----')
    ) return 'pkcs8';
    return 'unknown';
};

export const convertPrivateKey = (input: string, opts: ConvertOptions): ConvertResult => {
    const { targetFormat, sourcePassphrase, targetPassphrase, comment } = opts;

    // Parse the source key
    let key: sshpk.PrivateKey;
    const detectedFmt = detectPrivateKeyFormat(input);

    if (detectedFmt === 'ppk') {
        try {
            key = parsePpk(input, sourcePassphrase);
        } catch (e: unknown) {
            throw new Error(`Failed to parse PPK key: ${(e as Error).message}`);
        }
    } else {
        try {
            key = sshpk.parsePrivateKey(
                input,
                detectedFmt === 'unknown' ? 'auto' : detectedFmt,
                sourcePassphrase ? { passphrase: sourcePassphrase } : undefined
            );
        } catch (e: unknown) {
            throw new Error(`Failed to parse private key: ${(e as Error).message}`);
        }
    }

    // Determine the actual key algorithm type
    const keyType: KeyType = key.type === 'rsa'
        ? 'rsa'
        : key.type === 'ed25519'
            ? 'ed25519'
            : 'ecdsa';

    // Guard: PKCS#1 only supports RSA
    if (targetFormat === 'pkcs1' && keyType !== 'rsa') {
        throw new Error(
            `PKCS#1 is RSA-only. Cannot export ${key.type.toUpperCase()} key as PKCS#1. Use openssh or pkcs8 instead.`
        );
    }

    // PKCS#1 + passphrase rule: auto-upgrade to PKCS#8 (encrypted PKCS#1 is non-standard)
    if (targetFormat === 'pkcs1' && targetPassphrase && targetPassphrase.length > 0) {
        // Produce a real PKCS#5v2 encrypted PKCS#8 using PBKDF2 + AES-256-CBC.
        const privateKey = encryptPkcs8(key, targetPassphrase);
        return {
            privateKey,
            format: 'pkcs8',
            keyType,
            notes: [
                'Encrypted PKCS#1 is not standard; output upgraded to PKCS#8.',
            ],
        };
    }

    const notes: string[] = [];
    let privateKey: string;
    const actualFormat: PrivateKeyFormat = targetFormat;

    if (targetFormat === 'ppk') {
        privateKey = encodePpk(key, {
            passphrase: targetPassphrase && targetPassphrase.length > 0 ? targetPassphrase : undefined,
            comment: comment || key.comment || undefined,
            version: 2,
        });
    } else if (targetFormat === 'openssh') {
        if (comment) {
            key.comment = comment;
        }
        if (targetPassphrase && targetPassphrase.length > 0) {
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            privateKey = key.toString('openssh', { passphrase: targetPassphrase } as any);
        } else {
            privateKey = key.toString('openssh');
        }
    } else if (targetFormat === 'pkcs1') {
        // Unencrypted PKCS#1 (RSA-only, already guarded above)
        privateKey = key.toString('pkcs1');
    } else {
        if (targetPassphrase && targetPassphrase.length > 0) {
            privateKey = encryptPkcs8(key, targetPassphrase);
        } else {
            privateKey = key.toString('pkcs8');
        }
    }

    return { privateKey, format: actualFormat, keyType, notes: notes.length > 0 ? notes : undefined };
};

export const changePassphrase = (input: string, oldPass: string, newPass: string): ConvertResult => {
    const sourceFormat = detectPrivateKeyFormat(input);
    const targetFormat: PrivateKeyFormat = sourceFormat === 'unknown' ? 'openssh' : sourceFormat;
    return convertPrivateKey(input, {
        targetFormat,
        sourcePassphrase: oldPass,
        targetPassphrase: newPass || undefined,
    });
};

// Helper to access Web Crypto API (browser or Node)
const getCrypto = () => {
    if (typeof window !== 'undefined' && window.crypto) return window.crypto;
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore - Web Crypto API might be on global in some environments
    if (typeof crypto !== 'undefined') return crypto;
    throw new Error('Web Crypto API not available');
};

const arrayBufferToBase64 = (buffer: ArrayBuffer): string => {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return typeof btoa === 'function' ? btoa(binary) : Buffer.from(binary, 'binary').toString('base64');
};

const toPem = (buffer: ArrayBuffer, label: string) => {
    const base64 = arrayBufferToBase64(buffer);
    const chunks = base64.match(/.{1,64}/g)!.join('\n');
    return `-----BEGIN ${label}-----\n${chunks}\n-----END ${label}-----`;
};

const formatPublicKey = (key: sshpk.PrivateKey): string => {
    const pub = key.toPublic();
    let publicKey = pub.toString('openssh');

    // If output is PEM-like (RFC4716), convert to standard one-line OpenSSH format
    if (publicKey.startsWith('-----BEGIN')) {
        const buf = pub.toBuffer('rfc4253');
        const len = buf.readUInt32BE(0);
        const type = buf.slice(4, 4 + len).toString('ascii');
        const base64 = buf.toString('base64');
        publicKey = `${type} ${base64} ${pub.comment || ''}`.trim();
    }
    return publicKey;
};

export const generateKeyPair = async (
    type: KeyType,
    size: number = 2048,
    passphrase?: string
): Promise<KeyPair> => {
    let key: sshpk.PrivateKey;

    if (type === 'rsa') {
        const subtle = getCrypto().subtle;
        const pair = await subtle.generateKey(
            {
                name: "RSASSA-PKCS1-v1_5",
                modulusLength: size,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: "SHA-256",
            },
            true,
            ["sign", "verify"]
        );
        const privateKeyDER = await subtle.exportKey("pkcs8", pair.privateKey!);
        const privateKeyPEM = toPem(privateKeyDER, "PRIVATE KEY");
        // Parse back with sshpk to get sshpk object
        key = sshpk.parsePrivateKey(privateKeyPEM, 'pkcs8');
    } else if (type === 'ecdsa') {
        const ecdsaOpts: { curve: string } = { curve: 'nistp256' };
        if (size === 384) ecdsaOpts.curve = 'nistp384';
        else if (size === 521) ecdsaOpts.curve = 'nistp521';

        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        // @ts-ignore - type mismatch due to restrictive sshpk overloads
        key = sshpk.generatePrivateKey('ecdsa', ecdsaOpts);
    } else {
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        // @ts-ignore - type mismatch due to restrictive sshpk overloads
        key = sshpk.generatePrivateKey('ed25519', {});
    }

    let privateKey: string;
    if (passphrase && passphrase.length > 0) {
        // Generate encrypted OpenSSH private key
        privateKey = key.toString('openssh', { passphrase });
    } else {
        // 'openssh' format
        privateKey = key.toString('openssh');
    }

    const publicKey = formatPublicKey(key);

    return { privateKey, publicKey };
};

export const derivePublicKey = (privateKeyPEM: string, passphrase?: string): string => {
    try {
        const key = sshpk.parsePrivateKey(privateKeyPEM, 'auto', passphrase ? { passphrase } : undefined);
        return formatPublicKey(key);
    } catch (e) {
        console.error(e);
        throw new Error('Failed to parse private key. Check format and passphrase.');
    }
};

export interface CertificateInfo {
    type: string;
    keyId: string;
    validAfter: Date;
    validBefore: Date;
    principals: string[];
    extensions: Record<string, string>;
    criticalOptions: Record<string, string>;
    signatureKey: string;
}

export const parseCertificate = (certPEM: string): CertificateInfo => {
    try {
        const cert = sshpk.parseCertificate(certPEM, 'openssh');

        // Type casting to unknown then to a custom shape to access SSH-specific props not in @types/sshpk
        const raw = cert as unknown as {
            type: string;
            subjects: Array<{
                uid?: string;
                components: Array<{ name: string; value: { toString: () => string } }>;
                principals?: string[];
                comment?: string;
            }>;
            signatures: {
                openssh?: {
                    keyId?: string;
                    exts?: Array<{ name: string; critical: boolean; value: boolean | string; data?: Buffer }>;
                };
            };
            subjectKey?: { type: string };
            issuerKey?: { fingerprint: (alg: string) => { toString: () => string } };
        };
        const openssh = raw.signatures && raw.signatures.openssh ? raw.signatures.openssh : {};

        // Extract principals: sshpk maps them to multiple 'subjects' for multiple principals
        let principals: string[] = [];
        if (raw.subjects && Array.isArray(raw.subjects)) {
            for (const s of raw.subjects) {
                // eslint-disable-next-line @typescript-eslint/no-explicit-any
                const subject = s as any;
                if (subject.uid) {
                    principals.push(subject.uid as string);
                } else if (subject.components && Array.isArray(subject.components)) {
                    const uids = subject.components
                        .filter((c: { name: string }) => c.name === 'uid')
                        .map((c: { value: { toString: () => string } }) => c.value.toString());
                    principals.push(...uids);
                } else if (subject.principals && Array.isArray(subject.principals)) {
                    principals.push(...(subject.principals as string[]));
                }
            }
        }

        // Remove duplicates and clean up
        principals = [...new Set(principals)];

        // Extensions and Critical Options
        const exts: Record<string, string> = {};
        const opts: Record<string, string> = {};

        if (openssh.exts) {
            for (const ext of openssh.exts) {
                if (ext.critical) {
                    opts[ext.name] = ext.value === true ? 'true' : ext.data ? ext.data.toString() : '';
                } else {
                    exts[ext.name] = ext.value === true ? 'true' : ext.data ? ext.data.toString() : '';
                }
            }
        }

        // Type reconstruction (rough guess if not available)
        let typeStr = raw.type || 'unknown';
        if (raw.subjectKey && raw.subjectKey.type) {
            typeStr = raw.subjectKey.type + '-cert-v01@openssh.com';
        }

        return {
            type: typeStr,
            keyId: openssh.keyId || (raw.subjects[0] && (raw.subjects[0] as { comment?: string }).comment) || '',
            validAfter: cert.validFrom,
            validBefore: cert.validUntil,
            principals: principals,
            extensions: exts,
            criticalOptions: opts,
            signatureKey: cert.issuerKey ? cert.issuerKey.fingerprint('sha256').toString() : 'unknown'
        };
    } catch (e) {
        console.error(e);
        throw new Error('Failed to parse certificate.');
    }
};
