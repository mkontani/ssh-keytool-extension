import sshpk from 'sshpk';

export interface KeyPair {
    privateKey: string;
    publicKey: string;
}

export type KeyType = 'rsa' | 'ed25519' | 'ecdsa';

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
