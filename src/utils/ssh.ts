import sshpk from 'sshpk';

export interface KeyPair {
    privateKey: string;
    publicKey: string;
}

export type KeyType = 'rsa' | 'ed25519' | 'ecdsa';

// Helper to access Web Crypto API (browser or Node)
const getCrypto = () => {
    if (typeof window !== 'undefined' && window.crypto) return window.crypto;
    // @ts-ignore
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
    } else {
        // ECDSA / ED25519 supported by sshpk generation
        let opts: any = {};
        if (type === 'ecdsa') {
            if (size === 256) opts.curve = 'nistp256';
            else if (size === 384) opts.curve = 'nistp384';
            else if (size === 521) opts.curve = 'nistp521';
            else opts.curve = 'nistp256';
        }
        // sshpk.generatePrivateKey expects specific type strings or uses defaults
        key = sshpk.generatePrivateKey(type as any, opts);
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
