import { generateKeyPair, derivePublicKey } from '../src/utils/ssh';
import assert from 'assert';

async function runVerify() {
    console.log('Running SSH Keytool Verification (Async)...');

    try {
        // Test RSA
        console.log('Testing RSA generation...');
        const rsa = await generateKeyPair('rsa', 2048);
        console.log('Generated RSA Private Key:', rsa.privateKey.substring(0, 50) + '...');
        console.log('Generated RSA Public Key:', rsa.publicKey);
        // RSA private keys from sshpk (parsed from PKCS8) exported as openssh might look like PEM
        // sshpk default for openssh is old PEM if possible, or new format.
        // Let's check generally.
        assert(rsa.privateKey.includes('PRIVATE KEY'), 'RSA private key valid');
        assert(rsa.publicKey.startsWith('ssh-rsa'), 'RSA public key starts with ssh-rsa');
        console.log('RSA Key Pair generated successfully.');

        // Test ED25519
        console.log('Testing ED25519 generation...');
        const ed = await generateKeyPair('ed25519');
        assert(ed.privateKey.includes('OPENSSH PRIVATE KEY'), 'ED25519 private key format valid');
        assert(ed.publicKey.startsWith('ssh-ed25519'), 'ED25519 public key starts with ssh-ed25519');
        console.log('ED25519 Key Pair generated successfully.');

        // Test ECDSA
        console.log('Testing ECDSA generation...');
        const ecdsa = await generateKeyPair('ecdsa', 256);
        assert(ecdsa.privateKey.includes('OPENSSH PRIVATE KEY') || ecdsa.privateKey.includes('EC PRIVATE KEY'), 'ECDSA private key format valid');
        assert(ecdsa.publicKey.startsWith('ecdsa-sha2-nistp256'), 'ECDSA public key starts with ecdsa-sha2-nistp256');
        console.log('ECDSA Key Pair generated successfully.');

        // Test Derivation (using RSA key)
        console.log('Testing Public Key Derivation (RSA)...');
        const derived = derivePublicKey(rsa.privateKey);
        const derivedBody = derived.trim().split(' ')[1];
        const originalBody = rsa.publicKey.trim().split(' ')[1];
        assert.strictEqual(derivedBody, originalBody, 'Derived public key matches original');
        console.log('Public Key Derivation verified.');

        console.log('All tests passed!');
    } catch (e) {
        console.error('Verification Failed:', e);
        process.exit(1);
    }
}

runVerify();
