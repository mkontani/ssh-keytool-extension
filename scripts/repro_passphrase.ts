import { generateKeyPair } from '../src/utils/ssh';
import sshpk from 'sshpk';

async function run() {
    console.log('Testing Passphrase Encryption...');
    const passphrase = 'mysecretpassword';

    // Test RSA
    console.log('Generating RSA with passphrase...');
    const rsa = await generateKeyPair('rsa', 2048, passphrase);
    console.log('Private Key Start:', rsa.privateKey.substring(0, 40));

    try {
        // Try parsing without passphrase - should fail if encrypted
        sshpk.parsePrivateKey(rsa.privateKey, 'auto');
        console.error('FAIL: RSA Private Key parsed WITHOUT passphrase (it is NOT encrypted)');
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } catch (e: any) {
        if (e.name === 'KeyEncryptedError') {
            console.log('PASS: RSA Key is encrypted.');
        } else {
            console.log('Received expected error:', e.message);
        }
    }

}

run();
