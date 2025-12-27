const sshpk = require('sshpk');

try {
    console.log('Testing RSA generation with sshpk...');
    const key = sshpk.generatePrivateKey('rsa', { size: 2048 });
    console.log('Generated RSA Key:', key.fingerprint('md5').toString());

    console.log('Testing ECDSA...');
    const ecdsa = sshpk.generatePrivateKey('ecdsa', { curve: 'nistp256' });
    console.log('Generated ECDSA Key:', ecdsa.fingerprint('md5').toString());

    console.log('Success!');
} catch (e) {
    console.error('Error:', e);
}
