import { parseCertificate } from '../src/utils/ssh';
import sshpk from 'sshpk';

// Sample SSH Certificate (Ed25519)
// Generatable via: ssh-keygen -t ed25519 -f test_key -N "" && ssh-keygen -s test_key -I test_user -n user1,user2 -V +52w test_key.pub
// For manual test, we'll try to generate one if possible or use a hardcoded mocked one if sshpk supports cert generation easily.
// sshpk supports creating certificates.

async function run() {
    console.log('Testing Certificate Inspection...');

    try {
        // 1. Generate CA Key
        const caKey = sshpk.generatePrivateKey('ed25519');
        console.log('CA Key generated.');

        // 2. Generate User Key
        const userKey = sshpk.generatePrivateKey('ed25519');
        console.log('User Key generated.');

        // 3. Create Certificate
        const id = sshpk.identityForUser('user1');
        const cert = sshpk.createCertificate(id, userKey, id, caKey);

        // Set standard SSH cert properties (sshpk way)
        // sshpk's createCertificate makes X.509 by default? No, let's check.
        // Actually sshpk is mainly for SSH, but the terminology often overlaps.
        // Let's force it to be an SSH certificate if possible or just use a dummy string if we can't gen easily.

        // Simpler approach: Use a known valid SSH Cert string for testing parsing logic
        // But we want to be self-contained.

        // Let's try to just parse a mocked cert string if we can't generate one easily.
        // OR better: rely on `sshpk` to create it.

        cert.validFrom = new Date();
        cert.validUntil = new Date(Date.now() + 1000 * 60 * 60 * 24 * 365); // 1 year
        cert.signatures = {}; // Clears X.509 sigs?

        // Sign it as OpenSSH certificate
        cert.signWith(caKey);

        // Convert to OpenSSH format string
        // Note: sshpk might default to X.509 certs unless we specify OpenSSH format on export
        // AND the object structure must be correct for SSH certs.

        // If sshpk.createCertificate creates an X.509 parsed object, toOpenSSH might fail or produce weird output.
        // Let's try to verify if `parseCertificate` works on it.

        // Actually, let's look at `sshpk` docs/source methodology again.
        // `sshpk.createCertificate` creates a Certificate object.
        // To make it an *SSH* certificate, we usually need proper subjects/issuer.

        // Bypass generation complexity: Use a hardcoded valid cert string (RSA)
        // This is a sample RSA-CERT from a test vector or generated locally
        const sampleCert = `ssh-rsa-cert-v01@openssh.com AAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20AAAAg2S/u+5J6dGvBqf5v48Wk8A5J5w6q5v48Wk8A5J5w6q4AAAADAQABAAABAQDDt+YxpCNBK4w/Q0KP5PvZoHMmlj41Je1oEY73leL9M5rwScJ5V/4EpN53gfZl9lbUR4lxK5xxubiUk+JfTMVMwS6HfZjfAEc7SISh7kC/0a+I6ECHI3cl2LPTMy9IAoX5fMxGdQOKql5Gx9oiDII4v1uvE5+FORZqtoZY1rlJie+FvDEU197BRf/lbX2CetJx0Z5quE1lkmcF5RDeU1Cxt9zu1yy5kFvXFWopLYiWyOj9YiMBvmyMVlyroonCzgWDf8b2sat+rFnjo8c4ETjq/cg4f+PGaCfd4H20vtco9R2mnBCnr2PsB/VY30E/vnPhUmsIzRnfBsmQBlRlsUjDAAAAAAAAAAAAAAABAAAAQXJvb3QAAAAAAACAAAAABXVzZXIAAAAAAAAAAA==`;
        // Note: The above is just a placeholder pattern, likely invalid. 
        // We need a REAL cert string to test parsing.

        // Let's generate one on the fly using sshpk if possible, or skip deep validation and just check if we can structure the object.
        // Since we can't easily execute `ssh-keygen` in this environment (maybe?)
        // Let's check `parseCertificate` handles errors gracefully at least.

        // Better: We can use `sshpk` to generate a self-signed cert and see if it exports to 'openssh'.

        console.log('Generating Self-Signed Cert for test...');
        const certObj = sshpk.createSelfSignedCertificate(id, userKey);
        const certPem = certObj.toString('openssh');
        console.log('Cert PEM:', certPem);

        const valid = parseCertificate(certPem);
        console.log('Parsed Info:', valid);

        // Debug full object structure to find missing fields
        const rawCert = sshpk.parseCertificate(certPem, 'openssh');
        // console.log('Full Raw Cert:', JSON.stringify(rawCert, null, 2));


    } catch (e) {
        console.error('Test Failed:', e);
    }
}

run();
