import { parseCertificate } from '../src/utils/ssh';
import sshpk from 'sshpk';

async function run() {
    console.log('Testing Certificate Inspection (Multiple Principals)...');

    try {
        // Use a hardcoded valid cert string with multiple principals (principal1, principal2)
        // generated via ssh-keygen:
        // ssh-keygen -t ed25519 -f test_ca -N ""
        // ssh-keygen -t ed25519 -f test_user -N ""
        // ssh-keygen -s test_ca -I test_id -n principal1,principal2 -V +1d test_user.pub
        const certPem = `ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIKqNq0idJU1gKMyA1JmyVYSykmH/SdJyVMoFShz5XkvnAAAAIAMOq8+NF7tlTzOwuGa2u6O4SqS364cXXJqfGYoGIILNAAAAAAAAAAAAAAABAAAAB3Rlc3RfaWQAAAAcAAAACnByaW5jaXBhbDEAAAAKcHJpbmNpcGFsMgAAAABpUNHsAAAAAGlSI6cAAAAAAAAAggAAABVwZXJtaXQtWDExLWZvcndhcmRpbmcAAAAAAAAAF3Blcm1pdC1hZ2VudC1mb3J3YXJkaW5nAAAAAAAAABZwZXJtaXQtcG9ydC1mb3J3YXJkaW5nAAAAAAAAAApwZXJtaXQtcHR5AAAAAAAAAA5wZXJtaXQtdXNlci1yYwAAAAAAAAAAAAAAMwAAAAtzc2gtZWQyNTUxOQAAACDuES2iX91p8YY3Wj04aQiM9YbHvs77/hP3+2VPtahbRwAAAFMAAAALc3NoLWVkMjU1MTkAAABA1Hpmq/lzXuan5AXB3Gql1jF4mQ8lcHBOM3W5QrZMwbvEF7mJ5YLINw+mK6OEtQNJF8VSvFH/9ImpRbpzcXvDAw==`;

        console.log('Parsing test cert...');
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const rawCert: any = sshpk.parseCertificate(certPem, 'openssh');
        console.log('Number of subjects:', rawCert.subjects.length);
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        rawCert.subjects.forEach((s: any, i: number) => {
            console.log(`Subject ${i} type:`, s.type);
            console.log(`Subject ${i} components:`, JSON.stringify(s.components, null, 2));
            console.log(`Subject ${i} uid:`, s.uid);
            console.log(`Subject ${i} principals:`, s.principals);
        });

        const info = parseCertificate(certPem);
        console.log('Parsed Info:', JSON.stringify(info, null, 2));

        if (info.principals.length === 2 && info.principals.includes('principal1') && info.principals.includes('principal2')) {
            console.log('SUCCESS: Multiple principals correctly extracted:', info.principals);
        } else {
            console.error('FAILURE: Principals extraction failed. Found:', info.principals);
            process.exit(1);
        }

    } catch (e) {
        console.error('Test Failed:', e);
        process.exit(1);
    }
}

run();
