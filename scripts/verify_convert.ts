/**
 * verify_convert.ts
 * TDD verification script for the Key Convert feature.
 * Pattern: vite-node + Node assert (no test framework).
 */

import assert from 'assert';
import { generateKeyPair } from '../src/utils/ssh';
import {
    detectPrivateKeyFormat,
    convertPrivateKey,
    changePassphrase,
    type ConvertResult,
} from '../src/utils/ssh';
import { parsePpk, encodePpk } from '../src/utils/ppk';
import sshpk from 'sshpk';

// ---------- helpers ----------

function publicKeyBody(pem: string, passphrase?: string): string {
    const key = sshpk.parsePrivateKey(pem, 'auto', passphrase ? { passphrase } : undefined);
    const pub = key.toPublic();
    const buf = pub.toBuffer('rfc4253');
    return buf.toString('base64');
}

function ppkPublicKeyBody(ppkText: string, passphrase?: string): string {
    const key = parsePpk(ppkText, passphrase);
    const pub = key.toPublic();
    const buf = pub.toBuffer('rfc4253');
    return buf.toString('base64');
}

// ---------- test runner ----------

type TestFn = () => void | Promise<void>;
const tests: Array<{ name: string; fn: TestFn }> = [];
function test(name: string, fn: TestFn) {
    tests.push({ name, fn });
}

async function run() {
    console.log('\n=== verify_convert.ts ===\n');
    let passed = 0;
    let failed = 0;

    for (const { name, fn } of tests) {
        try {
            await fn();
            console.log(`  PASS  ${name}`);
            passed++;
        } catch (e: unknown) {
            console.error(`  FAIL  ${name}`);
            console.error('        ', (e as Error).message);
            failed++;
        }
    }

    console.log(`\n${passed} passed, ${failed} failed\n`);
    if (failed > 0) process.exit(1);
}

// ==========================================================================
// Test 1 — detectPrivateKeyFormat (runs first so format detection can be used
//           in subsequent tests without confusion)
// ==========================================================================

test('detectPrivateKeyFormat: openssh', () => {
    const input = '-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----';
    assert.strictEqual(detectPrivateKeyFormat(input), 'openssh');
});

test('detectPrivateKeyFormat: pkcs1 RSA', () => {
    const input = '-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----';
    assert.strictEqual(detectPrivateKeyFormat(input), 'pkcs1');
});

test('detectPrivateKeyFormat: pkcs1 EC', () => {
    const input = '-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----';
    assert.strictEqual(detectPrivateKeyFormat(input), 'pkcs1');
});

test('detectPrivateKeyFormat: pkcs8 unencrypted', () => {
    const input = '-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----';
    assert.strictEqual(detectPrivateKeyFormat(input), 'pkcs8');
});

test('detectPrivateKeyFormat: pkcs8 encrypted', () => {
    const input = '-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----';
    assert.strictEqual(detectPrivateKeyFormat(input), 'pkcs8');
});

test('detectPrivateKeyFormat: ppk', () => {
    const input = 'PuTTY-User-Key-File-2: ssh-rsa\nEncryption: none\n';
    assert.strictEqual(detectPrivateKeyFormat(input), 'ppk');
});

test('detectPrivateKeyFormat: unknown garbage', () => {
    const input = 'this is not a key';
    assert.strictEqual(detectPrivateKeyFormat(input), 'unknown');
});

// ==========================================================================
// Test 2 — RSA openssh → pkcs8 (unencrypted) → openssh round-trip
// ==========================================================================

test('RSA: openssh → pkcs8 → openssh round-trip preserves public key', async () => {
    const rsa = await generateKeyPair('rsa', 2048);
    const originalBody = publicKeyBody(rsa.privateKey);

    const toPkcs8 = convertPrivateKey(rsa.privateKey, { targetFormat: 'pkcs8' });
    assert.strictEqual(toPkcs8.format, 'pkcs8', 'format should be pkcs8');
    assert.ok(toPkcs8.privateKey.includes('BEGIN PRIVATE KEY'), 'pkcs8 header present');

    const backToOpenssh = convertPrivateKey(toPkcs8.privateKey, { targetFormat: 'openssh' });
    assert.strictEqual(backToOpenssh.format, 'openssh');
    const finalBody = publicKeyBody(backToOpenssh.privateKey);
    assert.strictEqual(finalBody, originalBody, 'public key body must match after round-trip');
});

test('ED25519: openssh → pkcs8 → openssh round-trip preserves public key', async () => {
    const ed = await generateKeyPair('ed25519');
    const originalBody = publicKeyBody(ed.privateKey);

    const toPkcs8 = convertPrivateKey(ed.privateKey, { targetFormat: 'pkcs8' });
    assert.strictEqual(toPkcs8.format, 'pkcs8');

    const backToOpenssh = convertPrivateKey(toPkcs8.privateKey, { targetFormat: 'openssh' });
    const finalBody = publicKeyBody(backToOpenssh.privateKey);
    assert.strictEqual(finalBody, originalBody, 'ED25519 public key body must match after round-trip');
});

test('ECDSA: openssh → pkcs8 → openssh round-trip preserves public key', async () => {
    const ecdsa = await generateKeyPair('ecdsa', 256);
    const originalBody = publicKeyBody(ecdsa.privateKey);

    const toPkcs8 = convertPrivateKey(ecdsa.privateKey, { targetFormat: 'pkcs8' });
    assert.strictEqual(toPkcs8.format, 'pkcs8');

    const backToOpenssh = convertPrivateKey(toPkcs8.privateKey, { targetFormat: 'openssh' });
    const finalBody = publicKeyBody(backToOpenssh.privateKey);
    assert.strictEqual(finalBody, originalBody, 'ECDSA public key body must match after round-trip');
});

// ==========================================================================
// Test 3 — RSA openssh → pkcs1 → openssh round-trip
// ==========================================================================

test('RSA: openssh → pkcs1 → openssh round-trip preserves public key', async () => {
    const rsa = await generateKeyPair('rsa', 2048);
    const originalBody = publicKeyBody(rsa.privateKey);

    const toPkcs1 = convertPrivateKey(rsa.privateKey, { targetFormat: 'pkcs1' });
    assert.strictEqual(toPkcs1.format, 'pkcs1');
    assert.ok(toPkcs1.privateKey.includes('BEGIN RSA PRIVATE KEY'), 'pkcs1 RSA header present');

    const backToOpenssh = convertPrivateKey(toPkcs1.privateKey, { targetFormat: 'openssh' });
    const finalBody = publicKeyBody(backToOpenssh.privateKey);
    assert.strictEqual(finalBody, originalBody, 'RSA public key body must match after pkcs1 round-trip');
});

// ==========================================================================
// Test 4 — ED25519 + ECDSA → pkcs1 must throw friendly error
// ==========================================================================

test('ED25519 → pkcs1 throws friendly error', async () => {
    const ed = await generateKeyPair('ed25519');
    assert.throws(
        () => convertPrivateKey(ed.privateKey, { targetFormat: 'pkcs1' }),
        (err: Error) => {
            assert.ok(
                err.message.toLowerCase().includes('pkcs#1') ||
                err.message.toLowerCase().includes('rsa-only') ||
                err.message.toLowerCase().includes('rsa only'),
                `Error message should mention PKCS#1 RSA-only, got: "${err.message}"`
            );
            return true;
        }
    );
});

test('ECDSA → pkcs1 throws friendly error', async () => {
    const ecdsa = await generateKeyPair('ecdsa', 256);
    assert.throws(
        () => convertPrivateKey(ecdsa.privateKey, { targetFormat: 'pkcs1' }),
        (err: Error) => {
            assert.ok(
                err.message.toLowerCase().includes('pkcs#1') ||
                err.message.toLowerCase().includes('rsa-only') ||
                err.message.toLowerCase().includes('rsa only'),
                `Error message should mention PKCS#1 RSA-only, got: "${err.message}"`
            );
            return true;
        }
    );
});

// ==========================================================================
// Test 5 — Passphrase chain round-trip
// ==========================================================================

test('RSA passphrase chain: no-pass → pw1 → pw2 → no-pass preserves public key', async () => {
    const rsa = await generateKeyPair('rsa', 2048);
    const originalBody = publicKeyBody(rsa.privateKey);

    // Step 1: add passphrase pw1
    const withPw1 = convertPrivateKey(rsa.privateKey, {
        targetFormat: 'openssh',
        targetPassphrase: 'pw1',
    });
    assert.strictEqual(withPw1.format, 'openssh');
    const body1 = publicKeyBody(withPw1.privateKey, 'pw1');
    assert.strictEqual(body1, originalBody, 'public key after pw1 must match');

    // Step 2: change to pw2
    const withPw2 = convertPrivateKey(withPw1.privateKey, {
        targetFormat: 'openssh',
        sourcePassphrase: 'pw1',
        targetPassphrase: 'pw2',
    });
    assert.strictEqual(withPw2.format, 'openssh');
    const body2 = publicKeyBody(withPw2.privateKey, 'pw2');
    assert.strictEqual(body2, originalBody, 'public key after pw2 must match');

    // Step 3: remove passphrase
    const noPass = convertPrivateKey(withPw2.privateKey, {
        targetFormat: 'openssh',
        sourcePassphrase: 'pw2',
    });
    assert.strictEqual(noPass.format, 'openssh');
    const body3 = publicKeyBody(noPass.privateKey);
    assert.strictEqual(body3, originalBody, 'public key after removing passphrase must match');
});

test('ED25519 passphrase chain: no-pass → pw1 → no-pass', async () => {
    const ed = await generateKeyPair('ed25519');
    const originalBody = publicKeyBody(ed.privateKey);

    const withPw = convertPrivateKey(ed.privateKey, { targetFormat: 'openssh', targetPassphrase: 'secretpass' });
    const body1 = publicKeyBody(withPw.privateKey, 'secretpass');
    assert.strictEqual(body1, originalBody, 'ED25519 pubkey with pw must match');

    const noPass = convertPrivateKey(withPw.privateKey, {
        targetFormat: 'openssh',
        sourcePassphrase: 'secretpass',
    });
    const body2 = publicKeyBody(noPass.privateKey);
    assert.strictEqual(body2, originalBody, 'ED25519 pubkey after removing pw must match');
});

// ==========================================================================
// Test 6 — PKCS#1 + passphrase auto-upgrade to PKCS#8
// ==========================================================================

test('RSA: openssh → pkcs1 with passphrase upgrades to pkcs8 with note', async () => {
    const rsa = await generateKeyPair('rsa', 2048);

    const result: ConvertResult = convertPrivateKey(rsa.privateKey, {
        targetFormat: 'pkcs1',
        targetPassphrase: 'mypassword',
    });

    assert.strictEqual(result.format, 'pkcs8', 'actual format should be pkcs8 (upgraded)');
    assert.ok(result.privateKey.includes('BEGIN ENCRYPTED PRIVATE KEY'), 'output should be encrypted pkcs8');
    assert.ok(Array.isArray(result.notes) && result.notes.length > 0, 'notes should be present');
    assert.ok(
        result.notes!.some(n => n.toLowerCase().includes('pkcs#1') || n.toLowerCase().includes('pkcs8') || n.toLowerCase().includes('upgraded')),
        `notes should mention upgrade, got: ${JSON.stringify(result.notes)}`
    );

    // The encrypted PKCS#8 must be machine-readable: parse it back via sshpk
    // with the same passphrase and confirm the public key body is preserved.
    const reparsed = sshpk.parsePrivateKey(result.privateKey, 'pkcs8', { passphrase: 'mypassword' });
    const reparsedBody = reparsed.toPublic().toBuffer('rfc4253').toString('base64');
    const originalBody = publicKeyBody(rsa.privateKey);
    assert.strictEqual(reparsedBody, originalBody, 'encrypted pkcs8 must decrypt back to original public key');
});

test('RSA: openssh → pkcs8 with passphrase produces encrypted pkcs8 that re-parses', async () => {
    const rsa = await generateKeyPair('rsa', 2048);
    const originalBody = publicKeyBody(rsa.privateKey);

    const result = convertPrivateKey(rsa.privateKey, {
        targetFormat: 'pkcs8',
        targetPassphrase: 'pk8pass',
    });

    assert.strictEqual(result.format, 'pkcs8');
    assert.ok(
        result.privateKey.includes('BEGIN ENCRYPTED PRIVATE KEY'),
        `pkcs8 + passphrase must produce ENCRYPTED PRIVATE KEY, got header: ${result.privateKey.split('\n')[0]}`
    );

    const reparsed = sshpk.parsePrivateKey(result.privateKey, 'pkcs8', { passphrase: 'pk8pass' });
    const reparsedBody = reparsed.toPublic().toBuffer('rfc4253').toString('base64');
    assert.strictEqual(reparsedBody, originalBody, 'encrypted pkcs8 (direct target) must decrypt to original');
});

// ==========================================================================
// Test 7 — PPK round-trips
// ==========================================================================

test('RSA: openssh → ppk (unencrypted) → openssh preserves public key', async () => {
    const rsa = await generateKeyPair('rsa', 2048);
    const originalBody = publicKeyBody(rsa.privateKey);

    const toPpk = convertPrivateKey(rsa.privateKey, { targetFormat: 'ppk' });
    assert.strictEqual(toPpk.format, 'ppk');
    assert.ok(toPpk.privateKey.startsWith('PuTTY-User-Key-File-'), 'PPK header present');

    const backToOpenssh = convertPrivateKey(toPpk.privateKey, { targetFormat: 'openssh' });
    const finalBody = publicKeyBody(backToOpenssh.privateKey);
    assert.strictEqual(finalBody, originalBody, 'RSA pubkey must match after PPK round-trip');
});

test('ED25519: openssh → ppk (unencrypted) → openssh preserves public key', async () => {
    const ed = await generateKeyPair('ed25519');
    const originalBody = publicKeyBody(ed.privateKey);

    const toPpk = convertPrivateKey(ed.privateKey, { targetFormat: 'ppk' });
    assert.strictEqual(toPpk.format, 'ppk');
    assert.ok(toPpk.privateKey.startsWith('PuTTY-User-Key-File-'), 'PPK header present');

    const backToOpenssh = convertPrivateKey(toPpk.privateKey, { targetFormat: 'openssh' });
    const finalBody = publicKeyBody(backToOpenssh.privateKey);
    assert.strictEqual(finalBody, originalBody, 'ED25519 pubkey must match after PPK round-trip');
});

test('RSA: openssh → ppk + passphrase → openssh preserves public key', async () => {
    const rsa = await generateKeyPair('rsa', 2048);
    const originalBody = publicKeyBody(rsa.privateKey);

    const toPpk = convertPrivateKey(rsa.privateKey, {
        targetFormat: 'ppk',
        targetPassphrase: 'ppkpassword',
        comment: 'test-rsa-key',
    });
    assert.strictEqual(toPpk.format, 'ppk');

    // Parse PPK back via parsePpk with passphrase
    const ppkBody = ppkPublicKeyBody(toPpk.privateKey, 'ppkpassword');
    assert.strictEqual(ppkBody, originalBody, 'RSA pubkey must match after encrypted PPK round-trip');

    // Convert back to openssh via convertPrivateKey (source must supply passphrase)
    const backToOpenssh = convertPrivateKey(toPpk.privateKey, {
        targetFormat: 'openssh',
        sourcePassphrase: 'ppkpassword',
    });
    const finalBody = publicKeyBody(backToOpenssh.privateKey);
    assert.strictEqual(finalBody, originalBody, 'RSA openssh pubkey must match after encrypted PPK round-trip');
});

test('ED25519: openssh → ppk + passphrase → openssh preserves public key', async () => {
    const ed = await generateKeyPair('ed25519');
    const originalBody = publicKeyBody(ed.privateKey);

    const toPpk = convertPrivateKey(ed.privateKey, {
        targetFormat: 'ppk',
        targetPassphrase: 'edpassword',
        comment: 'test-ed25519-key',
    });
    assert.strictEqual(toPpk.format, 'ppk');

    const ppkBody = ppkPublicKeyBody(toPpk.privateKey, 'edpassword');
    assert.strictEqual(ppkBody, originalBody, 'ED25519 pubkey must match after encrypted PPK round-trip');

    const backToOpenssh = convertPrivateKey(toPpk.privateKey, {
        targetFormat: 'openssh',
        sourcePassphrase: 'edpassword',
    });
    const finalBody = publicKeyBody(backToOpenssh.privateKey);
    assert.strictEqual(finalBody, originalBody, 'ED25519 openssh pubkey must match after encrypted PPK round-trip');
});

test('ECDSA: openssh → ppk (unencrypted) → openssh preserves public key', async () => {
    const ecdsa = await generateKeyPair('ecdsa', 256);
    const originalBody = publicKeyBody(ecdsa.privateKey);

    const toPpk = convertPrivateKey(ecdsa.privateKey, { targetFormat: 'ppk' });
    assert.strictEqual(toPpk.format, 'ppk');
    assert.ok(toPpk.privateKey.startsWith('PuTTY-User-Key-File-'), 'PPK header present');

    const backToOpenssh = convertPrivateKey(toPpk.privateKey, { targetFormat: 'openssh' });
    const finalBody = publicKeyBody(backToOpenssh.privateKey);
    assert.strictEqual(finalBody, originalBody, 'ECDSA pubkey must match after PPK round-trip');
});

test('ECDSA: openssh → ppk + passphrase → openssh preserves public key', async () => {
    const ecdsa = await generateKeyPair('ecdsa', 256);
    const originalBody = publicKeyBody(ecdsa.privateKey);

    const toPpk = convertPrivateKey(ecdsa.privateKey, {
        targetFormat: 'ppk',
        targetPassphrase: 'ecpassword',
        comment: 'test-ecdsa-key',
    });
    assert.strictEqual(toPpk.format, 'ppk');

    const ppkBody = ppkPublicKeyBody(toPpk.privateKey, 'ecpassword');
    assert.strictEqual(ppkBody, originalBody, 'ECDSA pubkey must match after encrypted PPK round-trip');

    const backToOpenssh = convertPrivateKey(toPpk.privateKey, {
        targetFormat: 'openssh',
        sourcePassphrase: 'ecpassword',
    });
    const finalBody = publicKeyBody(backToOpenssh.privateKey);
    assert.strictEqual(finalBody, originalBody, 'ECDSA openssh pubkey must match after encrypted PPK round-trip');
});

// ==========================================================================
// Test 8 — PPK fixture round-trips (bootstrapped from encodePpk)
// ==========================================================================
// We generate the PPK fixtures using encodePpk itself (acceptable bootstrapping per plan).
// The critical assertions are: parsePpk correctly extracts key type and the public
// key body matches what sshpk knows about the key.

test('PPK fixture: RSA key round-trips through parsePpk/encodePpk with comment', async () => {
    const rsa = await generateKeyPair('rsa', 2048);
    const rsaKey = sshpk.parsePrivateKey(rsa.privateKey, 'auto');
    const comment = 'fixture-rsa@test';

    const ppkText = encodePpk(rsaKey, { comment, version: 2 });
    assert.ok(ppkText.startsWith('PuTTY-User-Key-File-2:'), 'PPK v2 header');

    const parsed = parsePpk(ppkText);
    assert.strictEqual(parsed.type, 'rsa', `key type should be rsa, got: ${parsed.type}`);

    // Comment round-trip
    assert.strictEqual(parsed.comment, comment, 'comment should round-trip');

    // Public key body must match
    const originalBuf = rsaKey.toPublic().toBuffer('rfc4253').toString('base64');
    const parsedBuf = parsed.toPublic().toBuffer('rfc4253').toString('base64');
    assert.strictEqual(parsedBuf, originalBuf, 'RSA PPK fixture public key must match');
});

test('PPK fixture: ED25519 key round-trips through parsePpk/encodePpk with comment', async () => {
    const ed = await generateKeyPair('ed25519');
    const edKey = sshpk.parsePrivateKey(ed.privateKey, 'auto');
    const comment = 'fixture-ed25519@test';

    const ppkText = encodePpk(edKey, { comment, version: 2 });
    assert.ok(ppkText.startsWith('PuTTY-User-Key-File-2:'), 'PPK v2 header');

    const parsed = parsePpk(ppkText);
    assert.strictEqual(parsed.type, 'ed25519', `key type should be ed25519, got: ${parsed.type}`);
    assert.strictEqual(parsed.comment, comment, 'comment should round-trip');

    const originalBuf = edKey.toPublic().toBuffer('rfc4253').toString('base64');
    const parsedBuf = parsed.toPublic().toBuffer('rfc4253').toString('base64');
    assert.strictEqual(parsedBuf, originalBuf, 'ED25519 PPK fixture public key must match');
});

test('PPK fixture: encrypted PPK comment round-trip', async () => {
    const ed = await generateKeyPair('ed25519');
    const edKey = sshpk.parsePrivateKey(ed.privateKey, 'auto');
    const comment = 'encrypted-fixture@test';
    const pass = 'testpassphrase123';

    const ppkText = encodePpk(edKey, { comment, passphrase: pass, version: 2 });
    assert.ok(ppkText.includes('Encryption: aes256-cbc'), 'should be encrypted');

    const parsed = parsePpk(ppkText, pass);
    assert.strictEqual(parsed.comment, comment, 'comment should round-trip through encrypted PPK');

    const originalBuf = edKey.toPublic().toBuffer('rfc4253').toString('base64');
    const parsedBuf = parsed.toPublic().toBuffer('rfc4253').toString('base64');
    assert.strictEqual(parsedBuf, originalBuf, 'ED25519 encrypted PPK fixture public key must match');
});

// ==========================================================================
// Test: changePassphrase preserves format and public key
// ==========================================================================

test('changePassphrase: RSA openssh preserves format and public key', async () => {
    const rsa = await generateKeyPair('rsa', 2048);
    const originalBody = publicKeyBody(rsa.privateKey);

    // Add initial passphrase
    const withPw = convertPrivateKey(rsa.privateKey, { targetFormat: 'openssh', targetPassphrase: 'old123' });

    // Change passphrase
    const changed = changePassphrase(withPw.privateKey, 'old123', 'new456');
    assert.strictEqual(changed.format, 'openssh', 'format should remain openssh');

    const body = publicKeyBody(changed.privateKey, 'new456');
    assert.strictEqual(body, originalBody, 'public key must match after passphrase change');
});

test('changePassphrase: ED25519 openssh preserves format and public key', async () => {
    const ed = await generateKeyPair('ed25519');
    const originalBody = publicKeyBody(ed.privateKey);

    const withPw = convertPrivateKey(ed.privateKey, { targetFormat: 'openssh', targetPassphrase: 'oldpass' });
    const changed = changePassphrase(withPw.privateKey, 'oldpass', 'newpass');
    assert.strictEqual(changed.format, 'openssh');

    const body = publicKeyBody(changed.privateKey, 'newpass');
    assert.strictEqual(body, originalBody, 'ED25519 public key must match after passphrase change');
});

// ==========================================================================
// Edge cases
// ==========================================================================

test('convertPrivateKey: empty input throws', () => {
    assert.throws(() => convertPrivateKey('', { targetFormat: 'openssh' }), /failed|parse|invalid/i);
});

test('convertPrivateKey: garbage input throws', () => {
    assert.throws(() => convertPrivateKey('not a key', { targetFormat: 'openssh' }), /failed|parse|invalid/i);
});

test('detectPrivateKeyFormat: empty string returns unknown', () => {
    assert.strictEqual(detectPrivateKeyFormat(''), 'unknown');
});

// Run all tests
run();
