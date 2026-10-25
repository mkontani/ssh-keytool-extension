/**
 * verify_fido.ts
 * Verification script for FIDO (sk-*) key inspection and the ssh-keygen
 * command / config snippet builder.
 * Pattern: vite-node + Node assert (no test framework).
 */

import assert from 'assert';
import { generateKeyPair, derivePublicKey } from '../src/utils/ssh';
import {
    parseFidoPublicKey,
    parseFidoPrivateKey,
    isFidoPrivateKey,
    inspectFidoKey,
} from '../src/utils/fido';
import {
    buildKeygenCommand,
    validateKeygenOptions,
    buildKeygenNotes,
    buildAuthorizedKeysLine,
    buildSshdConfigLine,
    buildAllowedSignersLine,
    buildGitSigningCommands,
    authorizedKeyOptionsFromFlags,
    defaultKeyPath,
    shellQuote,
    type FidoKeygenOptions,
} from '../src/utils/fidoCommands';
import {
    FIDO_TEST_PASSPHRASE,
    ED25519_SK1,
    ED25519_SK1_PUB,
    ED25519_SK1_FP,
    ECDSA_SK1,
    ECDSA_SK1_PUB,
    ECDSA_SK1_FP,
    ED25519_SK_WORK_FLAGS24,
    ED25519_SK_WORK_FLAGS24_PUB,
    ED25519_SK_WORK_FLAGS24_FP,
    ED25519_SK1_AES256_CTR,
    ECDSA_SK1_AES256_CBC,
    ED25519_SK_WORK_FLAGS24_AES128_CTR,
    ED25519_SK1_CHACHA,
    ED25519_SK1_DEFAULT_ROUNDS,
    ED25519_SK1_NEWLINE_COMMENT,
} from './fixtures/fido';

// ---------- test runner ----------

type TestFn = () => void | Promise<void>;
const tests: Array<{ name: string; fn: TestFn }> = [];
function test(name: string, fn: TestFn) {
    tests.push({ name, fn });
}

async function run() {
    console.log('\n=== verify_fido.ts ===\n');
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

/** Strip the trailing comment from a one-line OpenSSH public key. */
const withoutComment = (line: string): string => line.split(' ').slice(0, 2).join(' ');

// ==========================================================================
// parseFidoPublicKey
// ==========================================================================

test('parseFidoPublicKey: sk-ssh-ed25519 (OpenSSH test vector)', () => {
    const info = parseFidoPublicKey(ED25519_SK1_PUB);
    assert.strictEqual(info.type, 'sk-ssh-ed25519@openssh.com');
    assert.strictEqual(info.application, 'ssh:');
    assert.strictEqual(info.comment, 'ED25519-SK test key #1');
    assert.strictEqual(info.fingerprint, ED25519_SK1_FP);
    assert.strictEqual(info.publicKey, ED25519_SK1_PUB);
});

test('parseFidoPublicKey: sk-ecdsa-sha2-nistp256 (OpenSSH test vector)', () => {
    const info = parseFidoPublicKey(ECDSA_SK1_PUB);
    assert.strictEqual(info.type, 'sk-ecdsa-sha2-nistp256@openssh.com');
    assert.strictEqual(info.application, 'ssh:');
    assert.strictEqual(info.comment, 'ECDSA-SK test key #1');
    assert.strictEqual(info.fingerprint, ECDSA_SK1_FP);
    assert.strictEqual(info.publicKey, ECDSA_SK1_PUB);
});

test('parseFidoPublicKey: custom application is decoded', () => {
    const info = parseFidoPublicKey(ED25519_SK_WORK_FLAGS24_PUB);
    assert.strictEqual(info.application, 'ssh:work');
    assert.strictEqual(info.fingerprint, ED25519_SK_WORK_FLAGS24_FP);
});

test('parseFidoPublicKey: no comment', () => {
    const info = parseFidoPublicKey(withoutComment(ED25519_SK1_PUB));
    assert.strictEqual(info.comment, '');
    assert.strictEqual(info.publicKey, withoutComment(ED25519_SK1_PUB));
});

test('parseFidoPublicKey: authorized_keys line with options prefix', () => {
    const info = parseFidoPublicKey(`no-touch-required,verify-required ${ED25519_SK1_PUB}\n`);
    assert.strictEqual(info.fingerprint, ED25519_SK1_FP);
    assert.strictEqual(info.comment, 'ED25519-SK test key #1');
});

test('parseFidoPublicKey: non-FIDO public key is rejected', async () => {
    const { publicKey } = await generateKeyPair('ed25519');
    assert.throws(() => parseFidoPublicKey(publicKey), /not a FIDO/i);
});

test('parseFidoPublicKey: FIDO certificate is rejected with a clear message', () => {
    assert.throws(
        () => parseFidoPublicKey('sk-ssh-ed25519-cert-v01@openssh.com AAAAI2NlcnQ= user'),
        /certificate/i,
    );
});

test('parseFidoPublicKey: type text that does not match the blob is rejected', () => {
    const [, blob] = ED25519_SK1_PUB.split(' ');
    assert.throws(() => parseFidoPublicKey(`sk-ecdsa-sha2-nistp256@openssh.com ${blob}`), /mismatch/i);
});

test('parseFidoPublicKey: truncated blob is rejected', () => {
    const [type, blob] = ED25519_SK1_PUB.split(' ');
    assert.throws(() => parseFidoPublicKey(`${type} ${blob.slice(0, 40)}`), /truncated|invalid/i);
});

test('parseFidoPublicKey: comment with control or bidi characters is rejected', () => {
    assert.throws(() => parseFidoPublicKey(`${withoutComment(ED25519_SK1_PUB)} evil\x1b[2Jcomment`), /comment/i);
    assert.throws(() => parseFidoPublicKey(`${withoutComment(ED25519_SK1_PUB)} abc\u202Edef`), /comment/i);
});

test('parseFidoPublicKey: garbage is rejected', () => {
    assert.throws(() => parseFidoPublicKey('hello world'), /not a FIDO|no .*key/i);
});

// ==========================================================================
// parseFidoPrivateKey — unencrypted
// ==========================================================================

test('parseFidoPrivateKey: ed25519-sk unencrypted (flags 0x01)', () => {
    const info = parseFidoPrivateKey(ED25519_SK1);
    assert.strictEqual(info.type, 'sk-ssh-ed25519@openssh.com');
    assert.strictEqual(info.cipher, 'none');
    assert.strictEqual(info.application, 'ssh:');
    assert.strictEqual(info.comment, 'ED25519-SK test key #1');
    assert.strictEqual(info.fingerprint, ED25519_SK1_FP);
    assert.strictEqual(info.publicKey, ED25519_SK1_PUB);
    assert.ok(info.details, 'details should be available for an unencrypted key');
    assert.deepStrictEqual(info.details.flags, {
        raw: 0x01,
        userPresenceRequired: true,
        userVerificationRequired: false,
        residentKey: false,
    });
    assert.strictEqual(info.details.keyHandleLength, 64);
});

test('parseFidoPrivateKey: ecdsa-sk unencrypted', () => {
    const info = parseFidoPrivateKey(ECDSA_SK1);
    assert.strictEqual(info.type, 'sk-ecdsa-sha2-nistp256@openssh.com');
    assert.strictEqual(info.fingerprint, ECDSA_SK1_FP);
    assert.strictEqual(info.publicKey, ECDSA_SK1_PUB);
    assert.strictEqual(info.details?.flags.raw, 0x01);
    assert.strictEqual(info.details?.keyHandleLength, 227);
});

test('parseFidoPrivateKey: flags 0x24 → no touch, verify-required, resident', () => {
    const info = parseFidoPrivateKey(ED25519_SK_WORK_FLAGS24);
    assert.strictEqual(info.application, 'ssh:work');
    assert.strictEqual(info.publicKey, ED25519_SK_WORK_FLAGS24_PUB);
    assert.deepStrictEqual(info.details?.flags, {
        raw: 0x24,
        userPresenceRequired: false,
        userVerificationRequired: true,
        residentKey: true,
    });
});

test('parseFidoPrivateKey: comment containing a newline is rejected (authorized_keys injection)', () => {
    assert.throws(() => parseFidoPrivateKey(ED25519_SK1_NEWLINE_COMMENT), /comment/i);
    assert.throws(() => derivePublicKey(ED25519_SK1_NEWLINE_COMMENT), /comment/i);
});

test('parseFidoPrivateKey: reports bcrypt rounds', () => {
    assert.strictEqual(parseFidoPrivateKey(ED25519_SK1).kdfRounds, null);
    assert.strictEqual(parseFidoPrivateKey(ED25519_SK1_AES256_CTR).kdfRounds, 4);
    assert.strictEqual(parseFidoPrivateKey(ED25519_SK1_DEFAULT_ROUNDS, FIDO_TEST_PASSPHRASE).kdfRounds, 24);
});

test('parseFidoPrivateKey: tolerates surrounding whitespace / CRLF', () => {
    const info = parseFidoPrivateKey(`\r\n  ${ED25519_SK1.replace(/\n/g, '\r\n')}  `);
    assert.strictEqual(info.fingerprint, ED25519_SK1_FP);
});

// ==========================================================================
// parseFidoPrivateKey — encrypted
// ==========================================================================

test('parseFidoPrivateKey: aes256-ctr with passphrase', () => {
    const info = parseFidoPrivateKey(ED25519_SK1_AES256_CTR, FIDO_TEST_PASSPHRASE);
    assert.strictEqual(info.cipher, 'aes256-ctr');
    assert.strictEqual(info.publicKey, ED25519_SK1_PUB);
    assert.strictEqual(info.details?.flags.raw, 0x01);
});

test('parseFidoPrivateKey: aes256-cbc (ecdsa-sk) with passphrase', () => {
    const info = parseFidoPrivateKey(ECDSA_SK1_AES256_CBC, FIDO_TEST_PASSPHRASE);
    assert.strictEqual(info.cipher, 'aes256-cbc');
    assert.strictEqual(info.publicKey, ECDSA_SK1_PUB);
    assert.strictEqual(info.details?.keyHandleLength, 227);
});

test('parseFidoPrivateKey: aes128-ctr with custom application and flags', () => {
    const info = parseFidoPrivateKey(ED25519_SK_WORK_FLAGS24_AES128_CTR, FIDO_TEST_PASSPHRASE);
    assert.strictEqual(info.cipher, 'aes128-ctr');
    assert.strictEqual(info.publicKey, ED25519_SK_WORK_FLAGS24_PUB);
    assert.strictEqual(info.details?.flags.raw, 0x24);
});

test('parseFidoPrivateKey: ssh-keygen default bcrypt rounds (24)', () => {
    const info = parseFidoPrivateKey(ED25519_SK1_DEFAULT_ROUNDS, FIDO_TEST_PASSPHRASE);
    assert.strictEqual(info.publicKey, ED25519_SK1_PUB);
});

test('parseFidoPrivateKey: encrypted without passphrase exposes only public data', () => {
    const info = parseFidoPrivateKey(ED25519_SK1_AES256_CTR);
    assert.strictEqual(info.cipher, 'aes256-ctr');
    assert.strictEqual(info.details, null);
    assert.strictEqual(info.comment, '');
    assert.strictEqual(info.application, 'ssh:');
    assert.strictEqual(info.fingerprint, ED25519_SK1_FP);
    assert.strictEqual(info.publicKey, withoutComment(ED25519_SK1_PUB));
});

test('parseFidoPrivateKey: wrong passphrase is rejected', () => {
    assert.throws(() => parseFidoPrivateKey(ED25519_SK1_AES256_CTR, 'wrong'), /incorrect passphrase/i);
});

test('parseFidoPrivateKey: unsupported cipher names the cipher', () => {
    assert.throws(
        () => parseFidoPrivateKey(ED25519_SK1_CHACHA, FIDO_TEST_PASSPHRASE),
        /unsupported cipher.*chacha20-poly1305@openssh\.com/i,
    );
});

test('parseFidoPrivateKey: non-FIDO OpenSSH private key is rejected', async () => {
    const { privateKey } = await generateKeyPair('ed25519');
    assert.throws(() => parseFidoPrivateKey(privateKey), /not a FIDO/i);
});

/** Rebuild an unencrypted openssh-key-v1 file with its public blob taken from another key. */
function swapPublicBlob(targetPem: string, donorPem: string): string {
    const decode = (pem: string) => Buffer.from(pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, ''), 'base64');
    const split = (raw: Buffer) => {
        let pos = 15; // "openssh-key-v1\0"
        const fields: Buffer[] = [];
        const readString = () => {
            const len = raw.readUInt32BE(pos);
            const start = pos;
            pos += 4 + len;
            return raw.subarray(start, pos);
        };
        fields.push(readString(), readString(), readString(), raw.subarray(pos, pos + 4)); // cipher, kdf, kdfopts, nkeys
        pos += 4;
        const pub = readString();
        const priv = readString();
        return { header: Buffer.concat([raw.subarray(0, 15), ...fields]), pub, priv };
    };
    const target = split(decode(targetPem));
    const donor = split(decode(donorPem));
    const b64 = Buffer.concat([target.header, donor.pub, target.priv]).toString('base64');
    return `-----BEGIN OPENSSH PRIVATE KEY-----\n${b64}\n-----END OPENSSH PRIVATE KEY-----\n`;
}

test('parseFidoPrivateKey: public blob that does not match the private section is rejected', () => {
    const tampered = swapPublicBlob(ED25519_SK1, ED25519_SK_WORK_FLAGS24);
    assert.throws(() => parseFidoPrivateKey(tampered), /does not match/i);
});

test('parseFidoPrivateKey: garbage is rejected', () => {
    assert.throws(() => parseFidoPrivateKey('not a key'), /OpenSSH private key/i);
    assert.throws(
        () => parseFidoPrivateKey('-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----'),
        /OpenSSH private key|truncated|invalid/i,
    );
});

// ==========================================================================
// isFidoPrivateKey / inspectFidoKey / derivePublicKey integration
// ==========================================================================

test('isFidoPrivateKey: detects sk keys without a passphrase', async () => {
    assert.strictEqual(isFidoPrivateKey(ED25519_SK1), true);
    assert.strictEqual(isFidoPrivateKey(ED25519_SK1_AES256_CTR), true);
    assert.strictEqual(isFidoPrivateKey(ED25519_SK1_CHACHA), true);
    const { privateKey } = await generateKeyPair('ed25519');
    assert.strictEqual(isFidoPrivateKey(privateKey), false);
    assert.strictEqual(isFidoPrivateKey('garbage'), false);
    assert.strictEqual(isFidoPrivateKey(''), false);
});

test('inspectFidoKey: dispatches public vs private input', () => {
    const pub = inspectFidoKey(ED25519_SK1_PUB);
    assert.strictEqual(pub.kind, 'public');
    assert.strictEqual(pub.key.fingerprint, ED25519_SK1_FP);

    const priv = inspectFidoKey(ED25519_SK_WORK_FLAGS24);
    assert.strictEqual(priv.kind, 'private');
    assert.strictEqual(priv.kind === 'private' && priv.key.details?.flags.raw, 0x24);

    const unlocked = inspectFidoKey(ED25519_SK1_AES256_CTR, FIDO_TEST_PASSPHRASE);
    assert.strictEqual(unlocked.kind === 'private' && unlocked.key.details?.flags.raw, 0x01);

    assert.throws(() => inspectFidoKey('garbage'));
});

test('derivePublicKey: FIDO private key (unencrypted) matches ssh-keygen -y', () => {
    assert.strictEqual(derivePublicKey(ED25519_SK1), ED25519_SK1_PUB);
    assert.strictEqual(derivePublicKey(ECDSA_SK1), ECDSA_SK1_PUB);
});

test('derivePublicKey: FIDO private key (encrypted) with passphrase', () => {
    assert.strictEqual(derivePublicKey(ED25519_SK1_AES256_CTR, FIDO_TEST_PASSPHRASE), ED25519_SK1_PUB);
});

test('derivePublicKey: FIDO private key (encrypted) without passphrase asks for it', () => {
    assert.throws(() => derivePublicKey(ED25519_SK1_AES256_CTR), /passphrase/i);
});

// ==========================================================================
// fidoCommands — ssh-keygen command builder
// ==========================================================================

const baseOptions: FidoKeygenOptions = {
    algorithm: 'ed25519-sk',
    resident: false,
    verifyRequired: false,
    noTouchRequired: false,
    application: '',
    user: '',
    comment: '',
    outputPath: '',
};

test('defaultKeyPath: matches ssh-keygen defaults', () => {
    assert.strictEqual(defaultKeyPath('ed25519-sk'), '~/.ssh/id_ed25519_sk');
    assert.strictEqual(defaultKeyPath('ecdsa-sk'), '~/.ssh/id_ecdsa_sk');
});

test('buildKeygenCommand: defaults', () => {
    assert.strictEqual(buildKeygenCommand(baseOptions), 'ssh-keygen -t ed25519-sk -f ~/.ssh/id_ed25519_sk');
});

test('buildKeygenCommand: default application "ssh:" is omitted', () => {
    assert.strictEqual(
        buildKeygenCommand({ ...baseOptions, application: 'ssh:' }),
        'ssh-keygen -t ed25519-sk -f ~/.ssh/id_ed25519_sk',
    );
});

test('buildKeygenCommand: all options', () => {
    const cmd = buildKeygenCommand({
        algorithm: 'ecdsa-sk',
        resident: true,
        verifyRequired: true,
        noTouchRequired: true,
        application: 'ssh:work',
        user: 'alice',
        comment: 'alice@laptop',
        outputPath: '~/.ssh/id_ecdsa_sk_work',
    });
    assert.strictEqual(
        cmd,
        'ssh-keygen -t ecdsa-sk -O application=ssh:work -O resident -O user=alice ' +
        '-O verify-required -O no-touch-required -C alice@laptop -f ~/.ssh/id_ecdsa_sk_work',
    );
});

test('buildKeygenCommand: user is ignored for non-resident keys', () => {
    assert.strictEqual(
        buildKeygenCommand({ ...baseOptions, user: 'alice' }),
        'ssh-keygen -t ed25519-sk -f ~/.ssh/id_ed25519_sk',
    );
});

test('buildKeygenCommand: shell-quotes comment and path', () => {
    const cmd = buildKeygenCommand({
        ...baseOptions,
        comment: "bob's key",
        outputPath: '~/my keys/id_sk',
    });
    assert.strictEqual(cmd, `ssh-keygen -t ed25519-sk -C 'bob'\\''s key' -f ~/'my keys/id_sk'`);
});

test('buildKeygenCommand: invalid options throw', () => {
    assert.throws(() => buildKeygenCommand({ ...baseOptions, application: 'work' }), /ssh:/);
});

test('shellQuote: safe strings are left alone, others single-quoted', () => {
    assert.strictEqual(shellQuote('alice@example.com'), 'alice@example.com');
    assert.strictEqual(shellQuote('a b'), "'a b'");
    assert.strictEqual(shellQuote('$(rm -rf /)'), "'$(rm -rf /)'");
    assert.strictEqual(shellQuote(''), "''");
    // zsh expands a word starting with "=" to a command path (EQUALS option).
    assert.strictEqual(shellQuote('=ls'), "'=ls'");
    assert.strictEqual(shellQuote('application=ssh:work'), 'application=ssh:work');
});

test('validateKeygenOptions: application must begin with ssh:', () => {
    assert.deepStrictEqual(validateKeygenOptions(baseOptions), []);
    assert.deepStrictEqual(validateKeygenOptions({ ...baseOptions, application: 'ssh:work' }), []);
    const errors = validateKeygenOptions({ ...baseOptions, application: 'https://example.com' });
    assert.strictEqual(errors.length, 1);
    assert.match(errors[0], /ssh:/);
});

test('validateKeygenOptions: control characters are rejected', () => {
    const errors = validateKeygenOptions({ ...baseOptions, comment: 'a\nb', outputPath: 'x\ty' });
    assert.strictEqual(errors.length, 2);
    assert.strictEqual(validateKeygenOptions({ ...baseOptions, comment: 'a\u0085b' }).length, 1, 'C1 control');
    assert.strictEqual(validateKeygenOptions({ ...baseOptions, comment: 'abc\u202Edef' }).length, 1, 'bidi override');
});

test('validateKeygenOptions: user is only checked for resident keys (field is hidden otherwise)', () => {
    assert.deepStrictEqual(validateKeygenOptions({ ...baseOptions, user: 'a\nb' }), []);
    assert.strictEqual(validateKeygenOptions({ ...baseOptions, resident: true, user: 'a\nb' }).length, 1);
});

test('buildKeygenNotes: mention resident retrieval, PIN and touch override', () => {
    const notes = buildKeygenNotes({ ...baseOptions, resident: true, verifyRequired: true, noTouchRequired: true });
    const joined = notes.join('\n');
    assert.match(joined, /ssh-keygen -K/);
    assert.match(joined, /PIN/);
    assert.match(joined, /no-touch-required/);
    assert.match(joined, /macOS/);
});

// ==========================================================================
// fidoCommands — config snippets
// ==========================================================================

test('buildAuthorizedKeysLine: options are comma-separated', () => {
    assert.strictEqual(
        buildAuthorizedKeysLine(ED25519_SK1_PUB, { noTouchRequired: false, verifyRequired: false }),
        ED25519_SK1_PUB,
    );
    assert.strictEqual(
        buildAuthorizedKeysLine(ED25519_SK1_PUB, { noTouchRequired: true, verifyRequired: true }),
        `no-touch-required,verify-required ${ED25519_SK1_PUB}`,
    );
    assert.strictEqual(
        buildAuthorizedKeysLine(ED25519_SK1_PUB, { noTouchRequired: false, verifyRequired: true }),
        `verify-required ${ED25519_SK1_PUB}`,
    );
});

test('buildSshdConfigLine: server-wide enforcement', () => {
    assert.strictEqual(
        buildSshdConfigLine({ noTouchRequired: false, verifyRequired: false }),
        'PubkeyAuthOptions touch-required',
    );
    assert.strictEqual(
        buildSshdConfigLine({ noTouchRequired: false, verifyRequired: true }),
        'PubkeyAuthOptions touch-required verify-required',
    );
    assert.strictEqual(
        buildSshdConfigLine({ noTouchRequired: true, verifyRequired: true }),
        'PubkeyAuthOptions verify-required',
    );
    assert.strictEqual(buildSshdConfigLine({ noTouchRequired: true, verifyRequired: false }), null);
});

test('buildAllowedSignersLine: git namespace', () => {
    assert.strictEqual(
        buildAllowedSignersLine('alice@example.com', ED25519_SK1_PUB),
        `alice@example.com namespaces="git" ${ED25519_SK1_PUB}`,
    );
});

test('buildGitSigningCommands: points at the .pub file', () => {
    const cmds = buildGitSigningCommands('~/.ssh/id_ed25519_sk.pub');
    assert.match(cmds, /git config --global gpg\.format ssh/);
    assert.match(cmds, /git config --global user\.signingkey ~\/\.ssh\/id_ed25519_sk\.pub/);
});

test('authorizedKeyOptionsFromFlags: maps key flags to authorized_keys options', () => {
    const touchOnly = parseFidoPrivateKey(ED25519_SK1).details!.flags;
    assert.deepStrictEqual(authorizedKeyOptionsFromFlags(touchOnly), { noTouchRequired: false, verifyRequired: false });
    const flags24 = parseFidoPrivateKey(ED25519_SK_WORK_FLAGS24).details!.flags;
    assert.deepStrictEqual(authorizedKeyOptionsFromFlags(flags24), { noTouchRequired: true, verifyRequired: true });
});

run();
