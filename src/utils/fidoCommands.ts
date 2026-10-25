/**
 * fidoCommands.ts — builds the ssh-keygen command and server / git config
 * snippets for FIDO (sk-*) keys. Pure string functions; nothing here touches
 * key material.
 *
 * References: ssh-keygen(1) "FIDO AUTHENTICATOR", sshd(8) AUTHORIZED_KEYS
 * FILE FORMAT, sshd_config(5) PubkeyAuthOptions.
 */

import type { FidoFlags } from './fido';
import { hasUnsafeChars } from './text';

export type FidoAlgorithm = 'ed25519-sk' | 'ecdsa-sk';

export interface FidoKeygenOptions {
    algorithm: FidoAlgorithm;
    resident: boolean;
    verifyRequired: boolean;
    noTouchRequired: boolean;
    /** Empty or "ssh:" means the OpenSSH default. */
    application: string;
    /** Only used for resident keys. */
    user: string;
    comment: string;
    /** Empty means ssh-keygen's default path for the algorithm. */
    outputPath: string;
}

export interface AuthorizedKeyOptions {
    noTouchRequired: boolean;
    verifyRequired: boolean;
}

/** OpenSSH's default FIDO application string; custom ones must share this prefix. */
export const DEFAULT_APPLICATION = 'ssh:';

// No leading "=": zsh expands "=cmd" to the command's path (EQUALS option).
const SAFE_SHELL_ARG = /^[A-Za-z0-9@%+:,./_-][A-Za-z0-9@%+=:,./_-]*$/;

type TextField = 'application' | 'user' | 'comment' | 'outputPath';

const TEXT_FIELD_LABELS: ReadonlyArray<[TextField, string]> = [
    ['application', 'Application'],
    ['user', 'User'],
    ['comment', 'Comment'],
    ['outputPath', 'Output file'],
];

const compact = (items: ReadonlyArray<string | null>): string[] =>
    items.filter((item): item is string => item !== null);

/** Quote a value for POSIX shells; safe values are returned unchanged. */
export const shellQuote = (value: string): string =>
    SAFE_SHELL_ARG.test(value) ? value : `'${value.replace(/'/g, `'\\''`)}'`;

/** Like shellQuote, but keeps a leading "~/" unquoted so the shell still expands it. */
const shellQuotePath = (path: string): string =>
    path.startsWith('~/') && path.length > 2 ? `~/${shellQuote(path.slice(2))}` : shellQuote(path);

export const defaultKeyPath = (algorithm: FidoAlgorithm): string =>
    `~/.ssh/id_${algorithm.replace('-', '_')}`;

/** Placeholder used in snippets before the key exists. */
export const publicKeyPlaceholder = (privateKeyPath: string): string =>
    `<contents of ${privateKeyPath}.pub>`;

export const validateKeygenOptions = (opts: FidoKeygenOptions): string[] =>
    compact([
        opts.application && !opts.application.startsWith(DEFAULT_APPLICATION)
            ? 'Application must begin with "ssh:" (e.g. ssh:work).'
            : null,
        ...TEXT_FIELD_LABELS
            // The user field is hidden (and ignored) unless the key is resident.
            .filter(([field]) => field !== 'user' || opts.resident)
            .map(([field, label]) =>
                hasUnsafeChars(opts[field]) ? `${label} must not contain control or invisible formatting characters.` : null
            ),
    ]);

export const buildKeygenCommand = (opts: FidoKeygenOptions): string => {
    const errors = validateKeygenOptions(opts);
    if (errors.length > 0) throw new Error(errors.join(' '));

    const hasCustomApplication = opts.application !== '' && opts.application !== DEFAULT_APPLICATION;
    return [
        'ssh-keygen', '-t', opts.algorithm,
        ...(hasCustomApplication ? ['-O', shellQuote(`application=${opts.application}`)] : []),
        ...(opts.resident ? ['-O', 'resident'] : []),
        ...(opts.resident && opts.user ? ['-O', shellQuote(`user=${opts.user}`)] : []),
        ...(opts.verifyRequired ? ['-O', 'verify-required'] : []),
        ...(opts.noTouchRequired ? ['-O', 'no-touch-required'] : []),
        ...(opts.comment ? ['-C', shellQuote(opts.comment)] : []),
        '-f', shellQuotePath(opts.outputPath || defaultKeyPath(opts.algorithm)),
    ].join(' ');
};

export const buildKeygenNotes = (opts: FidoKeygenOptions): string[] =>
    compact([
        'Requires a FIDO/U2F security key and OpenSSH 8.2+ on both the client and the server.',
        'macOS: the built-in ssh-keygen has no FIDO support ("No FIDO SecurityKeyProvider specified"). Use a FIDO-enabled OpenSSH, e.g. from Homebrew (brew install openssh).',
        opts.algorithm === 'ed25519-sk'
            ? 'ed25519-sk needs a security key with Ed25519 support (e.g. YubiKey 5 firmware 5.2.3+). Use ecdsa-sk for older keys.'
            : null,
        opts.resident
            ? 'Resident keys are stored on the security key. On another machine, run "ssh-keygen -K" to download them, or "ssh-add -K" to load them into ssh-agent.'
            : null,
        opts.verifyRequired
            ? 'verify-required asks for the security key PIN on every use. Set a FIDO2 PIN first; the server needs OpenSSH 8.4+ to enforce it.'
            : null,
        opts.noTouchRequired
            ? 'sshd rejects signatures made without a touch unless the authorized_keys entry has the no-touch-required option (included below).'
            : null,
    ]);

/** authorized_keys entry; options are comma-separated per sshd(8). */
export const buildAuthorizedKeysLine = (publicKey: string, opts: AuthorizedKeyOptions): string => {
    const options = compact([
        opts.noTouchRequired ? 'no-touch-required' : null,
        opts.verifyRequired ? 'verify-required' : null,
    ]);
    return options.length > 0 ? `${options.join(',')} ${publicKey}` : publicKey;
};

/**
 * Optional server-wide enforcement for all FIDO keys. Returns null when
 * nothing can be enforced (touch-required would reject no-touch keys).
 */
export const buildSshdConfigLine = (opts: AuthorizedKeyOptions): string | null => {
    const keywords = compact([
        opts.noTouchRequired ? null : 'touch-required',
        opts.verifyRequired ? 'verify-required' : null,
    ]);
    return keywords.length > 0 ? `PubkeyAuthOptions ${keywords.join(' ')}` : null;
};

/** allowed_signers entry for verifying git commits signed with this key. */
export const buildAllowedSignersLine = (principal: string, publicKey: string): string =>
    `${principal} namespaces="git" ${publicKey}`;

export const buildGitSigningCommands = (publicKeyPath: string): string =>
    [
        'git config --global gpg.format ssh',
        `git config --global user.signingkey ${shellQuotePath(publicKeyPath)}`,
        'git config --global commit.gpgsign true',
    ].join('\n');

/** Map flags stored in a FIDO private key file to matching authorized_keys options. */
export const authorizedKeyOptionsFromFlags = (flags: FidoFlags): AuthorizedKeyOptions => ({
    noTouchRequired: !flags.userPresenceRequired,
    verifyRequired: flags.userVerificationRequired,
});
