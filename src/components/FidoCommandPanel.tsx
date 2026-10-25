import { useState } from 'react';
import {
    buildAllowedSignersLine,
    buildAuthorizedKeysLine,
    buildGitSigningCommands,
    buildKeygenCommand,
    buildKeygenNotes,
    buildSshdConfigLine,
    defaultKeyPath,
    publicKeyPlaceholder,
    validateKeygenOptions,
    type FidoAlgorithm,
    type FidoKeygenOptions,
} from '../utils/fidoCommands';
import { SnippetBlock } from './SnippetBlock';

const INITIAL_OPTIONS: FidoKeygenOptions = {
    algorithm: 'ed25519-sk',
    resident: false,
    verifyRequired: false,
    noTouchRequired: false,
    application: '',
    user: '',
    comment: '',
    outputPath: '',
};

const INPUT_CLASS =
    'p-2 rounded bg-gray-800 border border-gray-700 text-sm focus:border-blue-500 outline-none placeholder-gray-600';

type FlagOption = 'resident' | 'verifyRequired' | 'noTouchRequired';

const FLAG_OPTIONS: ReadonlyArray<{ key: FlagOption; label: string; description: string }> = [
    { key: 'resident', label: 'Resident key', description: 'Store the key on the security key (-O resident)' },
    { key: 'verifyRequired', label: 'Require PIN', description: 'Ask for the PIN on every use (-O verify-required)' },
    { key: 'noTouchRequired', label: 'No touch required', description: 'Sign without touching the key (-O no-touch-required)' },
];

export function FidoCommandPanel() {
    const [opts, setOpts] = useState<FidoKeygenOptions>(INITIAL_OPTIONS);

    const update = <K extends keyof FidoKeygenOptions>(key: K, value: FidoKeygenOptions[K]) =>
        setOpts(prev => ({ ...prev, [key]: value }));

    const errors = validateKeygenOptions(opts);
    const keygenCommand = errors.length === 0 ? buildKeygenCommand(opts) : '';
    const keyPath = opts.outputPath || defaultKeyPath(opts.algorithm);
    const publicKey = publicKeyPlaceholder(keyPath);
    const authorizedKeyOptions = { noTouchRequired: opts.noTouchRequired, verifyRequired: opts.verifyRequired };
    const sshdConfigLine = buildSshdConfigLine(authorizedKeyOptions);

    return (
        <div className="flex flex-col gap-4">
            <div className="grid grid-cols-2 gap-3">
                <div className="flex flex-col gap-1">
                    <label className="text-xs font-medium text-gray-400">Algorithm</label>
                    <select
                        value={opts.algorithm}
                        onChange={(e) => update('algorithm', e.target.value as FidoAlgorithm)}
                        className="p-2 rounded bg-gray-800 border border-gray-700 text-sm focus:border-blue-500 outline-none"
                    >
                        <option value="ed25519-sk">ed25519-sk</option>
                        <option value="ecdsa-sk">ecdsa-sk</option>
                    </select>
                </div>
                <div className="flex flex-col gap-1">
                    <label className="text-xs font-medium text-gray-400">Output File</label>
                    <input
                        value={opts.outputPath}
                        onChange={(e) => update('outputPath', e.target.value)}
                        className={INPUT_CLASS}
                        placeholder={defaultKeyPath(opts.algorithm)}
                    />
                </div>
            </div>

            <div className="flex flex-col gap-2 p-3 bg-gray-800 rounded border border-gray-700">
                {FLAG_OPTIONS.map(({ key, label, description }) => (
                    <label key={key} className="flex items-start gap-2 text-sm cursor-pointer">
                        <input
                            type="checkbox"
                            checked={opts[key]}
                            onChange={(e) => update(key, e.target.checked)}
                            className="mt-1 accent-blue-500"
                        />
                        <span>
                            <span className="font-medium">{label}</span>
                            <span className="block text-xs text-gray-500">{description}</span>
                        </span>
                    </label>
                ))}
            </div>

            {opts.resident && (
                <div className="flex flex-col gap-1">
                    <label className="text-xs font-medium text-gray-400">User (optional)</label>
                    <input
                        value={opts.user}
                        onChange={(e) => update('user', e.target.value)}
                        className={INPUT_CLASS}
                        placeholder="Name stored with the resident key, e.g. alice"
                    />
                </div>
            )}

            <div className="grid grid-cols-2 gap-3">
                <div className="flex flex-col gap-1">
                    <label className="text-xs font-medium text-gray-400">Application</label>
                    <input
                        value={opts.application}
                        onChange={(e) => update('application', e.target.value)}
                        className={INPUT_CLASS}
                        placeholder="ssh: (default)"
                    />
                </div>
                <div className="flex flex-col gap-1">
                    <label className="text-xs font-medium text-gray-400">Comment</label>
                    <input
                        value={opts.comment}
                        onChange={(e) => update('comment', e.target.value)}
                        className={INPUT_CLASS}
                        placeholder="user@host"
                    />
                </div>
            </div>

            {errors.length > 0 ? (
                <div className="p-3 bg-red-900/50 border border-red-800 rounded text-red-200 text-sm flex flex-col gap-1">
                    {errors.map(err => <p key={err}>{err}</p>)}
                </div>
            ) : (
                <div className="flex flex-col gap-3">
                    <SnippetBlock
                        label="1. Generate (run on your machine)"
                        value={keygenCommand}
                        hint={keygenCommand.includes("'") ? 'Quoted for bash / zsh.' : undefined}
                    />
                    <SnippetBlock
                        label="2. Server: ~/.ssh/authorized_keys"
                        value={buildAuthorizedKeysLine(publicKey, authorizedKeyOptions)}
                        hint={`Replace the placeholder with the contents of ${keyPath}.pub.`}
                    />
                    {sshdConfigLine && (
                        <SnippetBlock
                            label="Optional: /etc/ssh/sshd_config"
                            value={sshdConfigLine}
                            hint={
                                'Enforces these checks for every FIDO key on the server, regardless of authorized_keys options. ' +
                                `Needs OpenSSH ${opts.verifyRequired ? '8.4' : '8.2'}+ on the server; an older sshd rejects unknown keywords and will not start, so check with "sshd -t" before restarting.`
                            }
                        />
                    )}
                    <details>
                        <summary className="text-xs font-medium text-gray-400 cursor-pointer select-none">
                            Optional: Git commit signing
                        </summary>
                        <div className="flex flex-col gap-3 mt-2">
                            <SnippetBlock label="git config" value={buildGitSigningCommands(`${keyPath}.pub`)} />
                            <SnippetBlock
                                label="~/.ssh/allowed_signers (for git log --show-signature)"
                                value={buildAllowedSignersLine('<your-git-email>', publicKey)}
                            />
                        </div>
                    </details>
                </div>
            )}

            <ul className="p-3 bg-gray-800 border border-gray-700 rounded text-xs text-gray-400 flex flex-col gap-1 list-disc list-inside">
                {buildKeygenNotes(opts).map(note => <li key={note}>{note}</li>)}
            </ul>
        </div>
    );
}
