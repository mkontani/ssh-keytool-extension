import { useState } from 'react';
import { inspectFidoKey, type FidoFlags, type FidoInspection } from '../utils/fido';
import { authorizedKeyOptionsFromFlags, buildAuthorizedKeysLine } from '../utils/fidoCommands';
import { SnippetBlock } from './SnippetBlock';

const MAX_INPUT_LENGTH = 65536;

/** Above this many bcrypt rounds, unlocking takes noticeably long (~1s per 64 rounds). */
const SLOW_KDF_ROUNDS = 64;

const errorMessage = (e: unknown): string => (e instanceof Error ? e.message : 'Failed to parse key');

const BADGE_COLORS = {
    good: 'bg-teal-900/60 text-teal-300 border-teal-800',
    warn: 'bg-amber-900/40 text-amber-200 border-amber-900/60',
    info: 'bg-blue-900/60 text-blue-300 border-blue-800',
    neutral: 'bg-gray-700 text-gray-300 border-gray-600',
} as const;

function FlagBadges({ flags }: { flags: FidoFlags }) {
    const badges: Array<{ label: string; color: keyof typeof BADGE_COLORS }> = [
        flags.userPresenceRequired
            ? { label: 'Touch required', color: 'good' }
            : { label: 'No touch required', color: 'warn' },
        flags.userVerificationRequired
            ? { label: 'PIN required', color: 'good' }
            : { label: 'No PIN', color: 'neutral' },
        flags.residentKey
            ? { label: 'Resident', color: 'info' }
            : { label: 'Non-resident', color: 'neutral' },
    ];
    return (
        <div className="flex flex-wrap gap-1">
            {badges.map(({ label, color }) => (
                <span key={label} className={`px-2 py-0.5 rounded border text-xs ${BADGE_COLORS[color]}`}>{label}</span>
            ))}
        </div>
    );
}

function KeySummary({ inspection }: { inspection: FidoInspection }) {
    const { key } = inspection;
    const details = inspection.kind === 'private' ? inspection.key.details : null;

    return (
        <div className="grid grid-cols-[100px_1fr] gap-2 p-3 bg-gray-800 rounded border border-gray-700 text-sm">
            <span className="text-gray-400">Kind</span>
            <span>{inspection.kind === 'public' ? 'Public key' : 'Private key (key handle)'}</span>

            <span className="text-gray-400">Type</span>
            <span className="font-mono text-xs break-all">{key.type}</span>

            <span className="text-gray-400">Application</span>
            <span className="font-mono text-xs break-all">{key.application}</span>

            <span className="text-gray-400">Fingerprint</span>
            <span className="font-mono text-xs break-all">{key.fingerprint}</span>

            {key.comment && (
                <>
                    <span className="text-gray-400">Comment</span>
                    <span className="font-mono text-xs break-all">{key.comment}</span>
                </>
            )}

            {inspection.kind === 'private' && (
                <>
                    <span className="text-gray-400">Encryption</span>
                    <span className="font-mono text-xs">
                        {inspection.key.cipher}
                        {inspection.key.kdfRounds !== null && ` (bcrypt, ${inspection.key.kdfRounds} rounds)`}
                    </span>
                </>
            )}

            {details && (
                <>
                    <span className="text-gray-400">Flags</span>
                    <div className="flex flex-col gap-1">
                        <FlagBadges flags={details.flags} />
                        <span className="font-mono text-xs text-gray-500">0x{details.flags.raw.toString(16).padStart(2, '0')}</span>
                    </div>

                    <span className="text-gray-400">Key handle</span>
                    <span className="text-xs">{details.keyHandleLength} bytes</span>
                </>
            )}
        </div>
    );
}

export function FidoInspectPanel() {
    const [input, setInput] = useState('');
    const [passphrase, setPassphrase] = useState('');
    const [result, setResult] = useState<FidoInspection | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [isUnlocking, setIsUnlocking] = useState(false);

    // Parsing without a passphrase never runs the KDF, so it is cheap enough for every keystroke.
    const handleInputChange = (value: string) => {
        const clipped = value.slice(0, MAX_INPUT_LENGTH);
        setInput(clipped);
        setPassphrase('');
        if (!clipped.trim()) {
            setResult(null);
            setError(null);
            return;
        }
        try {
            setResult(inspectFidoKey(clipped));
            setError(null);
        } catch (e: unknown) {
            setResult(null);
            setError(errorMessage(e));
        }
    };

    const handleUnlock = () => {
        setIsUnlocking(true);
        setError(null);
        // Let React commit the loading state before the synchronous bcrypt KDF blocks the thread.
        setTimeout(() => {
            try {
                setResult(inspectFidoKey(input, passphrase));
                setPassphrase('');
            } catch (e: unknown) {
                setError(errorMessage(e));
            } finally {
                setIsUnlocking(false);
            }
        }, 50);
    };

    const isLocked = result?.kind === 'private' && result.key.details === null;
    const details = result?.kind === 'private' ? result.key.details : null;
    const kdfRounds = result?.kind === 'private' ? result.key.kdfRounds : null;
    const canUnlock = passphrase !== '' && !isUnlocking;

    return (
        <div className="flex flex-col gap-4">
            <div className="flex flex-col gap-1">
                <label className="text-xs font-medium text-gray-400">FIDO Public Key or Private Key File</label>
                <textarea
                    value={input}
                    onChange={(e) => handleInputChange(e.target.value)}
                    maxLength={MAX_INPUT_LENGTH}
                    className="w-full h-28 p-2 text-xs font-mono bg-gray-800 rounded border border-gray-700 focus:border-blue-500 outline-none resize-none"
                    placeholder={'sk-ssh-ed25519@openssh.com AAAA...\nor\n-----BEGIN OPENSSH PRIVATE KEY-----'}
                />
            </div>

            {isLocked && (
                <div className="flex flex-col gap-1">
                    <label className="text-xs font-medium text-gray-400">Passphrase</label>
                    <div className="flex gap-2">
                        <input
                            type="password"
                            value={passphrase}
                            onChange={(e) => setPassphrase(e.target.value)}
                            onKeyDown={(e) => { if (e.key === 'Enter' && canUnlock) handleUnlock(); }}
                            autoComplete="new-password"
                            className="flex-1 p-2 rounded bg-gray-800 border border-gray-700 text-sm focus:border-blue-500 outline-none placeholder-gray-600"
                            placeholder="Unlock to see flags and comment..."
                        />
                        <button
                            onClick={handleUnlock}
                            disabled={!canUnlock}
                            className="px-4 bg-blue-600 hover:bg-blue-500 rounded text-sm font-medium text-white transition-all active:scale-95 disabled:opacity-50 disabled:active:scale-100"
                        >
                            {isUnlocking ? 'Unlocking...' : 'Unlock'}
                        </button>
                    </div>
                    {kdfRounds !== null && kdfRounds > SLOW_KDF_ROUNDS && (
                        <p className="text-xs text-amber-500/90">
                            This key uses {kdfRounds} KDF rounds; unlocking may take several seconds.
                        </p>
                    )}
                </div>
            )}

            {error && (
                <div className="p-3 bg-red-900/50 border border-red-800 rounded text-red-200 text-sm">
                    {error}
                </div>
            )}

            {result && (
                <div className="flex flex-col gap-3 animate-in fade-in slide-in-from-bottom-2">
                    <KeySummary inspection={result} />

                    {result.kind === 'private' && (
                        <SnippetBlock
                            label="Public Key"
                            value={result.key.publicKey}
                            hint={isLocked ? 'The comment is encrypted; unlock to include it.' : undefined}
                        />
                    )}

                    {details && (
                        <SnippetBlock
                            label="authorized_keys"
                            value={buildAuthorizedKeysLine(result.key.publicKey, authorizedKeyOptionsFromFlags(details.flags))}
                            hint="Options match the touch / PIN flags stored in this key."
                        />
                    )}

                    {result.kind === 'public' && (
                        <p className="text-xs text-gray-500">
                            Touch, PIN and resident flags are stored only in the private key file. Paste it to see them.
                        </p>
                    )}
                </div>
            )}
        </div>
    );
}
