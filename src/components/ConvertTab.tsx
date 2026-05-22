import { useState } from 'react';
import {
    detectPrivateKeyFormat,
    convertPrivateKey,
    type PrivateKeyFormat,
} from '../utils/ssh';

interface ConvertState {
    input: string;
    detectedFormat: PrivateKeyFormat | 'unknown';
    targetFormat: PrivateKeyFormat;
    sourcePassphrase: string;
    targetPassphrase: string;
    output: string | null;
    outputFormat: PrivateKeyFormat | null;
    notes: string[];
    error: string | null;
    isWorking: boolean;
}

const MAX_INPUT_BYTES = 65536;

const FORMAT_LABELS: Record<PrivateKeyFormat | 'unknown', string> = {
    openssh: 'OpenSSH',
    pkcs1: 'PKCS#1 (PEM)',
    pkcs8: 'PKCS#8 (PEM)',
    ppk: 'PuTTY PPK v2',
    unknown: 'Unknown',
};

const FORMAT_BADGE_COLORS: Record<PrivateKeyFormat | 'unknown', string> = {
    openssh: 'bg-blue-900/60 text-blue-300 border-blue-800',
    pkcs1: 'bg-purple-900/60 text-purple-300 border-purple-800',
    pkcs8: 'bg-teal-900/60 text-teal-300 border-teal-800',
    ppk: 'bg-orange-900/60 text-orange-300 border-orange-800',
    unknown: 'bg-gray-800 text-gray-400 border-gray-700',
};

export function ConvertTab() {
    const [state, setState] = useState<ConvertState>({
        input: '',
        detectedFormat: 'unknown',
        targetFormat: 'openssh',
        sourcePassphrase: '',
        targetPassphrase: '',
        output: null,
        outputFormat: null,
        notes: [],
        error: null,
        isWorking: false,
    });

    const copyToClipboard = async (text: string) => {
        try {
            await navigator.clipboard.writeText(text);
        } catch (err) {
            console.error('Failed to copy', err);
        }
    };

    const handleInputChange = (value: string) => {
        const clipped = value.length > MAX_INPUT_BYTES ? value.slice(0, MAX_INPUT_BYTES) : value;
        const detectedFormat = detectPrivateKeyFormat(clipped);
        setState(prev => ({
            ...prev,
            input: clipped,
            detectedFormat,
            output: null,
            outputFormat: null,
            error: null,
            notes: [],
        }));
    };

    const handleConvert = () => {
        setState(prev => ({ ...prev, isWorking: true, output: null, outputFormat: null, error: null, notes: [] }));

        // Wrap in setTimeout to allow React to commit the loading state before
        // potentially blocking synchronous crypto work (mirrors handleGenerate pattern).
        setTimeout(() => {
            try {
                const result = convertPrivateKey(state.input, {
                    targetFormat: state.targetFormat,
                    sourcePassphrase: state.sourcePassphrase || undefined,
                    targetPassphrase: state.targetPassphrase || undefined,
                });
                setState(prev => ({
                    ...prev,
                    output: result.privateKey,
                    outputFormat: result.format,
                    notes: result.notes ?? [],
                    error: null,
                    isWorking: false,
                }));
            } catch (e: unknown) {
                setState(prev => ({
                    ...prev,
                    output: null,
                    outputFormat: null,
                    notes: [],
                    error: (e as Error).message || 'Conversion failed',
                    isWorking: false,
                }));
            }
        }, 50);
    };

    const { input, detectedFormat, targetFormat, sourcePassphrase, targetPassphrase, output, outputFormat, notes, error, isWorking } = state;

    return (
        <div className="flex flex-col gap-4">
            {/* Input key textarea */}
            <div className="flex flex-col gap-1">
                <div className="flex items-center justify-between">
                    <label className="text-xs font-medium text-gray-400">Private Key</label>
                    {input.trim() && (
                        <span className={`text-xs px-2 py-0.5 rounded border font-mono ${FORMAT_BADGE_COLORS[detectedFormat]}`}>
                            {FORMAT_LABELS[detectedFormat]}
                        </span>
                    )}
                </div>
                <textarea
                    value={input}
                    onChange={(e) => handleInputChange(e.target.value)}
                    maxLength={MAX_INPUT_BYTES}
                    className="w-full h-28 p-2 text-xs font-mono bg-gray-800 rounded border border-gray-700 focus:border-blue-500 outline-none resize-none"
                    placeholder="Paste private key (OpenSSH, PKCS#1, PKCS#8, or PuTTY PPK)..."
                />
            </div>

            {/* Source passphrase */}
            <div className="flex flex-col gap-1">
                <label className="text-xs font-medium text-gray-400">Source Passphrase</label>
                <input
                    type="password"
                    value={sourcePassphrase}
                    onChange={(e) => setState(prev => ({ ...prev, sourcePassphrase: e.target.value }))}
                    autoComplete="new-password"
                    className="p-2 rounded bg-gray-800 border border-gray-700 text-sm focus:border-blue-500 outline-none placeholder-gray-600"
                    placeholder="Enter if source key is encrypted..."
                />
            </div>

            {/* Target format + passphrase row */}
            <div className="grid grid-cols-2 gap-3">
                <div className="flex flex-col gap-1">
                    <label className="text-xs font-medium text-gray-400">Target Format</label>
                    <select
                        value={targetFormat}
                        onChange={(e) => setState(prev => ({ ...prev, targetFormat: e.target.value as PrivateKeyFormat, output: null, error: null, notes: [] }))}
                        className="p-2 rounded bg-gray-800 border border-gray-700 text-sm focus:border-blue-500 outline-none"
                    >
                        <option value="openssh">OpenSSH</option>
                        <option value="pkcs1">PKCS#1 (PEM)</option>
                        <option value="pkcs8">PKCS#8 (PEM)</option>
                        <option value="ppk">PuTTY PPK v2</option>
                    </select>
                </div>
                <div className="flex flex-col gap-1">
                    <label className="text-xs font-medium text-gray-400">Target Passphrase</label>
                    <input
                        type="password"
                        value={targetPassphrase}
                        onChange={(e) => setState(prev => ({ ...prev, targetPassphrase: e.target.value }))}
                        autoComplete="new-password"
                        className="p-2 rounded bg-gray-800 border border-gray-700 text-sm focus:border-blue-500 outline-none placeholder-gray-600"
                        placeholder="Leave empty for unencrypted output"
                    />
                </div>
            </div>

            {/* PPK v2 weak-KDF warning (PPK v2 uses SHA-1 with no salt and no iterations) */}
            {targetFormat === 'ppk' && targetPassphrase.length > 0 && (
                <div className="p-2 bg-amber-900/30 border border-amber-800/50 rounded text-amber-200/90 text-xs">
                    PPK v2 encryption uses a SHA-1-based key derivation with no salt and no iteration count.
                    Passphrase protection is weaker than OpenSSH or PKCS#8. Use a strong, unique passphrase.
                </div>
            )}

            {/* Convert button */}
            <button
                onClick={handleConvert}
                disabled={isWorking || !input.trim()}
                className="w-full py-2 bg-green-700 hover:bg-green-600 rounded font-medium text-white shadow-lg transition-all active:scale-95 disabled:opacity-50 disabled:active:scale-100"
            >
                {isWorking ? 'Converting...' : 'Convert Key'}
            </button>

            {/* Error panel */}
            {error && (
                <div className="p-3 bg-red-900/50 border border-red-800 rounded text-red-200 text-sm">
                    {error}
                </div>
            )}

            {/* Notes panel */}
            {notes.length > 0 && (
                <div className="p-3 bg-amber-900/40 border border-amber-800/60 rounded text-amber-200 text-sm flex flex-col gap-1">
                    <span className="text-xs font-semibold text-amber-400 uppercase tracking-wide">Notes</span>
                    {notes.map((note, i) => (
                        <p key={i} className="text-xs">{note}</p>
                    ))}
                </div>
            )}

            {/* Output */}
            {output && (
                <div className="mt-2 animate-in fade-in slide-in-from-bottom-2">
                    <div className="flex justify-between items-center mb-1">
                        <span className="text-xs font-medium text-gray-400">
                            Converted Key
                            <span className={`ml-2 text-xs px-1.5 py-0.5 rounded border font-mono ${FORMAT_BADGE_COLORS[outputFormat ?? targetFormat]}`}>
                                {FORMAT_LABELS[outputFormat ?? targetFormat]}
                            </span>
                        </span>
                        <button
                            onClick={() => copyToClipboard(output)}
                            className="text-xs text-blue-400 hover:text-blue-300 transition-colors"
                        >
                            Copy
                        </button>
                    </div>
                    <textarea
                        readOnly
                        value={output}
                        className="w-full h-28 p-2 text-xs font-mono bg-gray-950 rounded border border-gray-800 focus:border-gray-700 outline-none resize-none text-gray-400"
                    />
                </div>
            )}
        </div>
    );
}
