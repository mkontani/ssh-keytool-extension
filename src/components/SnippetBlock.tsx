import { useState } from 'react';

interface SnippetBlockProps {
    label: string;
    value: string;
    hint?: string;
}

const COPIED_FEEDBACK_MS = 1500;

/** Read-only, copyable block for commands and config lines. */
export function SnippetBlock({ label, value, hint }: SnippetBlockProps) {
    const [copied, setCopied] = useState(false);

    const handleCopy = async () => {
        try {
            await navigator.clipboard.writeText(value);
            setCopied(true);
            setTimeout(() => setCopied(false), COPIED_FEEDBACK_MS);
        } catch (err) {
            console.error('Failed to copy', err);
        }
    };

    return (
        <div>
            <div className="flex justify-between items-center mb-1 gap-2">
                <span className="text-xs font-medium text-gray-400">{label}</span>
                <button
                    onClick={handleCopy}
                    className="text-xs text-blue-400 hover:text-blue-300 transition-colors shrink-0"
                >
                    {copied ? 'Copied' : 'Copy'}
                </button>
            </div>
            <pre className="w-full p-2 text-xs font-mono bg-gray-950 rounded border border-gray-800 text-gray-300 whitespace-pre-wrap break-all">
                {value}
            </pre>
            {hint && <p className="mt-1 text-xs text-gray-500">{hint}</p>}
        </div>
    );
}
