import { useState } from 'react';
import { FidoCommandPanel } from './FidoCommandPanel';
import { FidoInspectPanel } from './FidoInspectPanel';

type FidoMode = 'command' | 'inspect';

const MODES: ReadonlyArray<{ id: FidoMode; label: string }> = [
    { id: 'command', label: 'Command Builder' },
    { id: 'inspect', label: 'Inspect Key' },
];

export function FidoTab() {
    const [mode, setMode] = useState<FidoMode>('command');

    return (
        <div className="flex flex-col gap-4">
            <div className="flex bg-gray-800 rounded-lg p-1 gap-1">
                {MODES.map(({ id, label }) => (
                    <button
                        key={id}
                        onClick={() => setMode(id)}
                        className={`flex-1 py-1 px-3 rounded text-xs font-medium transition-colors ${mode === id
                            ? 'bg-gray-700 text-white shadow'
                            : 'text-gray-400 hover:text-white'
                            }`}
                    >
                        {label}
                    </button>
                ))}
            </div>

            {/* Both panels stay mounted so switching modes keeps their input. */}
            <div className={mode === 'command' ? '' : 'hidden'}>
                <FidoCommandPanel />
            </div>
            <div className={mode === 'inspect' ? '' : 'hidden'}>
                <FidoInspectPanel />
            </div>
        </div>
    );
}
