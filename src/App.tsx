import { useState } from 'react';
import { generateKeyPair, derivePublicKey } from './utils/ssh';
import type { KeyType } from './utils/ssh';

function App() {
  const [activeTab, setActiveTab] = useState<'generate' | 'derive'>('generate');

  // Generation State
  const [keyType, setKeyType] = useState<KeyType>('rsa');
  const [keySize, setKeySize] = useState<number>(2048);
  const [genPassphrase, setGenPassphrase] = useState('');
  const [genResult, setGenResult] = useState<{ privateKey: string; publicKey: string } | null>(null);
  const [genError, setGenError] = useState<string | null>(null);
  const [isGenerating, setIsGenerating] = useState(false);

  // Derivation State
  const [deriveKey, setDeriveKey] = useState('');
  const [derivePassphrase, setDerivePassphrase] = useState('');
  const [deriveResult, setDeriveResult] = useState<string | null>(null);
  const [deriveError, setDeriveError] = useState<string | null>(null);

  const copyToClipboard = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      // Optional: show toast
    } catch (err) {
      console.error('Failed to copy', err);
    }
  };

  const handleGenerate = async () => {
    setIsGenerating(true);
    setGenError(null);
    setGenResult(null);

    // Add small delay to ensure UI renders loading state before async work
    setTimeout(async () => {
      try {
        const res = await generateKeyPair(keyType, keySize, genPassphrase);
        setGenResult(res);
      } catch (e: any) {
        setGenError(e.message || 'Generation failed');
      } finally {
        setIsGenerating(false);
      }
    }, 50);
  };

  const handleDerive = () => {
    try {
      setDeriveError(null);
      setDeriveResult(null);
      if (!deriveKey.trim()) {
        setDeriveError('Please enter a private key');
        return;
      }
      const res = derivePublicKey(deriveKey, derivePassphrase);
      setDeriveResult(res);
    } catch (e: any) {
      setDeriveError(e.message || 'Derivation failed');
    }
  };

  const renderKeySizeOptions = () => {
    if (keyType === 'ed25519') return null;

    let options: number[] = [];
    if (keyType === 'rsa') options = [2048, 4096];
    if (keyType === 'ecdsa') options = [256, 384, 521];

    return (
      <div className="flex flex-col gap-1">
        <label className="text-xs font-medium text-gray-400">
          {keyType === 'ecdsa' ? 'Curve Size' : 'Key Size'}
        </label>
        <select
          value={keySize}
          onChange={(e) => setKeySize(Number(e.target.value))}
          className="p-2 rounded bg-gray-800 border border-gray-700 text-sm focus:border-blue-500 outline-none"
        >
          {options.map(size => (
            <option key={size} value={size}>{size} {keyType === 'ecdsa' ? (size === 521 ? '(nistp521)' : `(nistp${size})`) : 'bits'}</option>
          ))}
        </select>
      </div>
    );
  };

  return (
    <div className="w-full h-full p-4 flex flex-col gap-4 text-gray-200">
      <header className="flex items-center justify-between border-b border-gray-700 pb-2">
        <div className="flex items-center gap-2">
          <img src="/logo.png" alt="Logo" className="w-6 h-6" />
          <h1 className="text-lg font-bold bg-clip-text text-transparent bg-gradient-to-r from-blue-400 to-teal-400">
            SSH Keytool
          </h1>
        </div>
      </header>

      <div className="flex bg-gray-800 rounded-lg p-1 gap-1">
        <button
          onClick={() => setActiveTab('generate')}
          className={`flex-1 py-1 px-3 rounded text-sm font-medium transition-colors ${activeTab === 'generate' ? 'bg-gray-700 text-white shadow' : 'text-gray-400 hover:text-white'
            }`}
        >
          Generate
        </button>
        <button
          onClick={() => setActiveTab('derive')}
          className={`flex-1 py-1 px-3 rounded text-sm font-medium transition-colors ${activeTab === 'derive' ? 'bg-gray-700 text-white shadow' : 'text-gray-400 hover:text-white'
            }`}
        >
          Derive Public Key
        </button>
      </div>

      <div className="flex-1 overflow-auto">
        {activeTab === 'generate' && (
          <div className="flex flex-col gap-4">
            <div className="grid grid-cols-2 gap-3">
              <div className="flex flex-col gap-1">
                <label className="text-xs font-medium text-gray-400">Algorithm</label>
                <select
                  value={keyType}
                  onChange={(e) => {
                    const type = e.target.value as KeyType;
                    setKeyType(type);
                    if (type === 'ecdsa') setKeySize(256);
                    if (type === 'rsa') setKeySize(2048);
                  }}
                  className="p-2 rounded bg-gray-800 border border-gray-700 text-sm focus:border-blue-500 outline-none"
                >
                  <option value="rsa">RSA</option>
                  <option value="ed25519">ED25519</option>
                  <option value="ecdsa">ECDSA</option>
                </select>
              </div>
              {renderKeySizeOptions()}
            </div>

            <div className="flex flex-col gap-1">
              <label className="text-xs font-medium text-gray-400">Passphrase (Optional)</label>
              <input
                type="password"
                value={genPassphrase}
                onChange={(e) => setGenPassphrase(e.target.value)}
                className="p-2 rounded bg-gray-800 border border-gray-700 text-sm focus:border-blue-500 outline-none placeholder-gray-600"
                placeholder="Enter passphrase to encrypt key..."
              />
            </div>

            <button
              onClick={handleGenerate}
              disabled={isGenerating}
              className="w-full py-2 bg-blue-600 hover:bg-blue-500 rounded font-medium text-white shadow-lg transition-all active:scale-95 disabled:opacity-50 disabled:active:scale-100"
            >
              {isGenerating ? 'Generating...' : 'Generate Key Pair'}
            </button>

            {genError && (
              <div className="p-3 bg-red-900/50 border border-red-800 rounded text-red-200 text-sm">
                {genError}
              </div>
            )}

            {genResult && (
              <div className="flex flex-col gap-3 mt-2 animate-in fade-in slide-in-from-bottom-2">
                <div className="group relative">
                  <div className="flex justify-between items-center mb-1">
                    <span className="text-xs font-medium text-gray-400">Private Key</span>
                    <button
                      onClick={() => copyToClipboard(genResult.privateKey)}
                      className="text-xs text-blue-400 hover:text-blue-300 transition-colors"
                    >
                      Copy
                    </button>
                  </div>
                  <textarea
                    readOnly
                    value={genResult.privateKey}
                    className="w-full h-24 p-2 text-xs font-mono bg-gray-950 rounded border border-gray-800 focus:border-gray-700 outline-none resize-none text-gray-400"
                  />
                </div>

                <div className="group relative">
                  <div className="flex justify-between items-center mb-1">
                    <span className="text-xs font-medium text-gray-400">Public Key</span>
                    <button
                      onClick={() => copyToClipboard(genResult.publicKey)}
                      className="text-xs text-blue-400 hover:text-blue-300 transition-colors"
                    >
                      Copy
                    </button>
                  </div>
                  <textarea
                    readOnly
                    value={genResult.publicKey}
                    className="w-full h-16 p-2 text-xs font-mono bg-gray-950 rounded border border-gray-800 focus:border-gray-700 outline-none resize-none text-gray-400"
                  />
                </div>
              </div>
            )}
          </div>
        )}

        {activeTab === 'derive' && (
          <div className="flex flex-col gap-4">
            <div className="flex flex-col gap-1">
              <label className="text-xs font-medium text-gray-400">Private Key (PEM/OpenSSH)</label>
              <textarea
                value={deriveKey}
                onChange={(e) => setDeriveKey(e.target.value)}
                className="w-full h-32 p-2 text-xs font-mono bg-gray-800 rounded border border-gray-700 focus:border-blue-500 outline-none resize-none"
                placeholder="-----BEGIN OPENSSH PRIVATE KEY-----..."
              />
            </div>

            <div className="flex flex-col gap-1">
              <label className="text-xs font-medium text-gray-400">Passphrase (if encrypted)</label>
              <input
                type="password"
                value={derivePassphrase}
                onChange={(e) => setDerivePassphrase(e.target.value)}
                className="p-2 rounded bg-gray-800 border border-gray-700 text-sm focus:border-blue-500 outline-none placeholder-gray-600"
                placeholder="Enter passphrase..."
              />
            </div>

            <button
              onClick={handleDerive}
              className="w-full py-2 bg-purple-600 hover:bg-purple-500 rounded font-medium text-white shadow-lg transition-all active:scale-95"
            >
              Derive Public Key
            </button>

            {deriveError && (
              <div className="p-3 bg-red-900/50 border border-red-800 rounded text-red-200 text-sm">
                {deriveError}
              </div>
            )}

            {deriveResult && (
              <div className="mt-2 animate-in fade-in slide-in-from-bottom-2">
                <div className="flex justify-between items-center mb-1">
                  <span className="text-xs font-medium text-gray-400">Public Key</span>
                  <button
                    onClick={() => copyToClipboard(deriveResult)}
                    className="text-xs text-blue-400 hover:text-blue-300 transition-colors"
                  >
                    Copy
                  </button>
                </div>
                <textarea
                  readOnly
                  value={deriveResult}
                  className="w-full h-24 p-2 text-xs font-mono bg-gray-950 rounded border border-gray-800 focus:border-gray-700 outline-none resize-none text-gray-400"
                />
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

export default App;
