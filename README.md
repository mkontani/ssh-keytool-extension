# <img src="assets/logo.png" width="48" height="48" alt="Logo" style="vertical-align: middle; margin-right: 8px;"> SSH Keytool Extension

A secure, offline-capable Chrome Extension for generating SSH key pairs, deriving public keys, inspecting SSH certificates, and converting private keys between OpenSSH, PEM (PKCS#1/PKCS#8), and PuTTY PPK formats — directly in your browser.

![SSH Keytool: generate SSH keys in your browser](assets/webstore/01-generate.png)

## Features

- **Generate SSH Keys**: Supports RSA (2048/4096-bit), ECDSA (nistp256/384/521), and ED25519.
- **Passphrase Protection**: Encrypt private keys with a passphrase using robust OpenSSH encryption.
- **Public Key Derivation**: Derive the associated public key from an existing private key.
- **SSH Certificate Inspection**: Inspect details of SSH certificates (Key ID, Principals, Validity, Extensions, etc.).
- **Key Format Conversion**: Convert private keys between OpenSSH, PKCS#1, PKCS#8 (PBES2 with PBKDF2-SHA256 + AES-256-CBC), and PuTTY PPK v2 formats. Add, remove, or change passphrases in one step.
- **FIDO Security Keys**: Build `ssh-keygen -t ed25519-sk / ecdsa-sk` commands with resident / PIN / no-touch options, plus matching `authorized_keys`, `sshd_config`, and git signing snippets. Inspect FIDO (`sk-`) public keys and private key files to see the application, fingerprint, and touch / PIN / resident flags.
- **Offline & Secure**: All cryptographic operations happen locally within the extension. No keys are ever sent to any server.
- **Modern UI**: Clean, responsive interface with Dark Mode support.

![SSH Keytool: build commands for FIDO security keys](assets/webstore/02-fido-command-builder.png)

## Installation

1. Clone this repository.
2. Run `npm install` to install dependencies.
3. Run `npm run build` to build the extension.
4. Open Chrome and navigate to `chrome://extensions`.
5. Enable **Developer mode** in the top right.
6. Click **Load unpacked** and select the `dist` directory from the project folder.

## Usage

### Generating Keys
1. Open the extension popup.
2. Select the "Generate" tab.
3. Choose your desired algorithm (RSA, ED25519, or ECDSA) and key size.
4. (Optional) Enter a passphrase to encrypt the private key.
5. Click **Generate Key Pair**.
6. Copy the private and public keys to your clipboard.

### Deriving Public Keys
1. Select the "Derive" tab.
2. Paste your private key (OpenSSH/PEM format).
3. If the key is encrypted, enter the passphrase.
4. Click **Derive Public Key**.

### Inspecting SSH Certificates
1. Select the "Cert" tab.
2. Paste your SSH certificate (e.g., `ssh-rsa-cert-v01@openssh.com ...`).
3. View parsed details such as Type, Key ID, Valid Principals, Validity Period, Extensions, and Critical Options.

### Converting Keys
1. Select the "Convert" tab.
2. Paste your private key (OpenSSH, PKCS#1, PKCS#8, or PuTTY PPK). The source format is auto-detected and shown as a badge.
3. If the source key is encrypted, enter its passphrase in **Source Passphrase**.
4. Pick a **Target Format** (OpenSSH / PKCS#1 / PKCS#8 / PuTTY PPK v2).
5. (Optional) Enter a **Target Passphrase** to encrypt the output, or leave it empty for an unencrypted key. Changing or removing a passphrase is just a conversion to the same format with a different (or empty) target passphrase.
6. Click **Convert Key** and copy the output.

Notes:
- PKCS#1 is RSA-only — ED25519 / ECDSA keys cannot be exported as PKCS#1.
- Choosing PKCS#1 + a passphrase auto-upgrades the output to PKCS#8 (encrypted PKCS#1 is non-standard); a note is shown.
- PuTTY PPK v2 uses a weak SHA-1-based KDF without salt; a warning is shown when encrypting to PPK. Prefer OpenSSH or PKCS#8 when interop allows.
- FIDO (`sk-`) keys cannot be converted: the file is only a handle for the security key and exists solely in OpenSSH format. To change its passphrase, run `ssh-keygen -p -f <file>`.

### FIDO Security Keys
FIDO keys (`ed25519-sk` / `ecdsa-sk`, OpenSSH 8.2+) are created on a hardware security key such as a YubiKey, so the extension does not generate them. It helps you build the right command and inspect the result.

**Command Builder**
1. Select the "FIDO" tab, then "Command Builder".
2. Choose the algorithm and options: **Resident key** (`-O resident`), **Require PIN** (`-O verify-required`), **No touch required** (`-O no-touch-required`), plus an optional application (`ssh:...`), user, comment, and output file.
3. Copy the `ssh-keygen` command and run it with your security key plugged in.
4. Copy the matching `authorized_keys` line (with `no-touch-required` / `verify-required` options as needed) and, optionally, the `sshd_config` and git commit signing snippets.

**Inspect Key**
1. Select the "FIDO" tab, then "Inspect Key".
2. Paste an `sk-...` public key line or a FIDO private key file (`id_ed25519_sk`).
3. View the type, application, and SHA256 fingerprint. For private key files, the touch / PIN / resident flags and a matching `authorized_keys` line are also shown. Encrypted files show their public data right away; enter the passphrase and click **Unlock** to see the rest.

Notes:
- A FIDO private key file is only a handle: signing still requires the physical security key.
- macOS's built-in `ssh-keygen` has no FIDO support (`No FIDO SecurityKeyProvider specified`); use a FIDO-enabled OpenSSH such as Homebrew's (`brew install openssh`).
- Encrypted FIDO key files are supported with the `aes128/192/256-ctr` and `aes128/192/256-cbc` ciphers (`ssh-keygen`'s default is `aes256-ctr`). `chacha20-poly1305@openssh.com` and AES-GCM are not supported.
- The "Derive" tab also accepts FIDO private key files.
- FIDO certificates (`sk-*-cert-v01@openssh.com`) are not supported yet.

## Development

- `npm run dev`: Start development server (for UI testing in browser).
- `npm run build`: Build for production.
- `npm test`: Run verification scripts.

## License

MIT
