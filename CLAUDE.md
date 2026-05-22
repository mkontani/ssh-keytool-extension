# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A Chrome Extension (Manifest V3) that generates SSH key pairs, derives public keys from private keys, and inspects SSH certificates — all entirely client-side with no network access. The same build is also published as a static web app (GitHub Pages) using the same React UI.

## Commands

- `npm run dev` — Vite dev server for UI iteration in the browser (no Chrome extension reload required).
- `npm run build` — `tsc -b` then `vite build`, producing the `dist/` directory that is loaded as the unpacked Chrome extension.
- `npm run lint` — ESLint over `**/*.{ts,tsx}` (flat config, with `dist` ignored globally).
- `npm test` — Runs both verification scripts via `vite-node`:
  - `scripts/verify.ts` — exercises `generateKeyPair` for RSA/ED25519/ECDSA plus `derivePublicKey` round-trip.
  - `scripts/verify_cert.ts` — exercises `parseCertificate` against a hard-coded OpenSSH cert with multiple principals.
- Run a single verification script: `npx vite-node scripts/verify_cert.ts`.
- `npm run preview` — Serve the built `dist/` for sanity-checking the production bundle.

## Architecture

### Dual deploy target (extension + static site)

`public/manifest.json` declares an MV3 popup pointing at `index.html`. Vite is configured with `base: './'` so the same build artifacts work whether loaded as `chrome-extension://<id>/index.html` or hosted at any subpath on GitHub Pages — never introduce absolute `/`-rooted asset paths. `vite-plugin-node-polyfills` is required because `sshpk` and friends depend on `Buffer`/`stream` shims in the browser bundle.

### Crypto layer (`src/utils/ssh.ts`)

This single module is the entire domain logic. Three exported entry points: `generateKeyPair`, `derivePublicKey`, `parseCertificate`. Key design choices that are easy to break accidentally:

- **RSA keys use the Web Crypto API** (`SubtleCrypto.generateKey` → PKCS8 → PEM), then are *re-parsed* by `sshpk` so the rest of the pipeline can treat all algorithms uniformly. ED25519/ECDSA are generated directly via `sshpk.generatePrivateKey` because Web Crypto coverage is uneven across browsers for those curves. ECDSA `size` maps to curves (`256→nistp256`, `384→nistp384`, `521→nistp521`).
- **Public key output is normalized to single-line OpenSSH** by `formatPublicKey`. If `sshpk` returns RFC4716 (BEGIN/END framed) the function manually reassembles `<type> <base64> <comment>` from the rfc4253 buffer. Don't replace this with a plain `toString('openssh')`.
- **Certificate parsing relies on undocumented `sshpk` shape.** `@types/sshpk` does not expose `subjects`, `signatures.openssh.exts`, etc., so `parseCertificate` casts through `unknown` to a hand-written interface. Multiple principals are extracted via three fallback paths (`subject.uid`, `subject.components` of `name === 'uid'`, `subject.principals`) and then deduplicated — `sshpk` versions differ in which path is populated, so all three must remain.
- Passphrase-encrypted private keys are produced through `key.toString('openssh', { passphrase })` and parsed back via `sshpk.parsePrivateKey(pem, 'auto', { passphrase })`.

### UI (`src/App.tsx`)

Single-file, ~360 LOC component with three tabs (`generate` / `derive` / `inspect`) held in local `useState`. The Generate flow wraps the async key generation in a `setTimeout(..., 50)` so React commits the "Generating..." loading state before the synchronous portion of RSA key generation blocks the main thread — keep that delay if you refactor. The Inspect tab parses on every keystroke and swallows errors into an `inspectError` state rather than throwing.

### Testing model

There is no Jest/Vitest harness — verification is `assert`-based scripts run through `vite-node` so they can import the same `src/utils/ssh.ts` the UI uses. When adding new crypto behavior, extend `scripts/verify.ts` (or add a sibling script) and wire it into the `test` npm script.

## CI / Release

- `.github/workflows/ci.yml` — lint → test → build on push/PR to `main`.
- `.github/workflows/deploy-pages.yml` — publishes `dist/` to GitHub Pages on push to `main`.
- `.github/workflows/release.yml` — on GitHub Release creation, builds and uploads `ssh-keytool-extension.zip` (the loadable unpacked extension) as a release asset.

The manifest `version` in `public/manifest.json` and `package.json` `version` are tracked together — bump both for releases.
