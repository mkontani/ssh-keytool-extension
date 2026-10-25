# Chrome Web Store assets

Sources for the images in `assets/webstore/`:

| Output | Size | Source |
|---|---|---|
| `01-generate.png` … `05-inspect-cert.png` | 1280×800 | `shot.html?scene=…` |
| `promo-small-440x280.png` | 440×280 | `tile.html?size=small` |
| `promo-marquee-1400x560.png` | 1400×560 | `tile.html?size=marquee` |

`shot.html` embeds the **real built extension** in an iframe at popup size (400×600),
drives it into a scene and adds an English caption, so screenshots never drift from the
actual UI. Scenes: `generate`, `fido-builder`, `fido-inspect`, `convert`, `inspect-cert`.

## Regenerating

1. Build and copy the extension next to the templates (the copy is git-ignored):

   ```bash
   npm run build
   rm -rf assets/webstore/src/app && cp -R dist assets/webstore/src/app
   ```

2. Serve the repository root (the templates load `../../logo.png`):

   ```bash
   python3 -m http.server 4181 --bind 127.0.0.1
   ```

3. Capture each page with a headless browser at the exact size, `deviceScaleFactor: 1`,
   `locale: 'en-US'` and `colorScheme: 'dark'`. Wait for `document.body.dataset.ready === 'true'`
   before taking the screenshot. With Playwright:

   ```js
   const ctx = await browser.newContext({ viewport: { width: 1280, height: 800 }, deviceScaleFactor: 1, locale: 'en-US', timezoneId: 'UTC', colorScheme: 'dark' });
   const page = await ctx.newPage();
   await page.goto('http://127.0.0.1:4181/assets/webstore/src/shot.html?scene=generate');
   await page.waitForFunction(() => document.body.dataset.ready === 'true');
   await page.screenshot({ path: 'assets/webstore/01-generate.png' });
   ```

4. Check the output is 24-bit PNG without alpha (store requirement):
   `sips -g hasAlpha assets/webstore/*.png` should print `hasAlpha: no`.

## Demo data

- The FIDO key in `shot.html` is a key *handle* rebuilt from OpenSSH's public test vector
  (`regress/unittests/sshkey/testdata/ed25519_sk1`), not a real credential.
- The certificate was signed by a throwaway CA; its private key was never stored.
- The Convert scene generates a fresh key in the app at capture time, so no private key
  is committed.
