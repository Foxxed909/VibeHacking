# Browser-extension popup (archived)

`popup.js` is the popup controller for the "Shielder+" browser extension
(AES-GCM/PBKDF2 credential vault UI). It is kept here for reference only:

- it is **not wired into anything** in this repo,
- there is no `manifest.json` / `popup.html` next to it,
- the toolkit does not load or ship it.

If the extension is revived, its manifest and markup belong in this directory
alongside the script. Note that generated vault material must never be
committed — keep any local vault export git-ignored.
