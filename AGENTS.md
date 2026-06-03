# AGENTS.md

## Project Guidance

SecureCheck is a Chrome Extension Manifest V3 project for passive browser-visible security scanning of AI-built and vibe-coded websites.

Keep changes focused on:

- Scanner accuracy.
- False-positive reduction.
- Privacy-preserving behavior.
- Chrome extension permission boundaries.
- Clear AI remediation prompts.
- English and Traditional Chinese UI copy.

## Safety Boundaries

- Do not add active attacks, fuzzing, brute force, form submission, credential stuffing, or state-changing requests.
- Do not read, display, store, or transmit cookie values.
- Do not persist scan results in extension storage.
- Do not send scan data to external services or AI providers.
- Mask detected secret-like values before showing them in UI or reports.
- Keep site permissions temporary and scoped to the scanned origin whenever possible.

## Verification

Run these checks before committing:

```bash
npm run check
npm test
```

Also validate these JSON files after manifest or locale edits:

```bash
node -e "JSON.parse(require('fs').readFileSync('manifest.json','utf8')); JSON.parse(require('fs').readFileSync('_locales/en/messages.json','utf8')); JSON.parse(require('fs').readFileSync('_locales/zh_TW/messages.json','utf8'))"
```

## Review Guidelines

- Treat scan-data leakage as P1 or higher.
- Treat cookie-value exposure as P1 or higher.
- Treat extension UI XSS as P1 or higher.
- Treat new unnecessary permissions as P1 unless justified by the scanner's single purpose.
- Treat claims that overstate SecureCheck as a full security audit as P2 documentation risk.
