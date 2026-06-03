# Contributing To SecureCheck

Thank you for helping improve SecureCheck.

SecureCheck is intended for AI builders who need a lightweight, browser-based first pass over common website security mistakes. Contributions should keep the tool practical, privacy-preserving, and understandable for non-security specialists.

## Good Contributions

- New passive scanner rules for common AI-built website mistakes
- Fixes that reduce false positives
- Framework-specific AI remediation prompts
- Example vulnerable fixtures for testing scanner logic
- Bilingual English and Traditional Chinese copy improvements
- Browser extension security improvements
- Documentation, screenshots, and usage examples

## Scanner Rule Guidelines

Before adding a finding, please make sure it is:

- Passively detectable from the browser
- Useful to a non-security-specialist builder
- Specific enough to generate an actionable AI fix prompt
- Low enough risk that the scan does not attack, fuzz, brute-force, or mutate the target site
- Clear about limitations and possible false positives

Each issue should include:

- Stable `id`
- `severity`: `P0`, `P1`, or `P2`
- `category`
- English and Traditional Chinese titles and descriptions
- Reference such as OWASP, CWE, Mozilla Observatory, W3C, or relevant browser/security guidance
- A copy-ready `fixPrompt`

## Privacy Requirements

SecureCheck should not collect or transmit scan results.

Rules must avoid exposing sensitive values:

- Mask detected secrets.
- Do not show cookie values.
- Do not persist scan results in extension storage.
- Do not send target-site data to external services.

## Severity Guide

- `P0`: Critical. Credentials, secrets, database backups, mixed content on sensitive pages, or browser behavior that can immediately compromise users.
- `P1`: Warning. Important security controls missing, likely exploitable frontend patterns, exposed admin/API surfaces, insecure session cookies.
- `P2`: Advisory. Hardening gaps, information exposure, best-practice issues, or findings that need human confirmation.

## Development

Load the extension locally:

1. Open `chrome://extensions`.
2. Enable Developer mode.
3. Click Load unpacked.
4. Select this project folder.
5. Open a live website and run a scan.

## Reporting False Positives

When reporting a false positive, include:

- The finding ID
- Browser and extension version
- Target-site framework or host if known
- Why the finding is not actionable
- A safer detection rule if you have one

