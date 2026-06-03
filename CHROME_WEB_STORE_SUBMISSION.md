# Chrome Web Store Submission Notes

These notes are for preparing SecureCheck for Chrome Web Store review.

## Single Purpose

SecureCheck scans the currently active website for browser-visible security risks and generates copy-ready remediation prompts for AI coding assistants.

## Privacy Policy URL

Use this public privacy policy URL in the Chrome Web Store Developer Dashboard:

`https://github.com/Eric4045/securecheck-privacy`

If GitHub Pages is enabled for that repository, use this cleaner URL instead:

`https://eric4045.github.io/securecheck-privacy/`

## Data Disclosure Summary

SecureCheck does not collect or transmit user data.

It processes the active tab URL, page content, same-origin JavaScript, HTTP headers, and cookie security attributes locally in the user's browser only after the user starts a scan.

The extension does not:

- Run a backend server.
- Use analytics.
- Use ads.
- Use tracking pixels.
- Send scan results to the developer.
- Send scan results to any AI provider.
- Read or transmit cookie values.
- Persist scan results in extension storage.
- Sell or share user data.

## Permission Justifications

### `activeTab`

Required to scan the active site after the user clicks the scan button.

### `tabs`

Required to identify the active tab and display the current site URL in the popup.

### `scripting`

Required to run passive scanner logic against the active page.

### `storage`

Used only to remember local UI preferences such as language. Scan results are not persisted.

### Optional `cookies`

Requested at scan time to inspect cookie names and security attributes for the scanned site. Cookie values are never read or reported.

### Optional host permissions

Requested at scan time for the current site origin so SecureCheck can passively check headers, exposed files, and same-origin JavaScript bundles. The extension removes temporary site permission after the scan when possible.

## Recommended Developer Dashboard Language

Purpose:

```text
SecureCheck scans the active website for browser-visible security risks and generates copy-ready remediation prompts for AI coding assistants.
```

Privacy disclosure:

```text
SecureCheck does not collect or transmit user data. It processes the active tab URL, page content, same-origin JavaScript, HTTP headers, and cookie security attributes locally in the user's browser only to provide the scan. Cookie values are never read, and scan results are not persisted.
```

Permission note:

```text
The extension requests site permissions only when the user starts a scan, uses them for the scanned origin, and removes them after the scan when possible.
```

## Public Review Assets

- README with screenshots: <https://github.com/Eric4045/securecheck-ai-web-scanner>
- Example scan report: <https://github.com/Eric4045/securecheck-ai-web-scanner/blob/main/docs/example-report.md>
- Release notes: <https://github.com/Eric4045/securecheck-ai-web-scanner/blob/main/docs/release-notes/v1.0.0.md>
- Privacy policy: <https://github.com/Eric4045/securecheck-privacy>

## Review Risk Areas To Watch

- Keep all scan behavior passive.
- Do not add analytics without updating the privacy policy and dashboard disclosure.
- Do not send scan results to AI services automatically.
- Do not read cookie values.
- Do not persist scan results.
- Do not add remote code.
- Keep the privacy policy, manifest permissions, and dashboard disclosures consistent.
