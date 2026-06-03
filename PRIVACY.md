# SecureCheck AI Web Scanner Privacy Policy

Last updated: June 3, 2026

SecureCheck AI Web Scanner is a Chrome extension for scanning AI-built websites for browser-visible security risks. This policy explains how the extension handles data.

## Summary

SecureCheck AI Web Scanner does not collect, sell, share, or transmit user data to the developer or to third parties.

The extension runs locally in the browser. It does not operate a backend server, does not use analytics, does not serve ads, and does not include tracking pixels.

## Data Processed Locally

When the user clicks "Scan This Site", SecureCheck AI Web Scanner may process the following data locally in the browser:

- The active tab URL and origin.
- The current page HTML and DOM structure.
- Same-origin JavaScript files referenced by the page.
- HTTP response headers from the scanned website.
- Publicly reachable same-origin paths used for passive exposed-file checks.
- Cookie names and cookie security attributes such as `HttpOnly`, `Secure`, and `SameSite`.

Cookie values are never read, displayed, stored, or transmitted.

## Purpose

SecureCheck AI Web Scanner uses this local data only to:

- Detect browser-visible security risks.
- Show scan findings to the user.
- Generate copy-ready remediation prompts for AI coding assistants.
- Store the user's language preference locally.

## Storage

SecureCheck AI Web Scanner keeps scan results in extension memory only during the extension session. It does not persist scan results in Chrome storage.

The extension may store the selected UI language locally so the popup can remember the user's preference.

## Network Requests

SecureCheck AI Web Scanner sends network requests only to the website being scanned. These requests are used for passive checks such as reading response headers, checking same-origin JavaScript bundles, and testing whether common sensitive paths are publicly reachable.

SecureCheck AI Web Scanner does not send scan results, URLs, page content, cookies, or findings to any external analytics service, AI service, advertising network, or developer-operated server.

## Permissions

SecureCheck AI Web Scanner requests only the permissions needed for its single purpose:

- `activeTab`: read the active tab when the user starts a scan.
- `tabs`: identify the active tab and URL.
- `scripting`: run passive scanner logic on the active page.
- `storage`: remember local UI preferences.
- Optional `cookies`: inspect cookie names and security attributes for the scanned site.
- Optional host permissions: temporarily access the scanned site origin.

Temporary site permissions are requested at scan time and removed after the scan finishes when possible.

## Limited Use

SecureCheck AI Web Scanner's use and transfer of information received from Chrome APIs is limited to providing the extension's single purpose. SecureCheck AI Web Scanner does not sell user data, use user data for advertising, or use user data to determine creditworthiness or for lending purposes.

## Security

SecureCheck AI Web Scanner masks detected secret-like values before showing them in the UI. It avoids reading cookie values and avoids persistent storage of scan findings.

## Changes

If this policy changes, the updated version will be published in the public privacy policy repository and the "Last updated" date will be revised.

## Contact

For privacy or security questions, open an issue in the SecureCheck AI Web Scanner GitHub repository:

<https://github.com/Eric4045/securecheck-ai-web-scanner>
