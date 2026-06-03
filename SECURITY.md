# Security Policy

SecureCheck AI Web Scanner is a security-focused browser extension. Please report vulnerabilities responsibly.

## Scope

In scope:

- Extension permission issues
- Scan result leakage
- Cookie value exposure
- Unmasked secret exposure in reports
- DOM injection or XSS inside the extension UI
- Unsafe handling of messages between popup, background, and injected scanner scripts
- Findings that cause harmful active scanning behavior
- False positives that could lead users to make unsafe changes

Out of scope:

- Vulnerabilities in websites scanned by SecureCheck
- Browser or Chrome Web Store platform issues
- Social engineering or phishing
- Denial of service against third-party websites

## Disclosure

If you find a vulnerability, please avoid publishing details until there is time to investigate and patch it.

Please include:

- A description of the issue
- Reproduction steps
- Impact
- Browser and extension version
- Any relevant screenshots or proof of concept

Do not include real secrets, customer data, or private website content in reports. Use masked values or a local test page whenever possible.

## Security Principles

SecureCheck should:

- Keep scan results local
- Avoid persisting scan results
- Avoid reading cookie values
- Mask detected secrets
- Request only the permissions needed for the current scan
- Remove temporary site permissions after scanning
- Avoid active attacks, brute force, fuzzing, form submission, or state-changing requests
