# Example SecureCheck Scan Report

This is a fictional report for reviewers and contributors. It uses the reserved `.example` domain and deliberately fake findings. It does not include real user data, real secrets, or a real website scan.

## Target

- URL: `https://demo-app.example`
- Context: AI-built storefront demo
- Detected stack: `Vite, Netlify`
- Security score: `56/100`
- Compliance risk score: `70/100`
- Total passive checks: `30`

## Summary

| Severity | Count | Meaning |
| --- | ---: | --- |
| P0 Critical | 1 | Could immediately expose credentials or users |
| P1 Warning | 2 | Meaningful production security risk |
| P2 Advisory | 2 | Hardening or review recommended |

## Findings

### P0 Critical: Secret-like API key exposed in frontend source

- Category: Source Code and DOM
- Reference: `CWE-798`
- Evidence: A fake OpenAI-style key pattern was found in a same-origin JavaScript bundle and masked before display.
- Why it matters: API keys in frontend bundles can be copied by anyone who can load the page.

Copy-ready AI fix prompt:

```text
URGENT: My website has a secret-like API key exposed in frontend JavaScript source code. Tech stack: Vite, Netlify. Please tell me how to immediately revoke and regenerate this key, then show me how to move API calls to a backend function so keys are never exposed in frontend code.
```

### P1 Warning: Missing Content-Security-Policy header

- Category: HTTP Security Headers
- Reference: `OWASP ASVS 14.4.3`
- Evidence: No `Content-Security-Policy` response header was detected on the demo page.
- Why it matters: A CSP can reduce the blast radius of cross-site scripting and script injection bugs.

Copy-ready AI fix prompt:

```text
My website (https://demo-app.example) is missing a Content-Security-Policy header. Tech stack: Vite, Netlify. Please generate an appropriate CSP policy and show me exactly where to add it in my Netlify headers configuration.
```

### P1 Warning: Session cookie missing SameSite

- Category: Cookie Security
- Reference: `OWASP ASVS 3.4.3`
- Evidence: A fake session cookie name did not include a `SameSite` attribute.
- Why it matters: SameSite helps reduce cross-site request forgery risk.

Copy-ready AI fix prompt:

```text
My website has a session/auth cookie without the SameSite attribute. Tech stack: Vite, Netlify. Please explain the difference between SameSite=Strict and Lax, recommend the safer setting for my login flow, and show me how to set it.
```

### P2 Advisory: External script without Subresource Integrity

- Category: Source Code and DOM
- Reference: `OWASP ASVS 14.2.3`
- Evidence: A demo CDN script did not include an `integrity` attribute.
- Why it matters: SRI helps protect users if a third-party script source is compromised.

Copy-ready AI fix prompt:

```text
My website loads an external script without Subresource Integrity. Please show me how to generate an integrity hash and update the script tag safely.
```

### P2 Advisory: Server technology exposed

- Category: HTTP Security Headers
- Reference: `OWASP ASVS 14.3.3`
- Evidence: A demo response exposed a `Server` header.
- Why it matters: Exposed technology details can help attackers fingerprint the stack.

Copy-ready AI fix prompt:

```text
My website exposes server technology details in response headers. Tech stack: Vite, Netlify. Please show me whether this can be reduced on my hosting platform and what headers should be avoided.
```

## Copy-All Prompt Example

```text
SecureCheck Security Report
Found 5 issue(s) | Security Score: 56/100 | Compliance Score: 70/100
Tech Stack: Vite, Netlify

Please help me fix all security issues above, starting with the most critical ones. For each fix, show the exact file or hosting configuration to change, explain any tradeoffs, and avoid weakening the privacy model.
```

## Notes For Contributors

This report demonstrates the intended remediation workflow:

1. Detect a browser-visible issue.
2. Explain the impact in plain language.
3. Generate an AI-ready fix prompt.
4. Keep the user in control of applying the code change.

SecureCheck does not send reports or findings to any AI provider automatically.
