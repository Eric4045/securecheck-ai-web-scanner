# Codex For Open Source Application Notes

Use this file as the source material for the Codex for Open Source application. Keep the claims factual and do not imply that acceptance is guaranteed.

## Project Name

SecureCheck AI Web Scanner

## Repository URL

Current public repository:

`https://github.com/Eric4045/securecheck-ai-web-scanner`

## Short Description

SecureCheck is a free, open-source Chrome extension that scans AI-built and vibe-coded websites for browser-visible security risks, then generates copy-ready fix prompts for AI coding assistants.

## Longer Project Description

SecureCheck is built for developers, founders, students, and non-specialists who use AI coding tools to create and deploy websites quickly. These users often get a working product before they understand basic web security hygiene. SecureCheck gives them a practical first-pass safety review: it scans the active website for common browser-visible risks, explains findings in plain language, and generates targeted AI fix prompts that can be pasted into Codex, ChatGPT, Claude, Cursor, or another coding assistant.

The scanner checks HTTP security headers, exposed sensitive files and endpoints, cookie flags, frontend secret leakage, mixed content, unsafe DOM insertion patterns, console leakage, external scripts without SRI, token storage in localStorage, and eval usage. It focuses on passive checks that can be performed from the browser without backend credentials, form submission, fuzzing, brute force, or state-changing requests.

## Why This Fits Codex

SecureCheck is directly connected to AI-assisted software development. Its users are people who build websites with AI and need a bridge between "the AI made my site work" and "the site is safer to ship." The extension turns security findings into concrete remediation prompts that a coding agent can act on.

Codex would help maintain and expand SecureCheck by:

- Improving scanner rules and reducing false positives.
- Adding tests and vulnerable fixtures for detection logic.
- Producing framework-specific remediation prompts for Next.js, Vite, Astro, Express, Vercel, Netlify, Render, Cloudflare Pages, Firebase, and Supabase.
- Reviewing extension security, permission boundaries, and privacy behavior.
- Maintaining bilingual English and Traditional Chinese documentation.
- Creating example reports that teach AI builders how to fix common issues safely.

## Maintainer Role

I am the creator and maintainer of SecureCheck. I designed the product direction, built the Chrome extension, wrote the scanner logic, and maintain the UI, privacy model, and AI remediation-prompt workflow.

## Current Status

The project contains:

- Chrome Extension Manifest V3 implementation.
- Header, endpoint, cookie, and DOM scanners.
- Same-origin JavaScript bundle scanning.
- English and Traditional Chinese UI.
- One-click AI remediation prompts.
- Memory-only scan result handling.
- Site-specific runtime permission request and removal.
- Free open-source scanning with no license gate, scan limit, paywall, ads, or analytics.
- MIT license.
- Contribution guide, security policy, issue templates, CI, and scanner tests.
- A public privacy policy prepared for Chrome Web Store review.
- Demo screenshots, example scan report, and public release notes for reviewer visibility.

## Open Source Plan

The immediate open-source roadmap is:

- Publish and maintain the scanner source publicly.
- Add more screenshots, demo GIFs, and example scan reports.
- Expand scanner fixture tests.
- Add example vulnerable pages for common AI-built website mistakes.
- Add more framework-specific fix prompts.
- Improve Chrome Web Store packaging and review documentation.
- Continue documenting the privacy model and passive-scan limitations.

## Impact

SecureCheck helps AI builders catch preventable security issues before they ship. It is especially useful for small teams, solo builders, and non-security specialists who rely on AI coding assistants. It lowers the barrier to basic security hygiene by translating technical findings into instructions that an AI assistant can use to patch the site.

The project can also become a public reference for safe AI-assisted remediation workflows: detect a risk, explain the impact, generate a targeted fix prompt, and let the user keep control of the actual code change.

## Honest Caveats

SecureCheck is not a full penetration testing tool. It does not test backend authorization, business logic, dependency vulnerabilities, server-side validation, or database permissions. It is a first-pass browser-visible scanner focused on common mistakes and AI-assisted remediation.

The project still needs stronger public proof of usefulness, such as outside contributors, user feedback, Chrome Web Store usage, and more reproducible vulnerable fixtures.

## Application Answer Snippet

I am applying for support because SecureCheck is an open-source security tool for the AI coding ecosystem. It helps people who build websites with AI detect common browser-visible security risks and then copy targeted remediation prompts into an AI coding assistant such as Codex. With Codex access, I can improve scanner accuracy, add tests and fixtures, expand framework-specific remediation prompts, and make the project more useful for the growing number of AI builders shipping web apps without a security background.
