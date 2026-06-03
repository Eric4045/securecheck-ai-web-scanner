# Open Source Release Checklist

This checklist tracks whether SecureCheck is ready to submit as a Codex for Open Source candidate and as a Chrome Web Store item.

## Done

- [x] Create a public GitHub repository for the project.
- [x] Add the actual SecureCheck extension source code locally.
- [x] Remove the commercial license gate, scan limit, and payment flow.
- [x] Add an open-source license.
- [x] Add `README.md` with purpose, scanner coverage, privacy model, local installation, checks, and limitations.
- [x] Add `CONTRIBUTING.md`.
- [x] Add `SECURITY.md`.
- [x] Add `ROADMAP.md`.
- [x] Add `AGENTS.md` for Codex/review guidance.
- [x] Add scanner fixture tests for headers, endpoints, cookies, and DOM findings.
- [x] Add CI for syntax and scanner tests.
- [x] Add issue templates for false positives and new scanner rules.
- [x] Add Chrome Web Store submission notes.
- [x] Add a public privacy policy repository.
- [x] Add demo screenshots for scan start, progress, results, and copy-prompt workflow.
- [x] Add one example scan report using fictional `.example` data.
- [x] Add release notes for the first public OSS release.
- [x] Publish a GitHub release tag for the first public OSS release.
- [x] Confirm no secrets, private API tokens, customer data, or unreleased sensitive data are committed.
- [x] Ignore `.DS_Store`, packaged extension zips, build artifacts, and local secrets.

## Still Recommended Before Applying

- [x] Rename the GitHub repository from `security-scanner` to `securecheck-ai-web-scanner`.
- [ ] Add one example vulnerable fixture page per scanner category.
- [ ] Add extension packaging instructions and a release zip workflow.
- [ ] Enable GitHub Pages for the privacy policy if Chrome Web Store rejects the GitHub repository URL.
- [x] Add short public roadmap issues to show active maintenance:
  - <https://github.com/Eric4045/securecheck-ai-web-scanner/issues/1>
  - <https://github.com/Eric4045/securecheck-ai-web-scanner/issues/2>
  - <https://github.com/Eric4045/securecheck-ai-web-scanner/issues/3>

## Application Positioning

Use this framing:

SecureCheck is a safety tool for the AI coding ecosystem. It helps AI builders find preventable browser-visible security issues and turn them into actionable prompts for coding agents.

Avoid this framing:

- Do not claim broad adoption unless you have numbers.
- Do not claim it is a complete security audit.
- Do not hide the scanner limitations.
- Do not imply Codex access is guaranteed.

## Current Readiness

Current local project quality: strong concept and real implementation, with a free open-source scanner core, MIT license, contribution/security docs, roadmap, GitHub hygiene, privacy policy, Chrome review notes, demo screenshots, example report, release notes, and scanner regression tests.

Current application readiness: medium to strong after the repository is pushed publicly. It becomes stronger with demo fixtures, a public release tag, and visible community activity.
