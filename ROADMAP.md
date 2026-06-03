# Roadmap

SecureCheck AI Web Scanner is focused on helping AI builders find browser-visible security issues and turn them into actionable AI repair prompts.

## Near Term

- Add fixture-based regression tests for every scanner category.
- Add example vulnerable pages for `.env`, exposed admin routes, unsafe DOM insertion, frontend secrets, insecure cookies, and missing headers.
- Improve framework and hosting detection for Next.js, Vite, Astro, Express, Vercel, Netlify, Render, Cloudflare Pages, Firebase, and Supabase.
- Add screenshots and example scan reports for the README.
- Add extension packaging and release instructions.

## Scanner Improvements

- Fetch and scan same-origin JavaScript bundles more deeply.
- Add source maps detection without downloading private source maps by default.
- Add more frontend secret patterns while keeping false positives low.
- Improve admin/dashboard route heuristics so login pages are not over-reported.
- Improve rate-limit guidance by detecting login and form endpoints passively.

## AI Remediation

- Generate framework-specific prompts when hosting or framework signals are detected.
- Add a compact prompt mode for Codex and other coding agents.
- Add a "review this fix" prompt after the user applies a patch.
- Add safer remediation warnings for findings that require human verification.

## Project Health

- Keep the repository public and easy to review.
- Add release notes and extension packaging instructions.
- Add CI checks for syntax, scanner fixtures, and manifest validation.
- Document the privacy and permission model in more detail.
- Add GitHub Pages for the privacy policy if needed for Chrome Web Store review.
