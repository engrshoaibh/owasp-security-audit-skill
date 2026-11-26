# Changelog

All notable changes to this project are listed here. Versions follow [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-11-26

First tagged release. An OWASP-based security audit skill for AI coding agents (Claude Code, Codex, Gemini CLI,
Cursor, Windsurf) with a standard-library static scanner, an optional multi-tool orchestrator and an auto-managed
OWASP ZAP engine for DAST.

### Highlights
- **Two depths.** "Quick security check of `src/auth/`" or "Is this PR safe to merge?" runs a fast static pass with no
  questions, installs or network calls. "Audit this project" runs the full 6-step audit with a progress tracker and a
  findings register.
- **OWASP 2025 mapping.** Every finding carries a CWE, a confidence level and OWASP Top 10:2025, API Security
  Top 10:2023 and LLM Top 10:2025 IDs.
- **One-command install** for Claude Code (plugin marketplace or skill folder), Codex and other `AGENTS.md` agents,
  Gemini CLI / Antigravity, Cursor and Windsurf.
- **IDOR / BOLA review procedure** (`references/access-control-review.md`): endpoint inventory, owner-check tracing per
  framework, BOPLA/BFLA and business-flow checks, two-account verification.
- **Examples:** copy-paste prompts, a sample report, an intentionally vulnerable Flask app and a 60-second
  OWASP Juice Shop demo.

### Scanner (`scripts/loophole_scanner.py`)
- 42 rules across secrets, injection, SSTI, XSS, NoSQL, path traversal, XXE, crypto, BaaS rules, LLM supply chain,
  GitHub Actions, Docker, git hygiene and resource-exhaustion loops (`--list-rules`).
- Output as Markdown, JSON or SARIF 2.1.0 for GitHub code scanning; `--fail-on` for CI gates.
- `--quick`, `--changed [BASE]` (only files changed in a PR) and `--paths` for scoped scans.
- Inline suppressions, an ignore-file marker and a baseline file for accepted findings.
- Secrets are masked in every output format; TruffleHog verification is off unless you pass `--allow-network-verify`.

### Safety
- Active ZAP scans and Docker API scans refuse to run without `--confirm-authorized` and are scoped to the target URL.
- Partial or timed-out DAST runs are labelled incomplete and exit non-zero instead of passing.
- Package managers resolve to absolute paths, so an audited repo cannot plant a fake `brew` or `scoop`.
- The scanner skips symlinks so a link cannot read files outside the target.
- The audited code is treated as data, never as instructions, and the agent asks before installs, network calls and DAST.

### Project
- Apache-2.0 license (now detected by GitHub), CONTRIBUTING guide, security policy, OpenSSF Scorecard,
  SHA-pinned actions and a dependency-free CI with a self-scan gate.

[0.1.0]: https://github.com/engrshoaibh/owasp-security-audit-skill/releases/tag/v0.1.0
