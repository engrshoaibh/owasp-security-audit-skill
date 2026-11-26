# Contributing

Thanks for helping make AI-assisted security audits better. This project is small and friendly to first-time
contributors: most changes are a regex rule, a checklist line, or a docs fix.

Look for issues labelled [`good first issue`](https://github.com/engrshoaibh/owasp-security-audit-skill/labels/good%20first%20issue).
Comment on one before you start so two people do not work on the same thing.

> **Found a vulnerability in this project itself?** Do not open a public issue. Follow [SECURITY.md](SECURITY.md).

## What lives where

| Path | What it is |
|:---|:---|
| `SKILL.md` | The entry point the agent reads. Keep it short: it routes to `references/` instead of holding checklists. |
| `references/*.md` | Checklists and procedures per stack (frontend, APIs, databases, cloud, AI/LLM, ...). Loaded only when relevant. |
| `scripts/loophole_scanner.py` | Standard-library static scanner. Rules are the `RULES` list near the top. |
| `scripts/setup_tools.py` | Preflight check and installer for optional scanners (gitleaks, semgrep, trivy, ...). |
| `scripts/zap_web_scan.py` | Auto-managed OWASP ZAP daemon for DAST. |
| `tests/` | `unittest` tests. No third-party test dependencies. |
| `examples/` | Prompts, a sample report and an intentionally vulnerable demo app. |

## Development setup

You need Python 3.10+ and git. Nothing else is required: the scanner and the tests use only the standard library.

```bash
git clone https://github.com/<you>/owasp-security-audit-skill.git
cd owasp-security-audit-skill
python -m unittest discover -s tests -v
python scripts/loophole_scanner.py --target . --fail-on high   # the self-scan CI runs
```

## Adding a scanner rule

1. Add a `Rule(...)` to `RULES` in `scripts/loophole_scanner.py`. Give it:
   - a new ID in the right family (`INJ-04`, `CRYPTO-04`, `IAC-01`, ...),
   - a CWE and the OWASP IDs it maps to (Top 10:2025 `A0x`, API Top 10:2023 `APIx`, LLM Top 10:2025 `LLM0x`),
   - an honest `confidence` (`high` only if a match is almost always a real issue),
   - a one-line remediation that tells the reader what to do, not just what is wrong,
   - `extensions` or `path_globs` so it only runs on files where it makes sense.
2. Add a row to `CASES` in `tests/test_loophole_scanner.py` with **one snippet it must flag and one look-alike it
   must not flag**. A rule without both cases fails `test_every_line_rule_has_a_case`.
3. If the rule matches a fake secret, build the string at runtime in the test (see the existing `SEC-*` cases) so
   this repository never contains a real-looking key.
4. Run the tests and the self-scan above. If the rule fires on this repo's own code, either fix the pattern or add an
   inline `# security-skill: ignore` with a reason.
5. If the rule belongs to a checklist, mention its ID in the matching `references/*.md` section.

## Changing SKILL.md or a reference

- Agents pay for every line they load. Prefer a precise check over a long explanation, and put detail in
  `references/` rather than `SKILL.md`.
- Every checklist item should be something an agent can actually verify in code or config.
- Cite the OWASP source (Top 10, ASVS, API Top 10, LLM Top 10, Cheat Sheet) when you add a check.

## Adding support for another agent

Install instructions live in the README under **Install (one command per agent)**. A new target needs the clone
path the agent reads skills from and, if the agent does not load skills by itself, the rule or instruction file
that points it at `SKILL.md`. Please test it in that agent before opening the PR and say which version you used.

## Pull requests

- Keep each PR to one change. Small PRs get reviewed fast.
- CI must pass: syntax check, unit tests, scanner CLI smoke tests, the self-scan gate and the demo-app check.
- Pin any new GitHub Action to a full commit SHA with the version in a comment (OpenSSF Scorecard checks this).
- Do not add runtime dependencies to `scripts/loophole_scanner.py`. Optional tools go through `setup_tools.py`.
- Write commit messages in the imperative ("Add Terraform public S3 bucket rule").

## Safety rules for contributions

- Never commit real secrets, even revoked ones. Use runtime-built fakes in tests.
- Vulnerable sample code belongs in `examples/` or `tests/` with a `security-skill: ignore-file` marker, and
  executable samples are stored with a `.demo` suffix so GitHub code scanning does not alert on them.
- DAST features must stay opt-in and must only target hosts the user confirms they are authorized to test.

## License

By contributing you agree that your contributions are licensed under the [Apache License 2.0](LICENSE).
