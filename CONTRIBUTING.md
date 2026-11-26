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

## From issue to merged pull request

### 1. Claim the issue

- Comment "I'd like to work on this" on the issue. A maintainer assigns it to you, usually within a day.
- Don't start on an issue that is already assigned. If the assignee has been silent for 7 days, ask in the
  issue whether you can take it over.
- No issue for your idea yet? Open one first and describe the change, so we agree on it before you write code.
  Typo and docs fixes can skip this step.
- Questions go in the issue thread, not in private messages, so the next contributor can read the answer.

### 2. Fork and branch

```bash
git clone https://github.com/<you>/owasp-security-audit-skill.git
cd owasp-security-audit-skill
git remote add upstream https://github.com/engrshoaibh/owasp-security-audit-skill.git
git switch -c <type>/<issue-number>-<short-name>    # e.g. rule/10-terraform-public-s3
```

Branch types: `rule/` (scanner rule), `checklist/` (references), `docs/`, `fix/`, `ci/`, `test/`.

Before you open the pull request, bring your branch up to date:

```bash
git fetch upstream
git rebase upstream/main
```

### 3. Commit messages

```text
Add Terraform rule for public S3 ACLs and open security groups      <- subject

Flags aws_s3_bucket_acl with public-read/public-read-write and        <- body: what and why
security group ingress from 0.0.0.0/0 on ports other than 80/443.
Maps to CWE-284, A01:2025.

Fixes #10                                                            <- links and closes the issue
```

- **Subject:** imperative mood ("Add", "Fix", "Document", not "Added" or "Fixes"), 72 characters or fewer,
  no trailing period.
- **Body:** wrap at 72 characters and explain *why*, not line by line *what*. Include the rule ID, CWE and
  OWASP mapping for scanner rules.
- **Footer:** `Fixes #<issue>` in the last commit (or the PR description) so the issue closes when the PR merges.
  Use `Refs #<issue>` for partial work.
- One logical change per commit. Don't worry about small "fix typo" commits: we squash-merge, and the PR
  title and description become the final commit message.
- Never include secrets, tokens, internal hostnames or customer code in a commit, its message or its history.
  If one slips in, tell a maintainer privately (see SECURITY.md); a force-push does not remove it from forks.
- AI-assisted commits are welcome. Review every line yourself and keep any co-author trailer your tool adds.

### 4. Before you push: checklist

- [ ] `python -m unittest discover -s tests -v` passes
- [ ] `python scripts/loophole_scanner.py --target . --fail-on high` passes (the CI self-scan gate)
- [ ] New scanner rules have a must-flag **and** a must-not-flag case in `tests/test_loophole_scanner.py`
- [ ] Docs updated: README for new agents or features, `references/*.md` for new checks, `CHANGELOG.md`
      under `## [Unreleased]` for anything a user would notice
- [ ] No new runtime dependencies in `scripts/loophole_scanner.py`
- [ ] New GitHub Actions are pinned to a full commit SHA, with the version in a comment (OpenSSF Scorecard checks this)

CI runs the same checks plus scanner CLI smoke tests and the demo-app check, and must be green before merge.

### 5. Open the pull request

- Title = your commit subject. Description: what changed, why, how you tested it, and `Fixes #<issue>`.
- For a new rule, paste one real (sanitised) example it catches, and say how noisy it was on a project you tried.
- Open it as a **draft** if you want early feedback; mark it ready when the checklist above is done.
- One issue per pull request. Unrelated fixes go in a separate PR.

### 6. Review

- A maintainer replies within 48 hours. Every PR needs one approving review and green CI before it merges.
- Answer review comments with new commits (not a force-push) while the review is open, so reviewers can see
  what changed. Resolve a thread only after the reviewer agrees.
- If CI fails, open the failed job's log, fix it on your branch and push again. Ask in the PR if you are stuck.
- We squash-merge, so your PR becomes one commit on `main` and you're credited as its author.
- After merge, your name goes in the next release notes. Thank you!

### Ground rules

- Be kind and assume good intent. Critique code, not people.
- Don't open issues, comments or PRs just to raise activity numbers. Low-effort or generated spam PRs are closed
  without review.

## Safety rules for contributions

- Never commit real secrets, even revoked ones. Use runtime-built fakes in tests.
- Vulnerable sample code belongs in `examples/` or `tests/` with a `security-skill: ignore-file` marker, and
  executable samples are stored with a `.demo` suffix so GitHub code scanning does not alert on them.
- DAST features must stay opt-in and must only target hosts the user confirms they are authorized to test.

## License

By contributing you agree that your contributions are licensed under the [Apache License 2.0](LICENSE).
