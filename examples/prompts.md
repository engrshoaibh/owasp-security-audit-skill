# Example Prompts

Copy any of these into Claude Code, Codex, Cursor, Gemini CLI or another agent with the skill installed.
You don't need to name the skill: these phrases trigger it. In Claude Code you can also call it directly with
`/owasp-security-audit` (or `/owasp-security-audit:owasp-security-audit` when installed as a plugin).

## Quick checks (static only, about 2 minutes, no installs)

| Prompt | What happens |
|:---|:---|
| `Quick security check of this repo` | Built-in scanner with `--quick`, hits verified by reading the code, short verdict |
| `Is this PR safe to merge from a security point of view?` | Scans only files changed vs the base branch (`--changed origin/main`) |
| `Security check my uncommitted changes before I push` | `--changed` (uncommitted and untracked files) |
| `Quick scan src/auth and src/api for vulnerabilities` | `--paths src/auth src/api` |
| `Did I leak any API keys or secrets in this repo?` | Secret rules plus gitleaks if installed; values are masked in the reply |

## Full audits

| Prompt | What happens |
|:---|:---|
| `Audit this project for security issues` | All 6 steps with a progress tracker; asks up to 3 scoping questions first |
| `Full OWASP audit, static only, don't install anything` | Skips installs and DAST, still does SCA with tools already present |
| `Audit this repo and write the findings to SECURITY-AUDIT.md` | Same, plus the report saved in the format of `references/report-format.md` |
| `Security review focused on payments and multi-tenancy` | Prioritises business-logic, race-condition and access-control modules |

## Focused reviews

| Prompt | Module used |
|:---|:---|
| `Check every API route for IDOR / broken object level authorization` | `access-control-review.md` (endpoint inventory + owner checks) |
| `Review our LangChain agent for prompt injection and excessive agency` | `ai-llm-rag.md` (LLM01, LLM06, LLM10) |
| `Are our Supabase RLS policies safe?` | `baas-mobile.md` Module 9 |
| `Harden our Dockerfile and GitHub Actions workflows` | `infra-cloud-cicd.md` + `DOCKER-*` / `GHA-*` rules |
| `Check our dependencies for known CVEs` | Step 4 (osv-scanner / npm audit / pip-audit …) |

## Dynamic testing (only on systems you own)

| Prompt | What happens |
|:---|:---|
| `Run a passive ZAP baseline against http://localhost:3000` | `zap_web_scan.py --mode baseline` |
| `Scan our staging API from http://localhost:8000/openapi.json. I authorize active testing` | `--mode api --confirm-authorized` |

## CI and tooling

| Prompt | What happens |
|:---|:---|
| `Add a GitHub Actions job that uploads this skill's scanner results to code scanning` | SARIF workflow using `--format sarif` |
| `Fail CI on new High findings but accept the current ones` | `--write-baseline` once, then `--fail-on high` |
| `I reviewed finding INJ-02 in build.py, it's a false positive. Suppress it` | Adds `# security-skill: ignore[INJ-02]` with a reason |

## Try it on the demo app

```bash
cp -r examples/vulnerable-flask-app /tmp/vuln-demo && mv /tmp/vuln-demo/app.py.demo /tmp/vuln-demo/app.py
python scripts/loophole_scanner.py --target /tmp/vuln-demo
```
Then open `/tmp/vuln-demo` in your agent, ask `Audit this project`, and compare with [sample-report.md](./sample-report.md).
The manual-review finding (F-2, IDOR) is the one the scanner can't find on its own.
