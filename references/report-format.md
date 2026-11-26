# Report Format

Use this structure for the final findings register so humans can read it and tools can parse it.

## 1. Machine-readable finding schema

`scripts/loophole_scanner.py --format json` emits this shape (schema_version `1.0`). Use the same fields when you
add findings from manual review or other tools, so every finding in the register has one shape.

```json
{
  "schema_version": "1.0",
  "tool": {"name": "owasp-security-audit-skill/loophole_scanner", "version": "2.0.0"},
  "target": "/path/to/project",
  "summary": {"total": 3, "critical": 1, "high": 1, "medium": 1, "low": 0,
              "suppressed_inline": 0, "suppressed_baseline": 0},
  "findings": [
    {
      "rule_id": "INJ-01",
      "title": "SQL built with string interpolation / raw unsafe query",
      "severity": "High",
      "confidence": "medium",
      "cwe": "CWE-89",
      "owasp": ["A05:2025"],
      "module": "1.2.2 / 6A.1 SQLi",
      "file": "src/users/repo.py",
      "line": 42,
      "snippet": "cur.execute(f\"SELECT * FROM users WHERE id={uid}\")",
      "remediation": "Use parameterized queries ...",
      "context": "code",
      "fingerprint": "3f9c0d1e2a4b5c6d7e8f9a0b"
    }
  ]
}
```

| Field | Notes |
|:---|:---|
| `rule_id` | Scanner rule id, or `MANUAL-<n>` for findings from code review, or `<tool>:<id>` (e.g. `semgrep:python.lang.security...`, `osv:GHSA-xxxx`) |
| `severity` | `Critical` / `High` / `Medium` / `Low`, per [severity-rubric.md](./severity-rubric.md) |
| `confidence` | `high` / `medium` / `low` |
| `owasp` | Any of Top 10:2025 (`A01:2025`...), API Top 10:2023 (`API1:2023`...), LLM Top 10:2025 (`LLM01:2025`...). See [owasp-mapping.md](./owasp-mapping.md) |
| `context` | `code` or `non-production` (tests, examples, docs) |
| `snippet` | Secrets are masked. Never put a full secret here |
| `fingerprint` | Stable id (independent of line number), used by `--baseline` |

Other outputs:
- `--format sarif --output results.sarif`: SARIF 2.1.0 for GitHub code scanning (`github/codeql-action/upload-sarif`).
- `--fail-on high`: exit code 1 if anything at or above High remains (for CI gates).
- `--write-baseline .security-skill-baseline.json`: accept current findings; later scans show only new ones.
- Inline suppression after review: `# security-skill: ignore[RULE-ID]` on the line or the line above.
- Whole-file skip for intentionally vulnerable fixtures: `# security-skill: ignore-file` in the first 5 lines.

## 2. Human report template

```markdown
# Security Audit: <project>

**Verdict:** Not approved | Approved with accepted risks | Approved
**Scope:** <stack>, <commit / branch>, <date>
**Coverage:** static ✓ · secrets ✓ · SCA ✓ · DAST skipped (no staging URL) · manual review of auth and data access ✓

| Critical | High | Medium | Low | Needs review |
|:---:|:---:|:---:|:---:|:---:|
| 1 | 2 | 3 | 1 | 4 |

## Findings

### [CRITICAL] F-1: SQL injection in user lookup
- **Where:** `src/users/repo.py:42`
- **Category:** A05:2025 Injection · CWE-89 · Confidence: high
- **Evidence:** `id` comes from `GET /users/:id` (`routes.py:17`) and is interpolated into the query.
- **Impact:** Unauthenticated read of the whole `users` table, including password hashes.
- **Fix:**
  ```python
  cur.execute("SELECT * FROM users WHERE id = %s", (uid,))
  ```
- **Reference:** OWASP SQL Injection Prevention Cheat Sheet

(... one block per finding, Critical → Low ...)

## Attack chains
1. F-3 permissive CORS + F-5 missing CSRF token → cross-site account takeover.

## Needs review (low confidence)
- `LOOP-03` `worker.py:88`: `while True` with no visible exit; confirm the task is cancelled on shutdown.

## Not covered
- DAST not run (no running instance). Mobile binaries not analysed.
```

Rules for the register:
- One finding per root cause; list extra locations under it instead of repeating the finding.
- Every Critical/High has evidence (the input path), not only the matched line.
- Fixes are concrete code or config for this project, not generic advice.
- Mask secrets (first 4 and last 2 characters at most) and say whether the secret must be rotated.
