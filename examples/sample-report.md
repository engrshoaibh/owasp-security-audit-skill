# Security Audit: vulnerable-flask-app

> Sample output of a **full audit** with this skill, run against the intentionally vulnerable demo in
> [`vulnerable-flask-app/`](./vulnerable-flask-app/) (copied out, with `app.py.demo` renamed to `app.py`). The raw scanner output is in [`sample-scan.json`](./sample-scan.json).

**Verdict:** Not approved
**Scope:** Python 3 / Flask / SQLite, Docker · `examples/vulnerable-flask-app` · static review
**Coverage:** static ✓ · secrets ✓ · SCA partial (`flask` is unpinned and there is no lockfile, so CVE matching is unreliable) · DAST skipped (no running instance) · manual access-control review ✓

| Critical | High | Medium | Low | Needs review |
|:---:|:---:|:---:|:---:|:---:|
| 3 | 3 | 2 | 1 | 0 |

## Findings

### [CRITICAL] F-1: SQL injection in login
- **Where:** `app.py:37`
- **Category:** A05:2025 Injection · CWE-89 · Confidence: high · Scanner: `INJ-01`
- **Evidence:** `email` comes straight from the `POST /login` form (`app.py:34`) and is interpolated into the query
  with an f-string. No authentication is needed to reach it.
- **Impact:** `email = "' OR 1=1 --"` logs in as the first user (usually the admin) without a password, and UNION
  payloads can read any table.
- **Fix:**
  ```python
  row = db().execute(
      "SELECT id, password_hash FROM users WHERE email = ?", (email,)
  ).fetchone()
  ```
- **Reference:** OWASP SQL Injection Prevention Cheat Sheet

### [CRITICAL] F-3: Server-side template injection in `/greet`
- **Where:** `app.py:57`
- **Category:** A05:2025 Injection · CWE-1336 · Confidence: high · Scanner: `SSTI-01`
- **Evidence:** the `name` query parameter is concatenated into the template source passed to
  `render_template_string`. Unauthenticated.
- **Impact:** `/greet?name={{config}}` dumps the app config including `SECRET_KEY`; Jinja2 sandbox escapes lead to
  remote code execution.
- **Fix:** pass user data as a variable, never as template source:
  ```python
  return render_template_string("<h1>Hello {{ name }}</h1>", name=name)
  ```

### [CRITICAL] F-8: Debug mode on a public interface
- **Where:** `app.py:69`
- **Category:** A02:2025 Security Misconfiguration · CWE-489 · Confidence: high · Scanner: `DBG-01` (raised from Medium)
- **Evidence:** `app.run(host="0.0.0.0", debug=True)` binds to every interface with the Werkzeug debugger enabled.
- **Impact:** any error page exposes the interactive debugger console, which runs arbitrary Python (remote code
  execution) once the PIN is guessed or leaked. Raised to Critical because it is reachable from the network.
- **Fix:** `app.run(debug=os.environ.get("FLASK_DEBUG") == "1")` and run behind gunicorn in production.

### [HIGH] F-2: IDOR on invoices (any user can read any invoice)
- **Where:** `app.py:47-51`
- **Category:** A01:2025 Broken Access Control · API1:2023 BOLA · CWE-639 · Confidence: high · Found by manual review
- **Evidence:** `GET /invoices/<invoice_id>` checks that the caller is logged in (`current_user_id()`), but the
  query `SELECT * FROM invoices WHERE id = ?` never filters by owner. Ids are sequential integers.
- **Impact:** any logged-in user can read every customer's invoices by counting up from 1.
- **Fix:**
  ```python
  uid = current_user_id()
  row = db().execute(
      "SELECT * FROM invoices WHERE id = ? AND user_id = ?", (invoice_id, uid)
  ).fetchone()
  ```
  Add a test that logs in as user B, requests user A's invoice, and expects 404.

### [HIGH] F-4: Hardcoded fallback session secret
- **Where:** `app.py:14`
- **Category:** A02:2025 · A07:2025 · CWE-1188 · Confidence: high · Scanner: `SEC-05`
- **Evidence:** `SECRET_KEY = os.environ.get("SECRET_KEY") or "dev-secret"`. If the variable is missing in a
  deployment, the app silently signs sessions with a public value.
- **Impact:** anyone can forge a Flask session cookie with `user_id` set to any account (full account takeover).
- **Fix:** fail closed: `app.secret_key = os.environ["SECRET_KEY"]` (crash on startup if unset).

### [HIGH] F-5: Passwords hashed with unsalted MD5
- **Where:** `app.py:35`
- **Category:** A04:2025 Cryptographic Failures · CWE-916 · Confidence: high · Scanner: `CRYPTO-01`
- **Impact:** a database leak (for example via F-1) exposes passwords that crack in seconds.
- **Fix:** `from werkzeug.security import generate_password_hash, check_password_hash` (scrypt/pbkdf2) or argon2-cffi,
  and re-hash on next login.

### [MEDIUM] F-6: Open redirect after login
- **Where:** `app.py:42`
- **Category:** A01:2025 · CWE-601 · Confidence: high · Scanner: `REDIR-01`
- **Impact:** phishing links such as `/login?next=https://evil.example` look like they come from your domain.
- **Fix:** allow only relative paths: `nxt = request.args.get("next", "/")`, then
  `return redirect(nxt if nxt.startswith("/") and not nxt.startswith("//") else "/")`.

### [MEDIUM] F-7: Predictable password-reset token
- **Where:** `app.py:62`
- **Category:** A04:2025 · A07:2025 · CWE-338 · Confidence: high · Scanner: `CRYPTO-02`
- **Impact:** 6-digit tokens from `random` can be brute-forced (900,000 values, and there's no rate limit) or predicted.
- **Fix:** `reset_token = secrets.token_urlsafe(32)`, store only its hash, expire it after 15 minutes, and rate-limit
  the endpoint.

### [LOW] F-9: Container image unpinned and running as root
- **Where:** `Dockerfile:2`
- **Category:** A02:2025 · A03:2025 · CWE-250 / CWE-1357 · Scanner: `DOCKER-01`, `DOCKER-02`
- **Fix:** `FROM python:3.12-slim@sha256:<digest>`, then `RUN useradd -r app` and `USER app` before `CMD`. Also pin
  `flask==<version>` in `requirements.txt`.

## Attack chains
1. **F-3 → F-4 → account takeover:** `/greet?name={{config.SECRET_KEY}}` leaks the signing key, then a forged session
   cookie logs in as any user, no password needed.
2. **F-1 → F-5:** SQL injection dumps `users`, and the MD5 hashes crack offline in seconds, so the leaked passwords
   also work on other sites where users reused them.

## Access-control inventory (from `references/access-control-review.md`)

| Route | Auth | Object id | Owner check | Verdict |
|:---|:---|:---|:---|:---|
| `POST /login` | no | n/a | n/a | OK (but see F-1, F-6) |
| `GET /invoices/<id>` | yes | `invoice_id` | ❌ | **F-2 IDOR** |
| `GET /greet` | no | n/a | n/a | OK (but see F-3) |
| `POST /password-reset` | no | `email` | n/a | Needs rate limiting (F-7) |

## Not covered
- DAST: no running instance was provided.
- No CSRF protection on `POST` forms (Flask-WTF is not installed). Worth adding, but not rated here because the demo
  has no HTML forms.
