# Security Toolbox: Loophole, Loop & Attack-Detection Tools (Module 19)

> Use this reference when the developer wants automated tools to **find loopholes, detect infinite/resource-exhaustion loops, and simulate attacks via loopholes**.
> **Agent Execution Rule**: The agent runs applicable commands directly — do **not** ask the user to manually open terminals, start ZAP daemons, or execute these commands unless elevation/credentials require it.
> **Safety Rule**: Passive/static scanners (Section 19.1–19.3, 19.5–19.6) are safe on source code and local files. **Active DAST & exploit-probing tools** (Section 19.4, 19.7) send attack payloads — run them **ONLY** against local/staging environments with explicit authorization, never production without permission.

---

## 19.0 Prerequisite Auto-Setup & Built-in Repo Scanner (Zero Dependencies)

First check prerequisites and automatically download/set up any missing stack tools before running scans:

```bash
# Check prerequisites across all profiles (runtime, core, web, python, sast, iac)
python scripts/setup_tools.py --check --verify --profile all

# Automatically download & set up missing tools for confirmed stack profiles
python scripts/setup_tools.py --install --profile core,web,python --verbose
```

Then run the bundled cross-platform scanner script to detect installed CLI tools AND scan code for hardcoded secrets, injection sinks, auth/TLS bypasses, BaaS policy loopholes, and loop hazards (ReDoS, unbounded agent/while loops):

```bash
# Scan current project and print Markdown report
python scripts/loophole_scanner.py --target .

# JSON output + automatically run any installed safe local scanners (gitleaks, semgrep, osv-scanner, etc.)
python scripts/loophole_scanner.py --target . --format json --run-tools
```

---

## 19.1 Secret & Credential Leak Detection [ALWAYS RUN FIRST]

### Gitleaks (Fast Regex + Entropy, Offline)
```bash
gitleaks dir --source . --verbose --report-format json --report-path gitleaks-dir.json
gitleaks git --source . --verbose --report-format json --report-path gitleaks-git.json
gitleaks protect --staged --verbose --redact   # Pre-commit hook
```

### TruffleHog (Live Verification of Exploitable Keys)
```bash
trufflehog filesystem . --only-verified --json > trufflehog-verified.json
trufflehog git file://. --only-verified --json > trufflehog-git-verified.json
```
*Loopholes found*: Hardcoded API keys, DB URIs with passwords, `.env` secrets in git history, private keys, JWT signing secrets, cloud credentials still active against live APIs.

---

## 19.2 SAST & Dataflow Taint Analysis (Source-to-Sink Loopholes)

### Semgrep (Multi-Language OWASP Rules)
```bash
semgrep scan --config auto .
semgrep scan --config p/owasp-top-ten --config p/security-audit --config p/secrets .
semgrep scan --config p/owasp-top-ten --sarif -o semgrep.sarif .
```

### Dataflow Taint & Deep SAST
```bash
# Bearer CLI (dataflow + sensitive data exposure + OWASP rules for JS/TS/Python/Go/Ruby/Java/PHP)
bearer scan . --format json --output bearer-report.json

# CodeQL (deep inter-procedural source-to-sink taint tracking)
codeql database create codeql-db --language=javascript   # or python, java, go, csharp
codeql database analyze codeql-db codeql/javascript-queries:codeql-suites/javascript-security-extended.qls --format=sarif-latest --output=codeql.sarif
```

### Language-Specific Scanners
- **Node.js**: `npm audit --json > npm-audit.json`
- **Python**: `bandit -r . -f json -o bandit.json` and `pip-audit -f json -o pip-audit.json`
- **PHP / Laravel**: `./vendor/bin/psalm --taint-analysis` and `composer audit`
- **Ruby / Rails**: `brakeman -f json -o brakeman.json` and `bundle-audit check --update`
- **Go**: `govulncheck ./...` and `gosec -fmt json -out gosec.json ./...`
- **.NET**: `dotnet list package --vulnerable --include-transitive`
- **Flutter / Dart**: `flutter analyze` and `mobsfscan . --json -o mobsfscan.json`

---

## 19.3 Dependency & Supply Chain (SCA)

```bash
osv-scanner -r . --format json > osv-report.json
trivy fs . --scanners vuln,secret --severity HIGH,CRITICAL
snyk test --json > snyk-report.json
```

---

## 19.4 Loop & Resource-Exhaustion Detection ("Find Out the Loop")

Tools and probes to catch infinite loops, catastrophic backtracking, recursive DoS, runaway AI agents, and concurrent replay loops:

### 19.4.1 ReDoS (Catastrophic Regex Backtracking Loops)
```bash
# recheck CLI — mathematically checks regexes for exponential backtracking loops
npx recheck-cli "src/**/*.js" "src/**/*.ts"

# redos-detector CLI
npx redos-detector check "([a-zA-Z]+)*$"
```
*Loophole*: Regexes with nested quantifiers like `(a+)+` freeze Node.js single-threaded event loops or exhaust worker threads on a crafted 30-byte input.

### 19.4.2 GraphQL Recursive / Alias / Circular Query Loops
```bash
# graphql-cop — audits GraphQL for circular fragments, alias/batching DoS, introspection, CSRF
python3 graphql-cop.py -t https://staging.example.com/graphql
```
*Loophole*: Circular fragments (`fragment A on User { friends { ...B } }`) or 500x query aliasing/batching crashes backend resolvers or brute-forces OTPs in one request.

### 19.4.3 Race Condition / Concurrent Replay Loops (TOCTOU)
```bash
# Test coupon double-redemption, negative balance, or OTP brute-force via concurrent bursts
seq 1 20 | xargs -P 20 -I{} curl -s -o /dev/null -w "%{http_code}\n" \
  -X POST "https://staging.example.com/api/coupons/redeem" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{"code":"PROMO50"}'
```
*Better*: Use **Burp Suite Repeater (Single-Packet Attack)** over HTTP/2 to fire 20+ requests arriving in the exact same millisecond window.

### 19.4.4 Redirect & Webhook Retry Loops
```bash
# Verify max redirects & prevent open-redirect / SSRF hop bypasses
curl -iL --max-redirs 5 "https://staging.example.com/redirect?url=https://evil.com"
```
Check code for S3/Queue -> Lambda/Webhook event triggers writing back to the same trigger source (infinite billing/execution loop) and AI agents missing `max_iterations` / `recursion_limit`.

### 19.4.5 AI Agent & LLM Red-Teaming (Prompt Injection & Runaway Loops)
```bash
# promptfoo redteam — automated OWASP LLM Top 10 / RAG / Agent attack simulation
npx promptfoo@latest redteam init
npx promptfoo@latest redteam run

# garak — LLM vulnerability scanner (prompt injection, encoding bypasses, leaks)
garak --model_type openai --model_name gpt-4o-mini --probes promptinject,encoding,leakreplay

# Microsoft PyRIT — multi-turn autonomous red-teaming orchestration (Python)
```

---

## 19.5 Active Loophole Probers & Attack Simulators (DAST — Staging Only!)

### OWASP ZAP (Web & OpenAPI/GraphQL Scanner — Agent Auto-Managed Daemon & Docker)

#### Bundled Python Automation (`scripts/zap_web_scan.py`)
Works with Python stdlib (`--engine auto`) to connect to an existing ZAP daemon **or automatically launch, scan with, and shut down an isolated ephemeral local ZAP daemon** (or use Docker as fallback). Zero manual ZAP startup required by the user:
```bash
# 1. Check local ZAP / Docker readiness (optional preflight)
python scripts/zap_web_scan.py --check

# 2. Safe passive baseline scan (auto-starts isolated ZAP daemon, spiders, passive-scans, shuts down)
python scripts/zap_web_scan.py --target http://127.0.0.1:3000 --mode baseline

# 3. OpenAPI / GraphQL / SOAP schema scan (works natively on local ZAP daemon or Docker)
python scripts/zap_web_scan.py --target http://127.0.0.1:8000/openapi.json --mode api --api-format openapi
python scripts/zap_web_scan.py --target http://127.0.0.1:4000/graphql --mode api --api-format graphql

# 4. Full active attack scan (SQLi, XSS, SSRF, CmdInj — authorized dev/staging ONLY)
python scripts/zap_web_scan.py --target http://127.0.0.1:3000 --mode full --confirm-authorized --fail-on high
```

#### Official Python `zaproxy` Client (`zapv2`) Setup
If writing custom Python test suites or pytest security gates (download ZAP from https://www.zaproxy.org/):
```bash
pip install -r scripts/requirements-zap.txt   # installs `zaproxy` (replaces legacy `python-owasp-zap-v2.4`)

# Start ZAP headless daemon (Windows / Linux / macOS)
zap.bat -daemon -host 127.0.0.1 -port 8080 -config api.key=your_api_key
# or: zap.sh -daemon -host 127.0.0.1 -port 8080 -config api.key=your_api_key
```
```python
from zapv2 import ZAPv2
zap = ZAPv2(apikey="your_api_key", proxies={"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"})
```

#### Direct ZAP Docker CLI (`ghcr.io/zaproxy/zaproxy:stable`)
```bash
# Safe passive baseline
docker run --rm -v "${PWD}:/zap/wrk:rw" -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t "https://staging.example.com" -r zap-baseline.html

# OpenAPI / Swagger active attack scan
docker run --rm -v "${PWD}:/zap/wrk:rw" -t ghcr.io/zaproxy/zaproxy:stable zap-api-scan.py -t "https://staging.example.com/openapi.json" -f openapi -r zap-api.html

# Full active attack scan (SQLi, XSS, SSRF, CmdInj, Path Traversal)
docker run --rm -v "${PWD}:/zap/wrk:rw" -t ghcr.io/zaproxy/zaproxy:stable zap-full-scan.py -t "https://staging.example.com" -r zap-full.html
```

### Nuclei (Template-Based CVE, Exposure & OWASP Attack Detection)
```bash
nuclei -update-templates
nuclei -u https://staging.example.com -tags owasp,sqli,xss,ssrf,exposure,misconfig,default-login -severity critical,high -rl 100 -json -o nuclei.json
```

### Schemathesis (API Schema Loophole & Fuzz Testing)
Automatically generates edge-case, type-confusion, injection, and auth-bypass payloads directly from your OpenAPI or GraphQL schema:
```bash
schemathesis run https://staging.example.com/openapi.json --checks all --header "Authorization: Bearer $TOKEN"
```

### Targeted Attack-Vector Verification Tools
```bash
# 1. ffuf — Discover hidden endpoints, backup files, and bypassed routes
ffuf -u https://staging.example.com/FUZZ -w common-endpoints.txt -mc 200,204,301,302,401,403

# 2. arjun — Discover hidden query/JSON parameters (mass assignment & debug flags like ?admin=true)
arjun -u https://staging.example.com/api/profile -m JSON

# 3. jwt_tool — Probe JWT loopholes (alg:none, RS256->HS256 confusion, kid injection, weak secrets)
python3 jwt_tool.py "$JWT" -M at -t https://staging.example.com/api/me -rh "Authorization: Bearer"
python3 jwt_tool.py "$JWT" -C -d rockyou.txt

# 4. sqlmap — Verify SQL injection exploitability
sqlmap -r captured_request.txt --batch --level=3 --risk=2

# 5. dalfox — XSS & WAF bypass probing
dalfox url "https://staging.example.com/search?q=test" --cookie "session=$COOKIE"

# 6. corsy — Test CORS misconfigurations (wildcard/null/reflected origin with credentials)
python3 corsy.py -u https://staging.example.com/api/user

# 7. interactsh-client — Out-of-band listener for blind SSRF, XXE, and RCE callbacks
interactsh-client
```

---

## 19.6 Container, Kubernetes, IaC, Mobile, TLS & BaaS Scanners

### Containers & Kubernetes & IaC
```bash
trivy image --scanners vuln,secret,misconfig --severity HIGH,CRITICAL myapp:latest
grype myapp:latest --only-fixed --fail-on high
checkov -d . --framework terraform,kubernetes,dockerfile --output json > checkov.json
```

### Mobile (Android / iOS / Flutter)
```bash
# MobSF container + mobsfscan source SAST
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
mobsfscan /path/to/mobile/source --json -o mobsfscan.json

# Decompile APK and inspect manifest + strings
jadx -d jadx_out/ app-release.apk
apktool d app-release.apk -o apk_out/
```

### SSL/TLS & Security Headers
```bash
./testssl.sh --jsonfile tls.json https://staging.example.com
curl -s -D- https://staging.example.com -o /dev/null | grep -iE "strict-transport|content-security|x-frame|x-content-type|referrer-policy|permissions-policy"
```

### Firebase & Supabase Policy Verification
```bash
# Firebase Emulator Rules Tests
firebase emulators:exec --only firestore "npm test"

# Supabase RLS Check (verify tables without RLS and test anon/cross-user access)
psql "$SUPABASE_DB_URL" -c "SELECT tablename, rowsecurity FROM pg_tables WHERE schemaname = 'public';"
psql "$SUPABASE_DB_URL" -c "BEGIN; SET LOCAL ROLE anon; SELECT * FROM sensitive_table LIMIT 5; ROLLBACK;"
```

---

## 19.7 Attack-Chain Playbooks (Chaining Loopholes into Exploits)

During Phase 2 review, never evaluate findings in isolation — trace **how an attacker chains loopholes**:

| Chain Name | Step 1 (Entry Loophole) | Step 2 (Pivot / Bypass) | Step 3 (High/Critical Impact) |
|:---|:---|:---|:---|
| **Swagger -> Mass Assignment -> Admin** | Exposed `/swagger.json` or `.map` source maps | `arjun` / schema shows `isAdmin` or `role` field | `PATCH /api/users/me` sets `role: "admin"` -> full takeover |
| **Open Redirect + OAuth Token Theft** | Unvalidated `?redirect_uri=` or `?next=` | Victim clicks crafted OAuth authorize link | Auth code / token sent to attacker server |
| **SSRF -> Redirect Hop -> Cloud Takeover** | Avatar/webhook fetcher allows `https://` | Attacker URL returns `302 -> http://169.254.169.254/` | Steals cloud IAM credentials -> S3/DB dump |
| **RAG Poisoning -> Indirect Prompt Injection -> MCP RCE** | Unvalidated PDF/PR ingested into vector DB | Hidden instruction triggers agent tool call | Agent runs unconstrained SQL/shell/email exfiltration |
| **JWT `alg:none` / Public-Key Confusion -> BOLA** | App serves `/jwks.json` & accepts HS256 | `jwt_tool` signs forged token with `sub: admin` | Reads/deletes any tenant's data |
| **Race Condition Loop -> Financial Drain** | Non-atomic `if balance >= x` check | 20 concurrent HTTP/2 requests hit endpoint | Multiple withdrawals/coupons succeed on single balance |
| **CORS Origin Reflection + XSS** | API reflects arbitrary `Origin` + `Allow-Credentials: true` | Any third-party site makes authenticated `fetch()` | Cross-origin theft of user PII / tokens |

---

## 19.8 Result-to-Module Mapping

| Tool Finding | Audit Module |
|:---|:---|
| `gitleaks` / `trufflehog` secret hit | Module 1.5 (Secrets Management) |
| `semgrep` / `bearer` / `sqlmap` SQLi or CmdInj | Module 1.2 (Input Validation) & Module 6 (Database) |
| `recheck` / `redos-detector` catastrophic regex | Module 1.2.7 (ReDoS Loop Prevention) |
| `dalfox` / `semgrep` XSS | Module 4.1 (Frontend XSS) |
| `jwt_tool` weak alg / secret | Module 2.3 (JWT Security) |
| `corsy` / `curl` missing headers | Module 4.3–4.4 (CORS & Security Headers) |
| `schemathesis` 500 crash / schema bypass | Module 7A (REST API) & Module 3 (Access Control) |
| `graphql-cop` depth/batching/introspection | Module 7B (GraphQL Security) |
| `garak` / `promptfoo` jailbreak / leak | Module 10 (AI/LLM/RAG Security) |
| `trivy` / `grype` / `checkov` misconfig | Module 12 (Docker/K8s/IaC) |
| `mobsf` / `jadx` hardcoded secret / exported component | Module 11 (Mobile Security) |
| `psql` `rowsecurity = false` / permissive rules | Module 8 (Firebase) / Module 9 (Supabase) |
