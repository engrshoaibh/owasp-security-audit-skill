# Security Audit: OWASP Juice Shop

> Sample output of a **scoped audit** with this skill, run against
> [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) `v20.4.0` source
> (`routes/` and `lib/` only). Juice Shop is a deliberately vulnerable training app.
> Only test your own local instance. Do not commit the Juice Shop tree into this repository.

**Verdict:** Not approved
**Scope:** Node.js / Express / Sequelize / MongoDB · tag `v20.4.0` · `routes/` + `lib/` · static review · 2026-11-26
**Coverage:** static ✓ · secrets ✓ (no hardcoded cloud keys in scope) · SCA skipped · DAST skipped in this write-up (login SQLi confirmed separately on a local container when available) · manual review of flagged lines ✓

| Critical | High | Medium | Low | Needs review |
|:---:|:---:|:---:|:---:|:---:|
| 2 | 6 | 0 | 0 | 5 |

## Findings

### [CRITICAL] F-1: SQL injection in login
- **Where:** `routes/login.ts:34`
- **Category:** A05:2025 Injection · CWE-89 · Confidence: high · Scanner: `INJ-01`
- **Juice Shop challenges:** Login Admin, Login Bender, Login Jim
- **Evidence:** `req.body.email` and the hashed password are interpolated into a raw Sequelize query string.
  No authentication is needed to reach `POST /rest/user/login`.
- **Impact:** `email = "' OR 1=1--" ` authenticates as the first matching user (typically admin) with no valid
  password. UNION payloads can read other tables.
- **Fix:**
  ```ts
  models.sequelize.query(
    'SELECT * FROM Users WHERE email = $1 AND password = $2 AND deletedAt IS NULL',
    {
      bind: [req.body.email || '', security.hash(req.body.password || '')],
      model: UserModel,
      plain: true
    }
  )
  ```
- **Reference:** OWASP SQL Injection Prevention Cheat Sheet

### [CRITICAL] F-2: SQL injection in product search
- **Where:** `routes/search.ts:23`
- **Category:** A05:2025 Injection · CWE-89 · Confidence: high · Scanner: `INJ-01`
- **Juice Shop challenges:** Christmas Special / UNION SQL Injection, Database Schema
- **Evidence:** `req.query.q` is truncated to 200 characters, then dropped into a `LIKE` clause with template-literal
  interpolation. Unauthenticated.
- **Impact:** UNION SELECT can dump other tables (for example users and passwords). Schema discovery queries also work.
- **Fix:**
  ```ts
  models.sequelize.query(
    `SELECT * FROM Products
     WHERE ((name LIKE $1 OR description LIKE $1) AND deletedAt IS NULL)
     ORDER BY name`,
    { bind: [`%${criteria}%`] }
  )
  ```

### [HIGH] F-3: NoSQL injection via `$where` on product reviews
- **Where:** `routes/showProductReviews.ts:36` (same pattern at `routes/chat.ts:150`)
- **Category:** A05:2025 Injection · API3:2023 · CWE-943 · Confidence: high · Scanner: `NOSQL-01`
- **Juice Shop challenge:** NoSQL Injection (and related chat-bot review lookup)
- **Evidence:** the product id is concatenated into a MongoDB `$where` string that runs as server-side JavaScript.
  When the NoSQL challenge is enabled, the id is only truncated, not typed as a number.
- **Impact:** attackers can inject JS into `$where` (data exfiltration or a long-running expression that DoS the
  review query).
- **Fix:**
  ```ts
  db.reviewsCollection.find({ product: Number(id) })
  ```
  Never build `$where` from request input.

### [HIGH] F-4: NoSQL injection via `$where` on order tracking
- **Where:** `routes/trackOrder.ts:18`
- **Category:** A05:2025 Injection · API3:2023 · CWE-943 · Confidence: high · Scanner: `NOSQL-01`
- **Juice Shop challenge:** NoSQL Injection (Orders)
- **Evidence:** `req.params.id` is embedded in `` this.orderId === '${id}' `` inside `$where`.
- **Impact:** a crafted order id returns more than one order, or injects JS into the MongoDB query engine.
- **Fix:**
  ```ts
  db.ordersCollection.find({ orderId: String(id) })
  ```

### [HIGH] F-5: Path / local file include from request body
- **Where:** `routes/dataErasure.ts:104`
- **Category:** A01:2025 Broken Access Control · API1:2023 · CWE-22 · Confidence: high · Scanner: `PATH-01`
- **Juice Shop challenge:** Local File Read (LFR)
- **Evidence:** when the LFR challenge is enabled, `req.body.layout` is passed to `path.resolve` and used as a view
  path. A short denylist blocks `ftp`, `ctf.key`, and `encryptionkeys`, but other paths remain readable.
- **Impact:** authenticated (or reachable) callers can pull unexpected templates or other files into the response.
- **Fix:** allowlist layout names (for example `['default', 'dark']`) and map them to fixed paths under a views
  directory. Reject anything that is not on the list.

### [HIGH] F-6: Unsafe YAML deserialization of uploaded files
- **Where:** `routes/fileUpload.ts:114`
- **Category:** A08:2025 Software and Data Integrity Failures · CWE-502 · Confidence: high · Scanner: `DESER-01`
- **Juice Shop challenges:** Deprecated Interface, YAML Bomb
- **Evidence:** the upload buffer is passed to `yaml.load(data)` inside a VM with a timeout. `yaml.load` is not a
  safe loader.
- **Impact:** crafted YAML can expand into a resource bomb (availability) or, depending on the YAML library and
  tags, execute unexpected constructors.
- **Fix:** use `yaml.load(data, { schema: yaml.FAILSAFE_SCHEMA })` or `yaml.safeLoad` equivalent, or reject YAML
  uploads entirely and accept only JSON with a size limit.

### [HIGH] F-7: Server-side `eval` of profile username (SSTI / RCE)
- **Where:** `routes/userProfile.ts:65`
- **Category:** A05:2025 Injection · CWE-94 / CWE-95 · Confidence: high · Scanner: `INJ-03`
- **Juice Shop challenge:** Username XSS / SSTI-style abuse (`usernameXssChallenge`)
- **Evidence:** when the challenge is enabled, a username matching `#{...}` has its inner expression passed to
  `eval(code)`.
- **Impact:** a logged-in user who can set their username runs arbitrary JavaScript in the Node process.
- **Fix:** never `eval` user content. Escape for HTML with a sanitizer, or render through a template engine that
  auto-escapes. If a limited expression language is required, use an allowlisted interpreter.

### [HIGH] F-8: XML parser enables external entities (XXE)
- **Where:** `lib/xml.ts` (`parseXmlString`, ParseOption with `XML_PARSE_NOENT` and `XML_PARSE_DTDLOAD`)
- **Category:** A02:2025 Security Misconfiguration · CWE-611 · Confidence: high · Found by manual review of
  scanner-adjacent code (the helper uses `new Function` only to dynamic-import the parser; see false alarms)
- **Juice Shop challenges:** XXE / related XML challenges
- **Evidence:** entity substitution and DTD loading are turned on, and the WASM filesystem provider is registered so
  `file://` entities resolve.
- **Impact:** crafted XML can read local files or hit internal URLs through entity expansion.
- **Fix:** parse with DTDs and external entities disabled; do not register filesystem providers for untrusted XML.

## Attack chains
1. **F-1 alone:** unauthenticated admin login via SQL injection on `/rest/user/login`.
2. **F-2 → credential dump:** UNION SQL on product search returns user emails and password hashes from other tables.
3. **F-3 / F-4:** NoSQL `$where` abuse reads or floods review and order collections without going through ORM
   parameter binding.

## False alarms (scanner hits that are not reportable issues here)

These are useful follow-ups for tightening the scanner, not findings against Juice Shop’s training surface.

| Rule | Location | Why it is a false alarm |
|:---|:---|:---|
| `INJ-03` | `lib/xml.ts:12` | `new Function('specifier', 'return import(specifier)')` is a build workaround for an ESM-only package. The argument is a constant module name, not request input. |
| `INJ-03` | `routes/captcha.ts:22` | `eval(expression)` runs a math expression built only from server-side `Math.random()` integers and fixed operators. Callers never supply the expression. |
| `DESER-01` | `lib/scripts/lintConfig.ts:22` | Offline config lint script loads local YAML files from disk, not request bodies. |
| `DESER-01` | `routes/vulnCodeFixes.ts:83`, `routes/vulnCodeSnippet.ts:90` | `yaml.load` of static challenge metadata under `data/static/codefixes/`. Not attacker-controlled document content (path key is challenge id). |
| `CRYPTO-02` | `lib/insecurity.ts:53` | `Math.random()` seeds `denyAll()`’s JWT secret on purpose so every token fails verification. It is not used to mint session or reset tokens. |

## Not covered
- Files outside `routes/` and `lib/` (for example `models/`, front-end Angular app, Docker image hardening).
- Dependency CVE / SCA scan of `package-lock.json`.
- Full DAST crawl of a running instance (beyond confirming the login SQL injection pattern documented in
  [`demo/`](./demo/)).
- Business-logic and challenge-scoring code that intentionally weakens checks when a challenge flag is off.
