# Database, API, SSRF, Microservices & Business Logic Security Reference

> OWASP Top 10:2025: A01 (incl. SSRF), A05, A06 · API Top 10:2023: API1–API10 · Category lookup: [owasp-mapping.md](./owasp-mapping.md)

> OWASP Cheat Sheets:
> - [Database Security](https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html)
> - [SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
> - [Query Parameterization](https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html)
> - [REST Security](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html)
> - [REST Assessment](https://cheatsheetseries.owasp.org/cheatsheets/REST_Assessment_Cheat_Sheet.html)
> - [GraphQL](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html)
> - [Server-Side Request Forgery Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
> - [Microservices Security](https://cheatsheetseries.owasp.org/cheatsheets/Microservices_Security_Cheat_Sheet.html)
> - [Business Logic Security](https://cheatsheetseries.owasp.org/cheatsheets/Business_Logic_Security_Cheat_Sheet.html)
> - [Transaction Authorization](https://cheatsheetseries.owasp.org/cheatsheets/Transaction_Authorization_Cheat_Sheet.html)

---

## Module 6: Database & ORM Security [LOAD MATCHING DB ONLY]

### 6A. Relational Databases (PostgreSQL / MySQL / SQLite)
- [ ] **6A.1** All queries use parameterized placeholders (`$1`, `?`, `:name`) or safe ORM methods; zero dynamic SQL string interpolation.
- [ ] **6A.2** Dynamic identifiers (`ORDER BY` column, `ASC`/`DESC`, table/column selectors) map through a strict server-side allowlist — bind parameters cannot protect identifiers!
- [ ] **6A.3** Application DB credentials follow least privilege (no `SUPERUSER`, `postgres`, `root`, or schema-drop grants for runtime app user).
- [ ] **6A.4** DB binds to private/loopback network interfaces (not `0.0.0.0` public internet) and enforces TLS (`sslmode=verify-full` / `hostssl` / `require_secure_transport`).
- [ ] **6A.5** ORM escape hatches are audited:
  - **Prisma**: avoid `$queryRawUnsafe` / `$executeRawUnsafe`; use tagged ``Prisma.$queryRaw`...` ``; never spread unvalidated `req.body` into `data:` or `where:`.
  - **Drizzle / Knex / TypeORM / Sequelize**: avoid `sql.raw()`, `knex.raw()`, `.createQueryBuilder().where(\`...${input}\`)`, `Sequelize.literal()` with user input.
  - **SQLAlchemy**: avoid `text(f"...")`; use `bindparams` and ORM expressions.
- [ ] **6A.6** Backups are encrypted, access-controlled, and retention/restore-tested; migrations don't leak secrets or plaintext passwords.

### 6B. MongoDB / NoSQL
- [ ] **6B.1** Type-coerce/validate all query inputs (`String()`, Zod string schema) so attackers cannot pass operator objects (`{"$ne": null}`, `{"$gt": ""}`, `{"$regex": "..."}`) via JSON bodies or nested query params (`?user[$ne]=1`).
- [ ] **6B.2** Disable/avoid server-side JS execution (`$where`, `mapReduce`, `function()`).
- [ ] **6B.3** Authentication (`authorization: enabled`), per-DB least-privilege RBAC (never `root` for app), private `bindIp`, TLS, and encryption at rest are enabled.
- [ ] **6B.4** Mongoose schemas restrict mass assignment and strip sensitive fields (`select: false` on `passwordHash`, explicit DTO projections).

### 6C. Redis / Cache Stores
- [ ] **6C.1** Bound strictly to private interface/localhost; port `6379` is never publicly reachable.
- [ ] **6C.2** ACLs / strong `requirepass` + TLS (`rediss://`) enabled; dangerous commands (`FLUSHALL`, `FLUSHDB`, `CONFIG`, `EVAL`, `DEBUG`) disabled/renamed.
- [ ] **6C.3** Cache keys include tenant/user scope (prevents cross-tenant cache poisoning/leakage) and sensitive entries enforce TTLs.

---

## Module 7: API Security (REST & GraphQL) [LOAD IF APPLICABLE]

### 7A. REST API Security
- [ ] **7A.1** Strict `Content-Type` validation (`application/json`) rejects unexpected media types (`415 Unsupported Media Type`) and prevents content-sniffing/CSRF.
- [ ] **7A.2** Response DTOs explicitly whitelist serialized fields (blocks Excessive Data Exposure of password hashes, tokens, internal flags, PII).
- [ ] **7A.3** All collection/search endpoints enforce bounded pagination (`limit` capped server-side, e.g., `<= 100`) to prevent DB/memory exhaustion.
- [ ] **7A.4** Rate limiting, request timeouts, and max body sizes protect every endpoint (including auth, search, export, webhook).
- [ ] **7A.5** Internal Swagger/OpenAPI docs, debug endpoints, and deprecated vulnerable API versions are disabled or auth-protected in production.
- [ ] **7A.6** State-changing / financial operations support `Idempotency-Key` headers and database-level uniqueness/locks.

### 7B. GraphQL Security [SKIP IF NOT USING GRAPHQL]
- [ ] **7B.1** Introspection (`__schema`, `__type`) and GraphiQL/Apollo Sandbox are disabled in production.
- [ ] **7B.2** **Loop & DoS Prevention**: Query depth limiting (`maxDepth`), query cost/complexity analysis, alias limits, and circular fragment detection are enforced to block nested/recursive query loops (`user -> posts -> author -> posts...`).
- [ ] **7B.3** Array query batching is disabled or rate-limited per-operation (prevents 1000-attempt OTP/login brute-force in 1 HTTP request).
- [ ] **7B.4** Field-level and resolver-level authorization checks run on every query, nested field, and mutation (not just top-level route middleware).
- [ ] **7B.5** Field suggestion hints (`Did you mean ...?`) and verbose stack traces are disabled in production errors.

---

## Module 13: Microservices & Service Architecture [SKIP IF NOT USING]
- [ ] **13.1** Service-to-service traffic uses mTLS (service mesh / TLS client certs) or short-lived cryptographically signed service tokens.
- [ ] **13.2** End-user identity and tenant/role claims are propagated securely via verified tokens — each service independently authorizes requests (never blindly trust gateway-only checks or spoofable `X-User-Id` headers).
- [ ] **13.3** Internal network policies isolate east-west traffic; services only reach permitted upstream dependencies.
- [ ] **13.4** Timeouts, circuit breakers, retry budgets (with jitter & max retries), and dead-letter queues prevent cascading retry loops / amplification storms.

---

## Module 14: SSRF & Unbound Redirect Prevention [LOAD IF OUTBOUND HTTP EXISTS]
- [ ] **14.1** User-influenced URLs (webhooks, avatar fetchers, PDF generators, link previews, import URLs) validate against a strict domain/host allowlist.
- [ ] **14.2** Only `https://` (or documented `http://`) schemes permitted; `file://`, `gopher://`, `ftp://`, `dict://`, `jar://` are blocked.
- [ ] **14.3** Outbound HTTP clients resolve DNS first, reject private/loopback/link-local/multicast IPs (`127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, `::1`, `fc00::/7`), and pin the validated IP on connection (blocks DNS rebinding + decimal/octal/IPv6-mapped IP tricks).
- [ ] **14.4** Cloud metadata endpoints (`169.254.169.254`, `metadata.google.internal`) are blocked via network egress rules and IMDSv2 is enforced.
- [ ] **14.5** **Redirect Loop & Bypass Defense**: Automatic HTTP redirect following is disabled (`redirect: 'manual'` / `allow_redirects=False`) or capped and re-validated on every hop so `https://allowed.com -> 302 -> http://169.254.169.254` cannot bypass allowlists or cause infinite redirect loops.

---

## Module 17: Business Logic, Race Conditions & Payment Security [LOAD IF APPLICABLE]
- [ ] **17.1** Prices, discounts, coupons, balances, taxes, quantities (`> 0`, integer/safe decimal bounds), and entitlements are calculated solely server-side.
- [ ] **17.2** Workflow state machines enforce valid state transitions server-side (attacker cannot jump `cart -> order_confirmed` skipping `payment_verified`).
- [ ] **17.3** **Race Condition / Concurrent Loop Defense**: Balance transfers, coupon redemptions, withdrawals, inventory decrements, and OTP checks use atomic DB operations (`UPDATE ... WHERE balance >= amount`), `SELECT ... FOR UPDATE` row locks, serializable transactions, or distributed mutexes so parallel requests cannot double-spend or loop-redeem.
- [ ] **17.4** Payment receipts/webhooks verify cryptographic signatures (Stripe `constructEvent`, RevenueCat, Play Billing, App Store Server API) and enforce replay protection + idempotency.
- [ ] **17.5** Uploaded files are stored privately by default; download access checks ownership, signed URLs expire quickly, and EXIF GPS metadata is stripped.
