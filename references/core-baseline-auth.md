# Core Baseline, Authentication & Access Control Reference

> OWASP Top 10:2025: A01, A02, A04, A05, A07, A09, A10 · API Top 10:2023: API1, API2, API3, API5 · Category lookup: [owasp-mapping.md](./owasp-mapping.md)

> OWASP Cheat Sheets:
> - [Input Validation](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
> - [Error Handling](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html)
> - [Logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
> - [Transport Layer Security](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html)
> - [Secrets Management](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
> - [Authentication](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
> - [Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
> - [Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
> - [Multifactor Authentication](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html)
> - [JSON Web Token (JWT)](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
> - [Credential Stuffing Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html)
> - [Forgot Password](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)
> - [Authorization](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
> - [IDOR Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html)
> - [Mass Assignment](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html)
> - [OS Command Injection Defense](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html)
> - [Deserialization](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
> - [XML External Entity Prevention](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
> - [Denial of Service](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html)
> - [Cryptographic Storage](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
> - [Key Management](https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html)
> - [User Privacy Protection](https://cheatsheetseries.owasp.org/cheatsheets/User_Privacy_Protection_Cheat_Sheet.html)

---

## Module 1: Universal Security Baseline [ALWAYS IN SCOPE]

### 1.1 Transport Layer Security
- [ ] **1.1.1** HTTPS/TLS is enforced for all production traffic; cleartext HTTP is disabled or redirected (`301`/`308`).
- [ ] **1.1.2** TLS 1.2+ is required (TLS 1.3 preferred); SSLv3, TLS 1.0/1.1, and weak ciphers (RC4, DES, 3DES, export, NULL) are disabled.
- [ ] **1.1.3** HSTS header is set (`Strict-Transport-Security: max-age=31536000; includeSubDomains`).
- [ ] **1.1.4** TLS certificate validation is never disabled in production (`rejectUnauthorized: false`, `verify=False`, `InsecureSkipVerify: true`, permissive `badCertificateCallback`).

### 1.2 Input Validation, Injection & DoS Loop Prevention
- [ ] **1.2.1** All inputs are validated server-side with strict schemas (type, length, range, format allowlist); client validation is UX only.
- [ ] **1.2.2** SQL/NoSQL queries use parameterized statements or safe ORM bindings; never string-concatenated or interpolated.
- [ ] **1.2.3** OS command injection is prevented — avoid shell invocation (`shell=True`, `exec`, `system`), pass argument arrays directly to `execFile`/`subprocess.run(..., shell=False)` with allowlisted values.
- [ ] **1.2.4** Path traversal (`../`) is prevented — canonicalize paths (`path.resolve` / `realpath`) and verify the resolved path starts with the intended base directory.
- [ ] **1.2.5** XML parsers disable DTDs and external entities (XXE defense).
- [ ] **1.2.6** LDAP, XPath, and Server-Side Template Injection (SSTI) vectors are neutralized (never pass user strings as template source).
- [ ] **1.2.7** **ReDoS / Backtracking Loops**: Regular expressions avoid nested quantifiers (`(a+)+`, `(.*)*`, overlapping alternations) on untrusted input; input lengths and parser nesting depths are bounded.
- [ ] **1.2.8** File uploads validate size, extension allowlist, MIME type, and magic bytes; filenames are regenerated server-side (UUID) and stored outside executable web roots; archive extraction defends against Zip bombs and Zip Slip (`../`).
- [ ] **1.2.9** Untrusted data uses safe JSON/Protobuf deserialization instead of native binary formats (`pickle`, `unserialize`, Java `ObjectInputStream`, `yaml.load` without `SafeLoader`, `node-serialize`).

### 1.3 Error Handling & Information Disclosure
- [ ] **1.3.1** Production error responses omit stack traces, SQL queries, internal file paths, environment variables, and framework internals.
- [ ] **1.3.2** Generic error envelopes with correlation IDs are returned for 4xx/5xx errors.
- [ ] **1.3.3** Debug modes, GraphiQL/Swagger UI (unless intentionally public), profiler endpoints, and test/admin backdoors are disabled in production.
- [ ] **1.3.4** Fingerprinting headers (`Server`, `X-Powered-By`, `X-AspNet-Version`) are stripped or minimized.

### 1.4 Logging & Monitoring
- [ ] **1.4.1** Security events (auth success/failure, lockouts, role changes, access denials, input rejections, admin actions) are logged with actor, timestamp, IP, and outcome.
- [ ] **1.4.2** Logs scrub passwords, JWTs/session IDs, API keys, authorization headers, credit cards, and unnecessary PII.
- [ ] **1.4.3** Log injection (CRLF / fake log lines) is prevented using structured JSON logging or control-character sanitization.
- [ ] **1.4.4** Log stores are access-controlled, centralized, and protected against tampering.
- [ ] **1.4.5** Automated alerts exist for brute-force spikes, privilege escalations, abnormal traffic/cost spikes, and repeated 401/403/500 responses.

### 1.5 Secrets Management
- [ ] **1.5.1** No API keys, DB credentials, signing secrets, or private keys are hardcoded in source code, config defaults, or committed tests.
- [ ] **1.5.2** `.env*` (except safe templates like `.env.example`), `*.key`, `*.pem`, `*.p12`, `*.jks`, `*.keystore`, and service-account JSONs are excluded in `.gitignore`.
- [ ] **1.5.3** Production secrets live in a secrets manager (Vault, AWS/GCP Secret Manager, Azure Key Vault, CI secret store), not plain text in code or container images.
- [ ] **1.5.4** Automated secret scanning (`gitleaks`, `trufflehog`) runs in pre-commit hooks and CI.
- [ ] **1.5.5** Key/credential rotation and emergency revocation procedures are documented and tested.

### 1.6 Dependencies & Supply Chain
- [ ] **1.6.1** Dependencies are scanned regularly (`osv-scanner`, `npm audit`, `pip-audit`, `govulncheck`, `cargo audit`, `dotnet list package --vulnerable`, `trivy fs`).
- [ ] **1.6.2** Lockfiles (`package-lock.json`, `poetry.lock`, `go.sum`, `pubspec.lock`, etc.) are committed and reviewed on updates.
- [ ] **1.6.3** Automated SCA / dependency PR alerts (Dependabot, Renovate, Snyk) are enabled.
- [ ] **1.6.4** Unused, abandoned, typosquatted, or unverified packages are removed.

### 1.7 Mishandling of Exceptional Conditions (A10:2025)
- [ ] **1.7.1** **Fail closed**: authorization, payment, and validation code denies access when an exception, timeout, or missing value occurs (no `except: pass`, no `catch {}` that falls through to the allowed path, no default-allow on a failed policy lookup).
- [ ] **1.7.2** Errors from dependencies (DB, cache, auth provider, LLM API) are handled explicitly: retries are bounded with backoff, and partial failures roll back transactions instead of leaving half-applied state.
- [ ] **1.7.3** Resources (file handles, locks, DB connections, temp files) are released on every error path (`with`, `try/finally`, `defer`, `using`).
- [ ] **1.7.4** Unexpected input types, nulls, and oversized values are rejected before use, so they cannot crash a worker or skip a security check.
- [ ] **1.7.5** Unhandled exceptions and promise rejections are caught by a top-level handler that logs them and returns a generic error, without exposing internals or killing the process for every user.

---

## Module 2: Authentication & Session Management [ALWAYS IN SCOPE]

### 2.1 Password Storage & Policies
- [ ] **2.1.1** Passwords are hashed server-side using **Argon2id** (≥19 MiB memory, ≥2 iterations, parallelism 1), **bcrypt** (cost ≥10), or **PBKDF2-HMAC-SHA256** (≥600,000 iterations) with unique per-user salts. Never MD5, SHA-1, or unsalted SHA-256.
- [ ] **2.1.2** Password policies enforce minimum length (≥8, ideally ≥12 chars), allow passphrases/special chars without arbitrary truncation, and reject known breached passwords.
- [ ] **2.1.3** Password inputs use `autocomplete="current-password"` / `"new-password"` appropriately; password reset uses short-lived, single-use, cryptographically random tokens sent out-of-band (never security questions).

### 2.2 Session Management
- [ ] **2.2.1** Session IDs use CSPRNG with ≥128 bits of entropy; never predictable or sequential.
- [ ] **2.2.2** Session cookies enforce `HttpOnly`, `Secure`, `SameSite=Lax` (or `Strict`), and restrictive `Path`/`Domain`.
- [ ] **2.2.3** Session identifier is regenerated on login, MFA completion, and privilege escalation (prevents session fixation).
- [ ] **2.2.4** Both idle timeout and absolute lifetime are enforced server-side.
- [ ] **2.2.5** Logout invalidates the session/refresh credential server-side, not just clearing browser state.

### 2.3 JWT Security [LOAD IF USING JWT]
- [ ] **2.3.1** Allowed signing algorithms are explicitly pinned/whitelisted server-side (e.g., `algorithms: ['RS256']`); `alg: none` and untrusted `jku`/`x5u` headers are rejected.
- [ ] **2.3.2** Algorithm confusion (RS256 public key abused as HS256 HMAC secret) is blocked by separating key types and enforcing expected `alg`.
- [ ] **2.3.3** `exp`, `nbf`, `iss`, and `aud` claims are validated on every request; `jwt.decode()` without signature verification is never used for auth.
- [ ] **2.3.4** Access tokens are short-lived (e.g., 5–15 min); refresh tokens are stored securely, rotated on use with reuse-detection revocation, and revocable on logout/compromise.
- [ ] **2.3.5** Signing secrets (`HS256`) have high entropy (≥256 bits) and never use hardcoded fallback defaults (`process.env.JWT_SECRET || 'secret'`).
- [ ] **2.3.6** Sensitive PII/secrets are not stored inside unencrypted JWT payloads; tokens travel in `Authorization: Bearer` or `HttpOnly` cookies, never query strings.

### 2.4 OAuth 2.0 / OpenID Connect [LOAD IF USING OAUTH/OIDC]
- [ ] **2.4.1** Authorization Code flow with **PKCE** (`S256`) is used (Implicit flow avoided).
- [ ] **2.4.2** Cryptographic `state` (CSRF) and `nonce` (replay) parameters are generated and strictly verified.
- [ ] **2.4.3** `redirect_uri` uses exact server-side allowlist matching (no wildcard domains, regex bypasses, or open redirect chains).
- [ ] **2.4.4** ID tokens have signature, `iss`, `aud`, `exp`, and `nonce` validated; client secrets stay strictly server-side.

### 2.5 MFA & Brute-Force Protection
- [ ] **2.5.1** MFA is supported (required for admin/privileged roles); phishing-resistant MFA (WebAuthn/FIDO2/Passkeys) or TOTP preferred over SMS.
- [ ] **2.5.2** OTP codes are short-lived, single-use, constant-time compared, and locked after few failed attempts (e.g., 3–5 tries) so brute-forcing a 6-digit code in parallel requests is impossible.
- [ ] **2.5.3** Login, registration, OTP, and forgot-password endpoints enforce rate limiting, progressive backoff, and generic responses (prevents account enumeration).
- [ ] **2.5.4** MFA enrollment/recovery flows cannot bypass step-up checks or reuse backup codes (backup codes stored hashed).

---

## Module 3: Authorization & Access Control [ALWAYS IN SCOPE]

- [ ] **3.1** **Deny by Default**: Authorization middleware/guards are applied globally or explicitly verified on every protected route; public routes are opt-in.
- [ ] **3.2** **BOLA / IDOR Prevention**: Every single-record endpoint (`GET/PUT/PATCH/DELETE /resource/:id`) verifies server-side that the authenticated user owns or has tenant/ACL permission for `:id` — non-guessable UUIDs alone are NOT authorization.
- [ ] **3.3** **BFLA Prevention**: Admin, staff, internal, and debug endpoints explicitly enforce role/capability checks server-side (never rely on hidden UI buttons).
- [ ] **3.4** **Mass Assignment / Over-Posting**: Request bodies are filtered through strict DTOs/schemas (`Zod`, `Pydantic`, `$fillable`, `permit`, `[Bind]`); protected fields (`role`, `isAdmin`, `tenantId`, `ownerId`, `balance`, `subscriptionTier`) cannot be injected by clients.
- [ ] **3.5** **Multi-Tenant Isolation**: Every DB query, cache key, storage path, and vector search scopes by server-derived `tenant_id` (from verified session/token, never from request body/header).
- [ ] **3.6** **Step-Up Re-Authentication**: Password/email changes, MFA disablement, API key creation, payouts, and account deletion require re-authentication or fresh step-up verification.
- [ ] **3.7** **Multi-Dimensional Rate Limiting**: Rate limits and quotas apply per-IP, per-user, and per-tenant across expensive endpoints.

---

## Module 15: Cryptography & Key Management [ALWAYS IN SCOPE]

- [ ] **15.1** Use vetted standard libraries (`libsodium`, WebCrypto, `cryptography`, Node `crypto`, Go `crypto/*`); never invent custom crypto.
- [ ] **15.2** Use authenticated encryption (`AES-256-GCM`, `ChaCha20-Poly1305`); avoid `ECB` mode and unauthenticated `CBC`.
- [ ] **15.3** Generate keys, IVs, nonces, reset tokens, and CSRF tokens with CSPRNG (`crypto.randomBytes`, `secrets`, `Random.secure()`), never `Math.random()` or `random`.
- [ ] **15.4** Never reuse nonces/IVs with the same key in GCM/CTR/ChaCha20; verify authentication tags before trusting plaintext.
- [ ] **15.5** Use constant-time comparison (`crypto.timingSafeEqual`, `hmac.compare_digest`) for signatures, HMACs, API keys, and tokens.
- [ ] **15.6** Eliminate weak algorithms (MD5, SHA-1, DES, 3DES, RC4) for signatures, password hashing, or integrity checks.

---

## Module 16: Privacy & Data Protection [ALWAYS IN SCOPE]

- [ ] **16.1** Collect and return only necessary fields (avoid returning full DB user objects with password hashes, internal flags, or PII).
- [ ] **16.2** Scrub PII, tokens, and secrets from analytics, telemetry, crash reports (Sentry/Crashlytics), and session replay.
- [ ] **16.3** Enforce account deletion, data export, consent, and retention purge workflows.
- [ ] **16.4** External notifications (emails, push notifications, webhooks) do not expose sensitive data or unhashed tokens unnecessarily.

---

## Module 18: Security Testing & Verification [ALWAYS IN SCOPE]

- [ ] **18.1** SAST (`Semgrep`, `Bandit`, `Brakeman`, `CodeQL`), secret scanning (`Gitleaks`/`TruffleHog`), and SCA (`OSV-Scanner`) run automatically in CI/CD.
- [ ] **18.2** Automated tests include authorization regression tests (testing unauthenticated, cross-user IDOR, cross-tenant, and low-role escalation on every sensitive route).
- [ ] **18.3** Staging DAST/fuzzing (`OWASP ZAP`, `Nuclei`, `Schemathesis`) runs before major releases.
- [ ] **18.4** Critical/High findings are remediated prior to production deployment or formally documented with compensating controls.
