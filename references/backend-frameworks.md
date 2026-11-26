# Backend Framework Security Reference (Module 5)

> OWASP Top 10:2025: A01, A02, A05, A07, A08 · API Top 10:2023: API3, API8 · Category lookup: [owasp-mapping.md](./owasp-mapping.md)

> OWASP Cheat Sheets:
> - [Node.js Security](https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html)
> - [Django Security](https://cheatsheetseries.owasp.org/cheatsheets/Django_Security_Cheat_Sheet.html)
> - [Django REST Framework](https://cheatsheetseries.owasp.org/cheatsheets/Django_REST_Framework_Cheat_Sheet.html)
> - [FastAPI Security](https://cheatsheetseries.owasp.org/cheatsheets/FastAPI_Security_Cheat_Sheet.html)
> - [Laravel](https://cheatsheetseries.owasp.org/cheatsheets/Laravel_Cheat_Sheet.html)
> - [.NET Security](https://cheatsheetseries.owasp.org/cheatsheets/DotNet_Security_Cheat_Sheet.html)
> - [Ruby on Rails Security](https://cheatsheetseries.owasp.org/cheatsheets/Ruby_on_Rails_Security_Cheat_Sheet.html)
> - [Java Security](https://cheatsheetseries.owasp.org/cheatsheets/Java_Security_Cheat_Sheet.html)
> - [Bean Validation](https://cheatsheetseries.owasp.org/cheatsheets/Bean_Validation_Cheat_Sheet.html)

Evaluate ONLY the section(s) matching the project's confirmed backend stack.

---

## 5A. Node.js / Express / NestJS / Fastify [SKIP IF NOT USING]
- [ ] **5A.1** Request body limits are configured (`express.json({ limit: '10kb' })` or route-specific limits) to block payload-exhaustion DoS.
- [ ] **5A.2** `helmet()` is applied; `X-Powered-By` is disabled (`app.disable('x-powered-by')`).
- [ ] **5A.3** Strict schema validation (`Zod`, `Joi`, `class-validator` with `whitelist: true, forbidNonWhitelisted: true` in NestJS) strips/rejects unexpected fields (mass assignment & prototype pollution defense).
- [ ] **5A.4** MongoDB/query operator injection is blocked (`express-mongo-sanitize` or strict primitive type validation so `{ "$ne": "" }` objects cannot reach queries).
- [ ] **5A.5** Rate limiting (`express-rate-limit`, `@nestjs/throttler`, Fastify rate-limit) is active on auth, OTP, password-reset, and expensive routes.
- [ ] **5A.6** Never pass untrusted input to `eval()`, `new Function()`, `vm.runInNewContext()`, `child_process.exec()`, or `execSync()`.
- [ ] **5A.7** Express/Fastify error-handling middleware catches async rejections and returns generic errors in production (`NODE_ENV=production`).
- [ ] **5A.8** Object merges/clones guard against `__proto__`, `constructor`, and `prototype` pollution; JSON parsing/templating engines (`ejs`, `pug`, `handlebars`) auto-escape and block SSTI.

## 5B. Python — Django / DRF [SKIP IF NOT USING]
- [ ] **5B.1** `DEBUG = False` and explicit `ALLOWED_HOSTS` (never `['*']`) in production settings.
- [ ] **5B.2** `SECRET_KEY` is loaded from env/secret manager (never hardcoded or committed) and rotated if leaked.
- [ ] **5B.3** Secure cookies & HTTPS enforced: `SESSION_COOKIE_SECURE = True`, `CSRF_COOKIE_SECURE = True`, `CSRF_COOKIE_HTTPONLY = True`, `SECURE_SSL_REDIRECT = True`, `SECURE_HSTS_SECONDS` set.
- [ ] **5B.4** Django ORM queries avoid `.raw()`, `.extra()`, `RawSQL()`, or `cursor.execute()` with f-strings/`%`-formatting.
- [ ] **5B.5** Templates avoid `|safe`, `mark_safe()`, and `{% autoescape off %}` on untrusted data.
- [ ] **5B.6** DRF sets explicit `DEFAULT_PERMISSION_CLASSES` (`IsAuthenticated`, not `AllowAny`) and object-level permissions (`has_object_permission` enforced on `retrieve`/`update`/`destroy` and custom `@action`s).
- [ ] **5B.7** Security middlewares (`SecurityMiddleware`, `CsrfViewMiddleware`, `XFrameOptionsMiddleware`) remain enabled; `django.contrib.admin` URL is hardened/IP-restricted/MFA-protected.

## 5C. Python — FastAPI / Flask [SKIP IF NOT USING]
- [ ] **5C.1** In FastAPI, `OAuth2PasswordBearer` only extracts the bearer string — verify every protected route pairs it with real JWT signature/claim/expiry validation via `Depends(...)`.
- [ ] **5C.2** Global/router-level `dependencies=[Depends(require_auth)]` or explicit auth checks ensure no route is accidentally left unauthenticated.
- [ ] **5C.3** Pydantic models validate types, bounds (`max_length`, `gt`, `lt`), and set `extra="forbid"` where mass assignment/unexpected fields must fail closed.
- [ ] **5C.4** CORS `CORSMiddleware` never combines `allow_origins=["*"]` with `allow_credentials=True`.
- [ ] **5C.5** In Flask, `DEBUG = False` in production, `WTF_CSRF_ENABLED = True` for cookie apps, Jinja2 autoescaping is enabled, and `render_template_string()` never receives user input (SSTI -> RCE).
- [ ] **5C.6** Avoid `pickle.loads`, `yaml.load` (use `yaml.safe_load`), `eval`, and `subprocess(..., shell=True)` on external data.

## 5D. PHP — Laravel / Symfony [SKIP IF NOT USING]
- [ ] **5D.1** Eloquent models define explicit `$fillable` (prefer allowlist over empty `$guarded = []`); never pass `$request->all()` directly into `Model::create()` or `$model->update()`.
- [ ] **5D.2** `APP_DEBUG=false` and `APP_ENV=production` in production; `APP_KEY` is never committed and is rotated if leaked.
- [ ] **5D.3** `VerifyCsrfToken` is enforced on web routes; API routes use stateless tokens (Sanctum/Passport) with scoped abilities.
- [ ] **5D.4** Query Builder / Eloquent uses bound parameters; `DB::raw()`, `whereRaw()`, `orderByRaw()` never concatenate user input.
- [ ] **5D.5** Blade escapes with `{{ }}`; raw `{!! !!}` is never used on untrusted content.
- [ ] **5D.6** Authorization uses Laravel Gates/Policies (`$this->authorize(...)`) consistently on every controller action (IDOR defense).
- [ ] **5D.7** Never pass user input to `unserialize()`, `eval()`, `exec()`, `shell_exec()`, or dynamic `include`/`require` (LFI/RFI).

## 5E. .NET / ASP.NET Core [SKIP IF NOT USING]
- [ ] **5E.1** `PasswordHasher<TUser>` / ASP.NET Core Identity is used; custom hashing is avoided.
- [ ] **5E.2** Cookies enforce `HttpOnly = true`, `SecurePolicy = CookieSecurePolicy.Always`, `SameSite = SameSiteMode.Strict` (or `Lax`).
- [ ] **5E.3** Endpoints bind to dedicated DTOs/Request models (never EF Core domain entities directly) to block over-posting / mass assignment.
- [ ] **5E.4** EF Core uses LINQ or `FromSqlInterpolated` (never `FromSqlRaw` with concatenated/$"" strings; note `FromSqlRaw($"...{x}")` is injectable if passed as `string` instead of `FormattableString`).
- [ ] **5E.5** Fallback authorization policy requires auth by default (`FallbackPolicy`), and `[Authorize(Roles/Policy)]` is applied cleanly; `[ValidateAntiForgeryToken]` protects MVC forms.
- [ ] **5E.6** `UseDeveloperExceptionPage()` runs only in `IsDevelopment()`; `BinaryFormatter` and `TypeNameHandling.All` (Newtonsoft.Json) are banned.

## 5F. Ruby on Rails [SKIP IF NOT USING]
- [ ] **5F.1** Strong Parameters (`params.require(...).permit(...)`) whitelist allowed fields; never `.permit!`.
- [ ] **5F.2** `protect_from_forgery with: :exception` is active for cookie/session controllers.
- [ ] **5F.3** ActiveRecord queries use hash/placeholder syntax (`User.where(email: params[:email])`), never string interpolation (`where("email = '#{params[:email]}'")`) or unvalidated `.order(params[:sort])`.
- [ ] **5F.4** Templates avoid `.html_safe` and `raw()` on user content; `config.force_ssl = true` in production.
- [ ] **5F.5** Avoid `Marshal.load`, `YAML.load` (use `YAML.safe_load`), `send()` on user-controlled method names, and `render inline:`.

## 5G. Java / Spring Boot [SKIP IF NOT USING]
- [ ] **5G.1** Spring Security `SecurityFilterChain` denies by default (`anyRequest().authenticated()`), with explicit role/method security (`@PreAuthorize`) on endpoints.
- [ ] **5G.2** CSRF is enabled for cookie/session flows; disabled only when strictly stateless bearer auth is used.
- [ ] **5G.3** JPA/Hibernate uses named parameters (`:param`) or Criteria API; JPQL/native queries never concatenate strings.
- [ ] **5G.4** `@Valid` / Bean Validation (`@Size`, `@Pattern`, `@NotBlank`) validates DTOs; domain JPA entities are not bound directly in controllers.
- [ ] **5G.5** Spring Boot Actuator endpoints (`env`, `heapdump`, `mappings`, `beans`, `shutdown`) are disabled or locked behind admin auth on an internal management port.
- [ ] **5G.6** Unsafe deserialization is blocked (`ObjectInputStream` look-ahead filters, Jackson `activateDefaultTyping` avoided).

## 5H. Go & Rust [SKIP IF NOT USING]
- [ ] **5H.1** **Go**: `database/sql` uses `$1`/`?` placeholders (never `fmt.Sprintf` in SQL); `html/template` (not `text/template`) renders HTML; `crypto/rand` (not `math/rand`) generates tokens; `http.Client` sets explicit `Timeout` and disables/validates redirects; `TLSConfig.InsecureSkipVerify` is `false`.
- [ ] **5H.2** **Go**: Goroutine/worker pools and request readers (`http.MaxBytesReader`) bound memory and concurrency to prevent DoS loops.
- [ ] **5H.3** **Rust**: Minimize `unsafe` blocks and document safety invariants; use parameterized SQL (`sqlx::query!` / `diesel`); set body size limits (`DefaultBodyLimit` in Axum) and `tower_http` timeouts/CORS; run `cargo audit` and `cargo clippy`.
