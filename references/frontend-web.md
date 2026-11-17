# Frontend & Web Application Security Reference (Module 4)

> OWASP Cheat Sheets:
> - [Cross-Site Scripting (XSS) Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
> - [DOM-Based XSS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)
> - [Content Security Policy (CSP)](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
> - [Cross-Site Request Forgery (CSRF) Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Request_Forgery_Prevention_Cheat_Sheet.html)
> - [Clickjacking Defense](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html)
> - [HTTP Headers](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)
> - [HTML5 Security](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html)
> - [JavaScript and TypeScript Security](https://cheatsheetseries.owasp.org/cheatsheets/JavaScript_and_TypeScript_Security_Cheat_Sheet.html)
> - [Unvalidated Redirects and Forwards](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)

---

## 4.1 Cross-Site Scripting (XSS) & Injection Prevention
- [ ] **4.1.1** Rely on framework auto-escaping (`{expr}`, `{{ expr }}`); never disable escaping for untrusted strings.
- [ ] **4.1.2** Audit every framework escape hatch and require `DOMPurify.sanitize()` before rendering:
  - **React / Next.js**: `dangerouslySetInnerHTML`, raw `ref.current.innerHTML`
  - **Vue / Nuxt**: `v-html`, `render()` raw HTML
  - **Angular**: `bypassSecurityTrustHtml`, `bypassSecurityTrustScript`, `bypassSecurityTrustResourceUrl`, `[innerHTML]`
  - **Svelte / SvelteKit**: `{@html ...}`
  - **Vanilla DOM**: `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval`, `new Function`, `setTimeout(string)`
- [ ] **4.1.3** Dynamic URLs (`href`, `src`, `action`, `window.open`, `window.location`, Next `<Link href>`) validate URL scheme (`https:` / `http:` / safe relative `/...`) to block `javascript:`, `data:`, and `vbscript:` XSS.
- [ ] **4.1.4** Markdown/rich-text renderers (`marked`, `react-markdown`, `markdown-it`) disallow raw HTML or sanitize output with `DOMPurify` (and disable `javascript:` links).
- [ ] **4.1.5** `postMessage` handlers verify `event.origin` with exact allowlist comparison (`===`, never `.includes()`) and `postMessage` calls specify an explicit `targetOrigin` (never `'*'` for sensitive data).
- [ ] **4.1.6** `target="_blank"` links include `rel="noopener noreferrer"` where appropriate to prevent reverse tabnabbing/opener tampering.

## 4.2 Content Security Policy (CSP) & Clickjacking
- [ ] **4.2.1** Production serves a strict CSP header (`default-src 'self'; script-src 'self' 'nonce-...'; object-src 'none'; base-uri 'self'; frame-ancestors 'none';`).
- [ ] **4.2.2** Avoid `'unsafe-inline'` and `'unsafe-eval'` in `script-src`; migrate inline scripts to per-request cryptographic nonces or hashes.
- [ ] **4.2.3** `frame-ancestors 'none'` (or trusted origin) and `X-Frame-Options: DENY`/`SAMEORIGIN` block clickjacking on sensitive pages.
- [ ] **4.2.4** Subresource Integrity (`integrity="sha384-..." crossorigin="anonymous"`) is applied if external CDN scripts/styles are loaded.

## 4.3 CSRF & CORS
- [ ] **4.3.1** Cookie-authenticated state changes (`POST`, `PUT`, `PATCH`, `DELETE`) use anti-CSRF tokens (Synchronizer Token or Double-Submit) AND/OR `SameSite=Lax`/`Strict` cookies plus `Origin`/`Referer` verification.
- [ ] **4.3.2** `GET` endpoints never trigger state changes (no `GET /logout`, `GET /delete`, `GET /transfer`).
- [ ] **4.3.3** CORS never pairs `Access-Control-Allow-Credentials: true` with wildcard `*`, `null`, or blind reflection of the incoming `Origin` header.

## 4.4 HTTP Security Headers
- [ ] **4.4.1** `Strict-Transport-Security` (HSTS) enabled.
- [ ] **4.4.2** `X-Content-Type-Options: nosniff` enabled.
- [ ] **4.4.3** `Referrer-Policy: strict-origin-when-cross-origin` or `no-referrer` enabled (prevents token leakage via Referer).
- [ ] **4.4.4** `Permissions-Policy` disables unused sensitive browser APIs (`camera=(), microphone=(), geolocation=()`).

## 4.5 Client-Side Secrets, SSR & Bundle Exposure
- [ ] **4.5.1** No private API keys, admin tokens, or DB credentials in client env vars (`NEXT_PUBLIC_*`, `VITE_*`, `REACT_APP_*`, `NUXT_PUBLIC_*`).
- [ ] **4.5.2** Sensitive access/refresh tokens are not persisted in `localStorage`/`sessionStorage` (prefer `HttpOnly; Secure; SameSite` cookies via BFF pattern, or in-memory short-lived tokens).
- [ ] **4.5.3** Server-Side Rendering (Next.js App Router / RSC / Nuxt / SvelteKit) does not serialize internal DB fields, secrets, or unredacted user objects into `__NEXT_DATA__`, RSC props, or `window.__INITIAL_STATE__`.
- [ ] **4.5.4** Next.js Server Actions / Nuxt server routes / SvelteKit form actions authenticate and authorize callers inside every action — UI route guards (`middleware` or layouts) alone can be bypassed!
- [ ] **4.5.5** Production builds strip public source maps (`productionBrowserSourceMaps: false` / hidden source maps uploaded privately to Sentry) and disable debug/DevTools panels.

## 4.6 Unvalidated Redirects & Prototype Pollution
- [ ] **4.6.1** Login/OAuth `?next=` or `?redirect=` parameters only allow relative paths (starting with `/` and NOT `//` or `/\`) or exact allowlisted hostnames parsed via `new URL()`.
- [ ] **4.6.2** Client utilities avoid recursive deep-merge of untrusted JSON into plain objects without filtering `__proto__`, `constructor`, and `prototype`.
