# BaaS (Firebase / Supabase) & Mobile Security Reference

> OWASP Top 10:2025: A01, A02, A04 · OWASP MASVS · Category lookup: [owasp-mapping.md](./owasp-mapping.md)

> References:
> - [OWASP Mobile Application Security CS](https://cheatsheetseries.owasp.org/cheatsheets/Mobile_Application_Security_Cheat_Sheet.html)
> - [OWASP Pinning CS](https://cheatsheetseries.owasp.org/cheatsheets/Pinning_Cheat_Sheet.html)
> - [OWASP MASVS](https://mas.owasp.org/MASVS/) & [MASTG](https://mas.owasp.org/MASTG/)
> - [Firebase Security Rules](https://firebase.google.com/docs/rules) & [App Check](https://firebase.google.com/docs/app-check)
> - [Supabase RLS](https://supabase.com/docs/guides/database/postgres/row-level-security) & [API Keys](https://supabase.com/docs/guides/api/api-keys)

Evaluate ONLY the sections matching the confirmed stack.

---

## Module 8: Firebase Backend Security [SKIP IF NOT USING FIREBASE]
- [ ] **8.1** Firestore Rules deny by default (`allow read, write: if false;`) and grant minimal scoped access (`request.auth != null`, `request.auth.uid == resource.data.ownerId`, tenant/role checks).
- [ ] **8.2** Realtime Database rules restrict public reads/writes and validate data schema (`.validate`).
- [ ] **8.3** Cloud Storage rules validate `request.auth`, ownership, max file size (`request.resource.size < ...`), and `request.resource.contentType`.
- [ ] **8.4** **Privilege Escalation Loop Check**: Rules block client writes to protected fields (`role`, `isAdmin`, `ownerId`, `tenantId`, `subscriptionStatus`) via `request.resource.data.diff(resource.data).affectedKeys().hasAny([...]) == false`.
- [ ] **8.5** Firebase client API keys (public identifiers) are restricted in GCP Console; Firebase Admin SDK / service-account JSON credentials NEVER exist in client code, assets, or `.env` shipped to clients.
- [ ] **8.6** Firebase Auth enforces email verification where needed, strong password policies, MFA for sensitive accounts, and secure action-code links.
- [ ] **8.7** Firebase App Check (Play Integrity / App Attest / reCAPTCHA Enterprise) is enabled and enforced as anti-abuse defense (NOT as replacement for Security Rules).
- [ ] **8.8** Cloud Functions (`onCall` / `onRequest`) verify `context.auth` / ID token, authorize per-resource ownership, validate inputs, and apply rate limits.
- [ ] **8.9** Dev/staging/production Firebase projects are isolated; Security Rules have automated emulator unit tests (`@firebase/rules-unit-testing`).

---

## Module 9: Supabase Backend Security [SKIP IF NOT USING SUPABASE]
- [ ] **9.1** Row Level Security (RLS) is enabled (`ALTER TABLE ... ENABLE ROW LEVEL SECURITY;`) on EVERY table in exposed schemas (`public`, etc.).
- [ ] **9.2** Policies explicitly cover `SELECT`, `INSERT` (`WITH CHECK`), `UPDATE` (both `USING` and `WITH CHECK`), and `DELETE` (`USING`) scoped by `(SELECT auth.uid())`, role, and tenant.
- [ ] **9.3** **Metadata Tampering Loophole**: Policies NEVER trust user-editable `auth.jwt() -> 'user_metadata'` (`raw_user_meta_data`) for roles/permissions; use `app_metadata` or server-controlled lookup tables only.
- [ ] **9.4** Users cannot update protected columns (`role`, `owner_id`, `tenant_id`, `plan`) via direct PostgREST `PATCH` (prevent via column-level `REVOKE UPDATE`, `BEFORE UPDATE` triggers, or `WITH CHECK` comparing against `OLD`).
- [ ] **9.5** Views set `WITH (security_invoker = true)` (Postgres 15+); `SECURITY DEFINER` functions explicitly set `SET search_path = ''` (or `public, pg_temp`), validate caller `auth.uid()`, and revoke unnecessary `EXECUTE` from `anon`/`public`.
- [ ] **9.6** `service_role` / `sb_secret_*` keys NEVER appear in Flutter/Web/mobile code, `.env` shipped to clients, or git history; `anon` / `sb_publishable_*` keys rely on RLS for protection.
- [ ] **9.7** Storage buckets are private where appropriate; `storage.objects` RLS policies restrict `bucket_id`, path prefix (`(storage.foldername(name))[1] = auth.uid()::text`), and file types; signed URLs have short TTLs.
- [ ] **9.8** Edge Functions validate the user JWT via `supabase.auth.getUser(jwt)` (never blindly trust unverified headers), authorize the action, and rate-limit abuse.
- [ ] **9.9** Exposed schemas/tables in PostgREST (`supabase/config.toml` / DB grants) are minimized; RLS is tested across `anon`, `authenticated`, cross-user, cross-tenant, and admin roles.

---

## Module 11: Mobile & Flutter Application Security [SKIP IF NOT MOBILE]

### 11.1 Local Data Protection & Storage
- [ ] **11.1.1** Access/refresh tokens, passwords, and PII are stored in Keystore/Keychain (`flutter_secure_storage`, EncryptedSharedPreferences/Keystore, iOS Keychain) — NEVER plain-text `SharedPreferences`, `UserDefaults`, `AsyncStorage`, or unencrypted SQLite/Hive/Isar/Drift.
- [ ] **11.1.2** Encryption keys for local DBs (SQLCipher, encrypted Hive) are generated securely and stored in Keystore/Keychain, not hardcoded.
- [ ] **11.1.3** Sensitive data is omitted from `print`/`debugPrint`/`NSLog`/`Log.d`, temp files, and external storage; caches/tokens are wiped on logout & account switch.
- [ ] **11.1.4** Android `allowBackup` / `dataExtractionRules` and iOS backup exclusions (`NSURLIsExcludedFromBackupKey`) protect sensitive files; app-switcher previews, screenshots (`FLAG_SECURE`), clipboard, and keyboard autocomplete (`enableSuggestions: false`, `autocorrect: false`) are restricted for sensitive screens/fields.

### 11.2 Network, Certificate & Code Protection
- [ ] **11.2.1** HTTPS enforced; no global `usesCleartextTraffic="true"` or `NSAllowsArbitraryLoads=true`; `badCertificateCallback` NEVER returns `true` in production.
- [ ] **11.2.2** Certificate pinning (if required by threat model) includes backup pins and rotation strategy; Dio `LogInterceptor` / HTTP body logging is disabled in `kReleaseMode`.
- [ ] **11.2.3** Release builds enable obfuscation (`--obfuscate --split-debug-info` for Flutter; R8/ProGuard for Android) and strip dev menus, staging URLs, and test credentials.
- [ ] **11.2.4** No `service_role`, Admin SDK, Stripe secret, or private keys embedded in Dart/Kotlin/Swift, assets, `.env`, or `--dart-define` (values in client binaries are extractable).
- [ ] **11.2.5** Biometrics (`local_auth` / BiometricPrompt) unlock cryptographic Keystore/Keychain credentials rather than gating on a client boolean alone; Play Integrity / App Attest are verified server-side.

### 11.3 WebViews & Deep Links [SKIP IF NOT USED]
- [ ] **11.3.1** WebViews disable JavaScript and file access (`allowFileAccess`, `allowUniversalAccessFromFileURLs`) unless strictly required; navigation delegates enforce strict HTTPS domain allowlists and block `javascript:`, `file:`, `intent:` schemes.
- [ ] **11.3.2** `JavaScriptChannel` / `@JavascriptInterface` methods validate inputs and are never exposed to untrusted third-party pages.
- [ ] **11.3.3** Deep links (Android App Links `autoVerify="true"` + `assetlinks.json`, iOS Universal Links + `apple-app-site-association`, custom schemes) treat all URI params as untrusted and never pass raw tokens in URLs.

### 11.4 Android & iOS Platform Hardening
- [ ] **11.4.1** **Android**: `android:debuggable="false"`, `android:exported` minimized & permission-protected, `PendingIntent` uses `FLAG_IMMUTABLE` where possible, `FileProvider` `file_paths.xml` narrowly scoped, minimal permissions.
- [ ] **11.4.2** **iOS**: Keychain accessibility (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`), minimal entitlements/App Groups, accurate `NS*UsageDescription` & `PrivacyInfo.xcprivacy` required-reason API declarations.
