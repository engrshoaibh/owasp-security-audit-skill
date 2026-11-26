# Access Control Review: IDOR / BOLA / BFLA Procedure

> OWASP Top 10:2025 A01 · API Top 10:2023 API1 (BOLA), API3 (BOPLA), API5 (BFLA) ·
> Cheat sheets: [Authorization](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html),
> [IDOR Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html)

Broken access control is the most common serious vulnerability class in real applications, and pattern-based
scanners almost never find it: the bug is a *missing* line, not a dangerous one. Run this procedure in Step 6 of every
full audit, and in a quick check whenever the changed code adds or edits a route, resolver, or data query.

Work through the steps in order and keep the inventory table as you go. It becomes evidence in the report.

---

## Step 1: Learn the authorization model (5 minutes)

Answer these from the code before reviewing any route:

- **Who are the actors?** Anonymous, user, org member, org admin, staff/superadmin, service accounts, API keys.
- **What owns what?** Which tables or collections have an owner column (`user_id`, `owner_id`, `tenant_id`,
  `org_id`, `account_id`)? Draw the ownership chain, e.g. `Org → Project → Document → Comment`.
- **Where is identity established?** Session middleware, JWT verification, API-key lookup. Note the variable that holds
  the trusted caller (`request.user`, `req.user`, `ctx.auth`, `current_user`, `auth.uid()`).
- **Is there a central policy layer?** Policy classes, `@PreAuthorize`, CASL, Pundit, OPA, Postgres RLS, Firebase
  rules. If yes, review the policies and confirm every route actually uses them. If no, every handler is suspect.

## Step 2: Build the endpoint inventory

List every entry point that reads or changes data. Find them with framework-specific searches:

| Framework | Search for |
|:---|:---|
| Express / Fastify / NestJS | `router.(get\|post\|put\|patch\|delete)`, `app.(get\|post…)`, `@Get(`, `@Post(`, `@Controller(` |
| Next.js | `app/**/route.ts`, `pages/api/**`, server actions (`"use server"`) |
| Django / DRF | `urls.py` `path(`, `ViewSet`, `APIView`, `@api_view` |
| FastAPI / Flask | `@app.(get\|post…)`, `@router.`, `@bp.route` |
| Rails | `config/routes.rb`, `resources :` |
| Laravel | `routes/*.php`, `Route::` |
| Spring | `@RequestMapping`, `@GetMapping`, `@PostMapping` |
| ASP.NET | `[Http(Get\|Post…)]`, `MapGet(` |
| GraphQL | resolvers for every `Query` / `Mutation` field, plus field resolvers on types that hold private data |
| Supabase / Firebase | tables and buckets reachable with the anon key; RLS policies and security rules |

For each, record:

| Route / resolver | Auth required? | Object id inputs | Object type | Owner / tenant check | Role check | Verdict |
|:---|:---|:---|:---|:---|:---|:---|
| `GET /api/invoices/:id` | yes | `id` (path) | Invoice | ❌ none | n/a | **IDOR** |

"Object id inputs" includes path params, query params, body fields, headers, GraphQL arguments, *and ids nested in
the body* (`{"items":[{"order_id":…}]}`), file names, and ids taken from LLM tool-call arguments.

## Step 3: Check each object access (BOLA / IDOR, API1)

For every row with an object id input, trace from the input to the database query and confirm one of these holds:

1. **Scoped query**: the lookup itself includes the caller.
   `Invoice.objects.get(id=id, owner=request.user)` · `where: { id, userId: session.user.id }` ·
   `current_user.invoices.find(params[:id])`
2. **Explicit check after fetch, before use**: `if invoice.owner_id != user.id: raise 403/404`, done *before* the
   object is returned, modified, or used to derive other data.
3. **Enforced policy**: a policy/guard that loads the object and checks ownership, and is applied to this route
   (not only declared somewhere).
4. **Database-level enforcement**: Postgres RLS / Firebase rules that filter by the caller, and the query runs with the
   caller's identity (not a service-role key).

Red flags (each one is a likely finding):
- `findById(req.params.id)`, `get_object_or_404(Model, pk=pk)`, `Model.find(params[:id])` with no owner filter.
- Owner check present on `GET` but missing on `PUT` / `PATCH` / `DELETE` / export / download of the same object.
- The owner id comes from the request (`req.body.userId`, `?user_id=`, a JWT claim the client can set, or an LLM tool
  argument) instead of the verified session.
- Checks that compare against `tenant_id` from the request body or a header like `X-Tenant-Id` without verifying
  membership.
- Bulk endpoints (`ids=[1,2,3]`, GraphQL lists, CSV export) that check only the first id or none.
- Nested resources that check the parent but not the child: `/projects/:pid/docs/:did` verifies access to `pid` but
  loads `did` without confirming it belongs to `pid`.
- Supabase: tables without RLS, policies `using (true)`, or server code using the `service_role` key for user requests.
- Sequential or guessable ids make exploitation easier, but **UUIDs are not access control**. Rate the missing check,
  not the id format.

## Step 4: Check field-level access (BOPLA, API3)

- **Reads**: responses serialize whole models (`res.json(user)`, `model_to_dict`, `fields = "__all__"`) and leak
  `password_hash`, `role`, `email`, `stripe_customer_id`, other users' PII, or internal flags.
- **Writes**: update handlers bind the whole body (`Object.assign(user, req.body)`, `User.update(req.body)`,
  `$request->all()`, `params.permit!`) so a user can set `role`, `is_admin`, `owner_id`, `tenant_id`, `balance`,
  `email_verified`. Scanner rule `MASS-01` catches some of these.

## Step 5: Check function-level access (BFLA, API5)

- Admin and staff routes (`/admin`, `/internal`, `/api/v1/users/:id/role`, feature flags, impersonation, refunds)
  enforce a role check on the server, not only by hiding UI.
- The same handler is not reachable through a second path without the check (`/api/admin/users` vs `/api/users?all=1`,
  old API versions, GraphQL mutations that mirror REST admin endpoints).
- HTTP method confusion: `GET` allowed where only `POST` with CSRF protection was intended; `X-HTTP-Method-Override`
  honored.
- Server actions / RPC functions (Next.js `"use server"`, Supabase `rpc()`, Firebase callable functions) check the
  caller themselves. They are public endpoints.

## Step 6: Check business flows and multi-step state (API6)

- Steps can't be skipped or replayed: checkout without payment, password reset without the token, invite acceptance
  for a different email, approving your own request.
- Limits are enforced atomically on the server (coupon single-use, seat counts, credits). See `databases-apis.md`
  Module 17 for race conditions.

## Step 7: Verify dynamically when a running instance is authorized

With two test accounts (A and B) in different tenants on a local/staging instance:
1. As A, create an object and note its id.
2. As B, request it with every method the route supports (`GET`, `PUT`, `PATCH`, `DELETE`, export).
3. Expected: 403 or 404 every time. Anything else is a confirmed finding (confidence: high).
4. Repeat as anonymous, and as a low-role user against admin routes.

Tools that help: Burp Autorize / AuthMatrix, ZAP Access Control add-on, or a short script with two sessions.
Never do this against production or other people's data.

## Reporting

- Tag findings `A01:2025` plus `API1:2023` (object), `API3:2023` (property) or `API5:2023` (function), with CWE-639
  (IDOR), CWE-862 (missing authorization) or CWE-863 (incorrect authorization).
- Evidence = the route, the input, the query line, and the missing check. Example:
  "`GET /api/invoices/:id` (`routes/invoices.js:14`) passes `req.params.id` to `Invoice.findById` (`:18`) with no
  owner filter; any logged-in user can read any invoice."
- Severity: usually **High** (another user's data, needs an account) or **Critical** (unauthenticated, cross-tenant
  at scale, or write/delete access). Use [severity-rubric.md](./severity-rubric.md).
- Fix: show the scoped query or policy call in the project's own framework, and recommend a test that requests
  another user's object and expects 403/404.
- Include the inventory table (or the rows with problems) in the report so the reviewer can see what was covered.
