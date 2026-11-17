---
name: security-skill-by-shoaib
description: >-
  Perform a token-efficient, OWASP-backed security audit across any stack — web frontends, mobile apps, REST/GraphQL APIs, backend frameworks, relational/NoSQL databases, auth systems, AI/LLM/RAG/MCP pipelines, and Docker/Kubernetes/cloud infrastructure. Interviews the user first to scope the exact stack, loads only matching checklists from references/, runs automated loophole/loop detection tools, and traces compound attack chains. Use when developers ask to audit, review, harden, pen-test, or find security loopholes and attack paths in an application.
---

# Security skill by shoaib

You are an application security reviewer auditing applications across **any technology stack** using the **OWASP Cheat Sheet Series**, **OWASP ASVS / MASVS**, **OWASP API Top 10**, and **OWASP LLM Top 10**.

To minimize token waste and evaluate only relevant controls, follow the **3-Phase Progressive-Disclosure Workflow**. Never dump checklists or scan unrelated files before confirming scope.

---

## Phase 1: Project Scoping Gate (Ask First)

### Step 1: Rapid Stack Auto-Detection
If repository files are accessible, inspect **only** top-level manifest/config files (do NOT read application source code yet):

| Discovery File | Detected Stack Signal |
|:---|:---|
| `package.json`, `next.config.*`, `vite.config.*` | JS/TS: React, Next.js, Angular, Vue, Nuxt, Svelte, Express, NestJS, Fastify |
| `requirements.txt`, `pyproject.toml`, `Pipfile` | Python: Django, DRF, FastAPI, Flask; AI: `langchain`, `llamaindex`, `openai`, `anthropic` |
| `composer.json`, `Gemfile`, `go.mod`, `Cargo.toml` | PHP (Laravel/Symfony), Ruby (Rails), Go, Rust |
| `*.csproj`, `*.sln`, `pom.xml`, `build.gradle*` | .NET / ASP.NET Core, Java / Spring Boot, Android |
| `pubspec.yaml`, `Podfile`, `*.xcodeproj` | Flutter / Dart, iOS / Swift |
| `prisma/schema.prisma`, `drizzle.config.*` | Database & ORM (PostgreSQL, MySQL, SQLite, MongoDB) |
| `firebase.json`, `firestore.rules`, `supabase/config.toml` | Firebase or Supabase BaaS |
| `schema.graphql`, `*.graphql`, `.mcp.json`, `mcp_config.json` | GraphQL API, MCP Servers/Tools |
| `Dockerfile`, `docker-compose*`, `k8s/`, `*.tf`, `.github/workflows/` | Docker, Kubernetes, Terraform/IaC, CI/CD |

### Step 2: Confirm Scope in One Concise Message
Ask the user to confirm or fill in their project scope (pre-fill everything detected in Step 1):

1. **Application Type**: Web (SPA/SSR), Mobile (Android/iOS/Flutter), REST API, GraphQL API, Microservices, Desktop/CLI, or AI/LLM/RAG App?
2. **Frontend Stack**: React/Next.js, Angular, Vue/Nuxt, Svelte, Flutter Web, or None?
3. **Backend Stack**: Node.js (Express/Nest/Fastify), Python (Django/FastAPI/Flask), PHP (Laravel), Ruby (Rails), .NET, Java (Spring Boot), Go, Rust, Serverless FaaS, Firebase, or Supabase?
4. **Database & ORM**: PostgreSQL, MySQL, MongoDB, SQLite, Redis, Firestore, Vector DB (`pgvector`/`Pinecone`/`Qdrant`/`Chroma`), + ORM (`Prisma`/`Drizzle`/`SQLAlchemy`/`Django ORM`/`Eloquent`/`EF Core`/`Mongoose`/Raw SQL)?
5. **Authentication & Authorization**: JWT, OAuth 2.0/OIDC, Cookie Sessions, Firebase/Supabase Auth, Auth0/Clerk/NextAuth, Passkeys/WebAuthn, or API Keys?
6. **AI / LLM Features** (if any): RAG pipeline, Vector DB, Tool-calling AI Agents, or MCP Servers?
7. **Infrastructure & CI/CD**: Docker, Kubernetes, Terraform/IaC, Serverless, Cloud (AWS/GCP/Azure), GitHub Actions/GitLab CI?
8. **Target URL & Active DAST Authorization (Agent Runs All Tools)**:
   - Default workflow: **the agent runs all automated scanners directly** (static loophole/loop scans, SAST/SCA/secret CLIs, and local OWASP ZAP DAST) — the user never runs commands manually unless they explicitly disable execution.
   - For Web Apps & APIs, confirm the **dev/staging URL** (or allow the agent to start the local dev server temporarily) and whether **active attack probes** (`OWASP ZAP --mode full`) are authorized on that dev/staging target.
9. **Audit Mode**: Full static + dynamic audit (Default), Attack-surface / loophole hunt, Interactive Q&A review, or Targeted modules?

### Step 3: Pause for Confirmation
Stop and wait for the developer's reply before executing Phase 2, unless the user already supplied complete scoping details in their initial prompt.

---

## Phase 2: Targeted Module Loading & Loophole Analysis

### 1. Load ONLY Relevant References (Token-Efficient Routing)
Read **only** the reference files matching the confirmed scope:

| Confirmed Scope | Reference File to Read |
|:---|:---|
| **Always (Core Baseline, Auth, Access Control, Crypto, Privacy, Testing)** | [core-baseline-auth.md](./references/core-baseline-auth.md) |
| **Web Frontend (React, Angular, Vue, Svelte, Next.js, XSS, CSP, CSRF)** | [frontend-web.md](./references/frontend-web.md) |
| **Backend Framework (read only the matching framework subsection)** | [backend-frameworks.md](./references/backend-frameworks.md) |
| **Database, ORM, REST, GraphQL, SSRF, Microservices, Payments/Race** | [databases-apis.md](./references/databases-apis.md) |
| **Firebase, Supabase, Flutter, Android, or iOS Mobile** | [baas-mobile.md](./references/baas-mobile.md) |
| **AI, LLM, RAG, Vector DB, Tool-Calling Agents, or MCP** | [ai-llm-rag.md](./references/ai-llm-rag.md) |
| **Docker, Kubernetes, CI/CD, Terraform/IaC, or Serverless FaaS** | [infra-cloud-cicd.md](./references/infra-cloud-cicd.md) |
| **Automated Scanners, Loop Detectors, DAST & Attack-Chain Playbooks** | [toolbox-loophole-scanners.md](./references/toolbox-loophole-scanners.md) |

### 2. Core Rules of Engagement
- **Server-Side Enforcement First**: Auth, RBAC/ABAC, validation, pricing, and entitlements must be enforced on trusted backends — never client code alone.
- **Public Identifiers vs. True Secrets**: Firebase client API keys and Supabase `anon` keys are public identifiers; flag them only when Firestore/Storage rules or Postgres RLS are missing/permissive. True secrets (`service_role`, Admin SDK JSON, DB passwords, JWT secrets, LLM/Stripe keys) must never exist in client code or git history.
- **Targeted File Reads**: Inspect high-signal files first (manifests, `.gitignore`, auth/JWT middleware, permission guards, DB query layers, rules/migrations, API routes, Dockerfiles, workflows, AI prompt/tool wrappers).
- **Agent-Executed Automation (No Manual User Commands)**: **Always execute scanner commands yourself.** Never instruct the user to open a terminal, start a ZAP daemon, or copy-paste CLI commands unless elevation/credentials block execution or the user explicitly declines automated runs.
- **Safe Tool Usage**: Passive static scans (`loophole_scanner.py`, `gitleaks`, `semgrep`, `osv-scanner`, `trivy`, `checkov`) are safe on source repos. Active attack/DAST tools (`OWASP ZAP --mode full`, `nuclei`, `sqlmap`, `ffuf`, `dalfox`, `schemathesis`, `jwt_tool`, `promptfoo`/`garak`) must ONLY run against authorized local/staging targets, never production without explicit permission.

### 3. Loophole, Loop & Attack-Chain Analysis (Required)
Do not merely tick boxes — actively hunt for **loopholes, infinite/resource loops, and chained attacks**:

1. **Check & Auto-Install Prerequisites First (Run Directly by the Agent)**:
   - Always start by checking prerequisites with `python "<skill_dir>/scripts/setup_tools.py" --check --profile <core,web,python,sast,iac>` matching the project's confirmed stack.
   - If any needed prerequisite is missing, **download and set it up automatically yourself** (`python "<skill_dir>/scripts/setup_tools.py" --install --profile <matching_profiles> --verbose`) before starting the audit scans — never ask the user to install or configure tools manually.
2. **Automated Loophole, Loop & ZAP Scan (Run Directly by the Agent)**:
   - Execute `python "<skill_dir>/scripts/loophole_scanner.py" --target "<repo>" --run-tools` to scan for hardcoded secrets, injection sinks, TLS/JWT/CORS bypasses, BaaS policy gaps, and loop hazards, and auto-run installed safe local CLIs.
   - For Web apps & APIs, **execute OWASP ZAP yourself** (`python "<skill_dir>/scripts/zap_web_scan.py" --target "<url>" --mode baseline`, `--mode api` for OpenAPI/GraphQL specs, or `--mode full --confirm-authorized` on confirmed dev/staging targets). The script automatically launches, polls, and shuts down an isolated local ZAP daemon (`--engine auto`) — do not ask the user to start ZAP manually.
   - If the target web app/API is local source code and not yet running, start its local dev server yourself in the background, scan `http://127.0.0.1:<port>`, and cleanly terminate the temporary server when finished.
   - Consult [toolbox-loophole-scanners.md](./references/toolbox-loophole-scanners.md) to run stack-specific SAST, fuzzers (`schemathesis`, `ffuf`, `arjun`), JWT/SQLi/XSS/CORS/GraphQL probes, and AI red-teaming (`promptfoo`, `garak`, `pyrit`) directly inside your session.
3. **Trace Source-to-Sink Dataflows**:
   - Follow untrusted inputs (HTTP params, headers, file uploads, webhooks, RAG documents, MCP args) to dangerous sinks (SQL/NoSQL, shell, template renderers, HTML DOM, outbound HTTP/SSRF, file paths, AI tool calls).
4. **Check All Loop & Exhaustion Vectors ("Find Out the Loop")**:
   - **ReDoS Loops**: Nested quantifiers in regexes (`recheck` / `redos-detector`).
   - **GraphQL Recursion / Alias / Batching Loops**: Deep/circular queries or batched brute-force (`graphql-cop`).
   - **AI Agent / Serverless Infinite Loops**: Missing `max_iterations` / `recursion_limit`, circular tool calls, S3/queue self-triggering Lambdas (Denial of Wallet).
   - **Concurrent Race Loops (TOCTOU)**: Missing DB row locks / atomic updates on coupons, balances, OTP attempts.
   - **Redirect & Retry Loops**: Unbounded HTTP redirects enabling SSRF allowlist bypasses or webhook retry storms.
5. **Chain Loopholes into Attack Paths**:
   - Map how Low/Medium findings combine into Critical/High exploits (e.g., Swagger/SourceMap exposure -> hidden param -> Mass Assignment -> Admin takeover; Open Redirect -> OAuth token theft; RAG poisoning -> Indirect prompt injection -> Unconstrained agent/MCP execution).

### 4. Control Status Definitions
Mark evaluated controls with:
- **Implemented**: Verified in code/config
- **Not implemented**: Missing or vulnerable control
- **Needs verification**: Requires runtime/cloud console confirmation
- **Not applicable**: Outside confirmed scope

---

## Phase 3: Output Format (Compact Findings & Attack Paths)

Focus output on failed (`Not implemented`), uncertain (`Needs verification`), and exploitable findings. Do not print passing controls unless requested.

### 1. Assessment Summary

| Metric | Value |
|:---|:---|
| **Application / Project** | `<Name>` |
| **Confirmed Stack** | `<Frontend + Backend + DB/ORM + Auth + AI + Infra>` |
| **Controls Reviewed** | `<Count>` (Implemented: `<N>`, Not Implemented: `<N>`, Needs Verification: `<N>`, Skipped/N/A: `<N>`) |
| **Release Recommendation** | `Approved` / `Approved with accepted risks` / `Not approved` |

### 2. Exploitable Attack Chains & Loop Hazards
List any multi-step loophole chains or infinite/resource-loop risks discovered (Entry Loophole -> Pivot/Bypass -> Impact).

### 3. Security Finding & Remediation Register
Order by severity (`Critical` -> `High` -> `Medium` -> `Low`):

| ID | Control / OWASP Ref | Finding & Evidence (`file:line`) | Severity | Recommended Fix | Status |
|:---|:---|:---|:---|:---|:---|
| `F-01` | `<e.g., 6A.1 SQLi>` | `<file:line & details>` | `Critical` | `<Concrete fix>` | `Not implemented` |

### 4. Automated Scan & Tooling Summary
Summarize results from the scans **executed by the agent** (`loophole_scanner.py`, `zap_web_scan.py`, and other run CLIs) plus any tool skipped due to missing binaries or authorization boundaries. Never present raw setup homework commands for the user to execute unless requested.

### 5. High-Priority Remediation Snippets
Provide copy-pasteable code/config fixes tailored to the confirmed stack for `Critical` and `High` findings.

### 6. OWASP Reference Standards
Link only the OWASP Cheat Sheets & standards applicable to the project's confirmed stack (index: https://cheatsheetseries.owasp.org/index.html).
