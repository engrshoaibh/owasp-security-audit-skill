# OWASP Category Mapping

Use these ids in the `owasp` field of every finding. Pick the most specific category from each list that applies
(a GraphQL IDOR is `A01:2025` and `API1:2023`; a prompt injection that triggers a tool call is `LLM01:2025` and
`LLM06:2025`).

## OWASP Top 10:2025 (web applications)

| Id | Category | Where checked in this skill | Scanner rules |
|:---|:---|:---|:---|
| A01:2025 | Broken Access Control (includes SSRF) | core-baseline-auth Module 3, databases-apis Modules 7 & 14, baas-mobile 8–9 | MASS-01, PATH-01, REDIR-01, SSRF-01, BAAS-01/02 |
| A02:2025 | Security Misconfiguration | frontend-web 4.2–4.4, backend-frameworks, infra-cloud-cicd | CORS-01, DBG-01, COOKIE-01, XXE-01, DOCKER-02, GIT-01..04 |
| A03:2025 | Software Supply Chain Failures | core-baseline-auth 1.6, infra-cloud-cicd 12C, Step 4 (SCA) | GHA-01/02/03, DOCKER-01, LLM-01 |
| A04:2025 | Cryptographic Failures | core-baseline-auth 1.1, Module 15 | SEC-02, TLS-01, CRYPTO-01/02/03 |
| A05:2025 | Injection (SQL, NoSQL, OS, template, XSS) | core-baseline-auth 1.2, frontend-web 4.1, databases-apis Module 6 | INJ-01/02/03, SSTI-01, XSS-01, NOSQL-01 |
| A06:2025 | Insecure Design | databases-apis Module 17 (business logic, races), threat modelling | LOOP-01 |
| A07:2025 | Authentication Failures | core-baseline-auth Module 2 | SEC-01/03/04/05, JWT-01 |
| A08:2025 | Software or Data Integrity Failures | core-baseline-auth (deserialization), infra-cloud-cicd 12C | DESER-01, LLM-02 |
| A09:2025 | Security Logging and Alerting Failures | core-baseline-auth 1.4 | manual review |
| A10:2025 | Mishandling of Exceptional Conditions | core-baseline-auth 1.3 & 1.7 (fail-open error paths, unhandled exceptions, resource cleanup) | LOOP-03 |

## OWASP API Security Top 10:2023

| Id | Category | Where checked |
|:---|:---|:---|
| API1:2023 | Broken Object Level Authorization (BOLA / IDOR) | access-control-review.md; core-baseline-auth Module 3 |
| API2:2023 | Broken Authentication | core-baseline-auth Module 2 |
| API3:2023 | Broken Object Property Level Authorization (mass assignment, excessive data exposure) | databases-apis 7A, core-baseline-auth Module 3 |
| API4:2023 | Unrestricted Resource Consumption (rate limits, pagination, GraphQL depth, ReDoS) | databases-apis 7A/7B, toolbox 19.4 |
| API5:2023 | Broken Function Level Authorization (admin routes, HTTP verb tampering) | access-control-review.md Step 5; core-baseline-auth Module 3 |
| API6:2023 | Unrestricted Access to Sensitive Business Flows (bots, scalping, coupon abuse) | databases-apis Module 17 |
| API7:2023 | Server Side Request Forgery | databases-apis Module 14 |
| API8:2023 | Security Misconfiguration (CORS, verbose errors, missing headers) | frontend-web 4.3–4.4, backend-frameworks |
| API9:2023 | Improper Inventory Management (old versions, shadow/debug endpoints, exposed docs) | databases-apis 7A |
| API10:2023 | Unsafe Consumption of APIs (trusting third-party responses, webhooks) | databases-apis Modules 7 & 13 |

## OWASP Top 10 for LLM Applications 2025

| Id | Category | Where checked |
|:---|:---|:---|
| LLM01:2025 | Prompt Injection (direct and indirect) | ai-llm-rag 10.1 |
| LLM02:2025 | Sensitive Information Disclosure | ai-llm-rag 10.2.3, 10.5 |
| LLM03:2025 | Supply Chain (models, datasets, plugins, adapters) | ai-llm-rag 10.6 |
| LLM04:2025 | Data and Model Poisoning | ai-llm-rag 10.2.2, 10.2.5, 10.6 |
| LLM05:2025 | Improper Output Handling | ai-llm-rag 10.5.1 |
| LLM06:2025 | Excessive Agency | ai-llm-rag 10.3, 10.4 |
| LLM07:2025 | System Prompt Leakage | ai-llm-rag 10.1.4 |
| LLM08:2025 | Vector and Embedding Weaknesses | ai-llm-rag 10.2 |
| LLM09:2025 | Misinformation (ungrounded output used for decisions) | ai-llm-rag 10.7 |
| LLM10:2025 | Unbounded Consumption (denial of wallet, runaway loops) | ai-llm-rag 10.3.4 |

## Common CWE quick reference

| CWE | Weakness |
|:---|:---|
| CWE-22 | Path traversal |
| CWE-78 | OS command injection |
| CWE-79 | Cross-site scripting |
| CWE-89 | SQL injection |
| CWE-200 | Exposure of sensitive information |
| CWE-284 / 285 / 639 | Improper access control / authorization / IDOR |
| CWE-287 | Improper authentication |
| CWE-295 | Improper certificate validation |
| CWE-327 / 328 / 338 | Broken crypto / weak hash / weak RNG |
| CWE-352 | CSRF |
| CWE-502 | Deserialization of untrusted data |
| CWE-601 | Open redirect |
| CWE-611 | XXE |
| CWE-770 | Allocation of resources without limits |
| CWE-798 | Hardcoded credentials |
| CWE-918 | SSRF |
| CWE-1333 | ReDoS |
| CWE-1336 | Template injection |
| CWE-1427 | Improper neutralization of input used for LLM prompting (prompt injection) |
