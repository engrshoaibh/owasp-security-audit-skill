# Severity & Confidence Rubric

Use this rubric for every finding so ratings stay consistent between runs and between agents.
Scanner severities are defaults; adjust them after reading the code, and say why when you do.

## 1. Rate impact and exploitability

| Impact | Meaning |
|:---|:---|
| **Severe** | Remote code execution, full auth bypass, account takeover at scale, read/write of other tenants' data, leaked production credentials with broad scope |
| **Major** | Access to another user's data (IDOR/BOLA), privilege escalation, stored XSS on an authenticated page, SSRF to internal services or cloud metadata |
| **Moderate** | Limited data exposure, reflected XSS, CSRF on a state-changing action, DoS of one component, missing hardening that enables a Major issue |
| **Minor** | Defense-in-depth gaps, information disclosure with no direct exploit, best-practice deviations |

| Exploitability | Meaning |
|:---|:---|
| **Easy** | Unauthenticated, reachable from the internet, no user interaction, public technique |
| **Moderate** | Needs a normal user account, or one user interaction, or a known precondition |
| **Hard** | Needs admin rights, an internal network position, a race window, or several unlikely conditions |

## 2. Combine into severity

| Impact \ Exploitability | Easy | Moderate | Hard |
|:---|:---|:---|:---|
| **Severe** | Critical | Critical | High |
| **Major** | High | High | Medium |
| **Moderate** | Medium | Medium | Low |
| **Minor** | Low | Low | Low |

Adjustments:
- **Leaked live secret**: Critical if it grants production or billing access, High otherwise, until rotated.
  Rotation is required even after the secret is removed from code, because it stays in git history.
- **Non-production code** (tests, examples, docs, local-only scripts): lower one level unless it ships or runs in CI
  with secrets.
- **Compensating control verified** (WAF rule, network isolation, framework auto-escaping): lower one level and name
  the control.
- **Chained finding**: rate the whole chain by its end impact and reference the individual findings.
- Optionally add a CVSS v4.0 vector for Critical and High findings when the user needs one for compliance.

## 3. Confidence

| Confidence | Use when |
|:---|:---|
| **high** | You traced the input from a reachable entry point to the sink, or the pattern is unambiguous (a committed private key) |
| **medium** | The dangerous pattern is real, but you could not confirm the input is attacker-controlled or the path is reachable |
| **low** | A heuristic hit you could not verify, or a likely false positive kept for the user's review |

Report **low** confidence items in a separate "Needs review" list, not in the main register.

## 4. Release verdict

| Verdict | Rule |
|:---|:---|
| **Not approved** | Any Critical, or any High with high confidence that is reachable in production |
| **Approved with accepted risks** | Only High with medium/low confidence, or Medium and below, each with an owner or a documented acceptance |
| **Approved** | No findings above Low, and Steps 3 and 4 ran with no tool errors |

If a step was skipped (no DAST, tools missing), say so next to the verdict. A verdict is never stronger than the
coverage behind it.
