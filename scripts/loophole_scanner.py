#!/usr/bin/env python3
"""
Cross-platform static loophole, loop-hazard, and security-tool discovery scanner.
Uses only the Python standard library so it works anywhere (Windows, macOS, Linux).

Every finding carries a severity, a confidence level, a CWE id and its OWASP
mappings (Top 10:2025, API Security Top 10:2023, LLM Top 10:2025). Secret values
are masked before they are printed, so reports are safe to paste or share.

Usage:
  python scripts/loophole_scanner.py --target .
  python scripts/loophole_scanner.py --target . --format json
  python scripts/loophole_scanner.py --target . --format sarif > results.sarif
  python scripts/loophole_scanner.py --target . --fail-on high
  python scripts/loophole_scanner.py --target . --write-baseline .security-skill-baseline.json
  python scripts/loophole_scanner.py --target . --run-tools

Suppress a reviewed false positive with a comment on the same line or the line above:
  # security-skill: ignore[INJ-02]   (one or more rule ids, comma separated)
  # security-skill: ignore           (all rules on that line)
Skip a whole file (e.g. intentionally vulnerable test fixtures) with this marker in its first 5 lines:
  # security-skill: ignore-file
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Iterable

SCANNER_NAME = "owasp-security-audit-skill/loophole_scanner"
SCANNER_VERSION = "2.0.0"
REPORT_SCHEMA_VERSION = "1.0"
DEFAULT_BASELINE = ".security-skill-baseline.json"

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "vendor", "venv", ".venv", "env",
    "__pycache__", ".pytest_cache", ".mypy_cache", "dist", "build", "out",
    ".next", ".nuxt", "target", "bin", "obj", ".dart_tool", ".gradle", "Pods",
    "coverage",
}

SCAN_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".php", ".rb", ".java", ".kt", ".cs", ".go", ".rs",
    ".dart", ".swift", ".sql", ".rules", ".yaml", ".yml",
    ".json", ".toml", ".env", ".tf", ".tfvars", ".xml", ".html",
    ".sh", ".ps1", ".ejs", ".hbs", ".j2", ".jinja",
}

MAX_FILE_BYTES = 512 * 1024  # Skip huge/minified bundles

SEVERITIES = ("Critical", "High", "Medium", "Low")
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}
SARIF_SECURITY_SEVERITY = {"Critical": "9.5", "High": "8.0", "Medium": "5.5", "Low": "3.0"}
SARIF_LEVEL = {"Critical": "error", "High": "error", "Medium": "warning", "Low": "note"}

# Path segments / file names that indicate tests, fixtures, docs or examples.
# Findings there are usually not reachable in production, so severity drops one level.
NON_PROD_DIRS = {
    "test", "tests", "__tests__", "spec", "specs", "fixture", "fixtures",
    "example", "examples", "sample", "samples", "docs", "doc", "testdata",
    "mock", "mocks", "__mocks__", "e2e", "cypress", "playwright",
}
NON_PROD_FILE_GLOBS = (
    "test_*.py", "*_test.py", "*_test.go", "*.test.*", "*.spec.*", "*Test.java",
    "*Tests.cs", "*_spec.rb", "conftest.py",
)

IGNORE_FILE_RE = re.compile(r"security-skill:\s*ignore-file\b", re.IGNORECASE)
SUPPRESS_RE = re.compile(r"security-skill:\s*ignore(?!-file)(?:\[([A-Za-z0-9_,\s-]+)\])?", re.IGNORECASE)
COMMENT_LINE = re.compile(r"^\s*(?:#|//|/\*|\*|<!--)")


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    confidence: str
    cwe: str
    owasp: list[str]
    module: str
    file: str
    line: int
    snippet: str
    remediation: str
    context: str = "code"  # "code" or "non-production" (tests, examples, docs)
    fingerprint: str = ""


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    severity: str
    confidence: str  # "high" | "medium" | "low": how likely a match is a real issue
    cwe: str
    owasp: tuple[str, ...]  # Top 10:2025 (A0x), API Top 10:2023 (APIx), LLM Top 10:2025 (LLM0x)
    module: str
    pattern: re.Pattern[str]
    remediation: str
    extensions: tuple[str, ...] | None = None
    path_globs: tuple[str, ...] | None = None  # restrict to paths matching any glob
    masked: bool = False  # mask the matched value in snippets


RULES: list[Rule] = [
    # --- Hardcoded Secrets & Key Leaks ---
    Rule(
        "SEC-01", "Potential AWS Access Key ID hardcoded", "Critical", "high", "CWE-798",
        ("A07:2025", "A04:2025"), "1.5 Secrets Management",
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        "Revoke the key now, purge it from git history, and load credentials via IAM roles or a secrets manager.",
        masked=True,
    ),
    Rule(
        "SEC-02", "Private key material committed in file", "Critical", "high", "CWE-321",
        ("A04:2025",), "1.5 Secrets Management",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"),
        "Remove the key from the repo and history, rotate it, and add *.pem / *.key to .gitignore.",
    ),
    Rule(
        "SEC-03", "Potential live LLM / Stripe / GitHub / Slack / Google API key hardcoded", "Critical", "high",
        "CWE-798", ("A07:2025", "LLM02:2025"), "1.5 / 10.5.3 Secrets",
        re.compile(
            r"\b(?:sk-proj-[A-Za-z0-9_-]{20,}|sk-ant-[A-Za-z0-9_-]{20,}|sk_live_[A-Za-z0-9]{16,}|rk_live_[A-Za-z0-9]{16,}"
            r"|ghp_[A-Za-z0-9]{30,}|gho_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|xox[abpr]-[A-Za-z0-9-]{10,}"
            r"|AIza[0-9A-Za-z_-]{35})"
        ),
        "Move API keys to server-side env / secrets manager and rotate exposed keys. (AIza Firebase client keys "
        "are public by design but need GCP API restrictions and strict Security Rules.)",
        masked=True,
    ),
    Rule(
        "SEC-04", "Hardcoded DB connection string with embedded credentials", "High", "medium", "CWE-798",
        ("A07:2025",), "1.5 / 6 Database",
        re.compile(r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss|amqp)://[^:\s'\"`/]+:[^@\s'\"`${}]+@[^\s'\"`]+"),
        "Move database credentials out of source files into a secret manager / runtime environment variables.",
        masked=True,
    ),
    Rule(
        "SEC-05", "Hardcoded fallback JWT / session secret", "High", "high", "CWE-1188",
        ("A02:2025", "A07:2025"), "2.3 JWT / Session",
        re.compile(r"(?:JWT_SECRET|SESSION_SECRET|APP_KEY|SECRET_KEY)\s*(?:=[^#\n]*)?(?:\|\||\?\?|\bor\b)\s*['\"][^'\"]{3,}['\"]", re.IGNORECASE),
        "Fail closed on startup if the signing secret env var is unset; never fall back to a hardcoded default.",
    ),
    # --- TLS / Auth / Config ---
    Rule(
        "TLS-01", "TLS certificate verification disabled", "High", "high", "CWE-295",
        ("A04:2025", "API10:2023"), "1.1.4 / 11.2.1 TLS",
        re.compile(r"(?:NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0|rejectUnauthorized\s*:\s*false|\bverify\s*=\s*False\b|InsecureSkipVerify\s*:\s*true|badCertificateCallback\s*=\s*\([^)]*\)\s*=>\s*true|CERT_NONE\b)"),
        "Remove TLS verification bypasses from production code; fix certificate trust (custom CA bundle) instead.",
    ),
    Rule(
        "JWT-01", "JWT decoded without verification or 'none' algorithm permitted", "Critical", "high", "CWE-347",
        ("A07:2025", "API2:2023"), "2.3.1 JWT Security",
        re.compile(r"(?:algorithms\s*[:=]\s*\[[^\]]*['\"]none['\"]|verify_signature['\"]?\s*:\s*False|jwt\.decode\([^)]*verify\s*=\s*False|jwt\.decode\s*\(\s*[^,)]+\s*\)\s*(?:;|$))"),
        "Pin secure algorithms (e.g. ['RS256']) and verify JWT signatures and claims (exp, aud, iss) on every request. "
        "In Node, use jwt.verify(), not jwt.decode(), for authentication decisions.",
    ),
    Rule(
        "CORS-01", "Permissive wildcard / reflected CORS with credentials enabled", "High", "medium", "CWE-942",
        ("A02:2025", "API8:2023"), "4.3.3 CORS",
        re.compile(r"(?:allow_origins\s*=\s*\[\s*['\"]\*['\"]\s*\].*allow_credentials\s*=\s*True|origin\s*:\s*(?:true|['\"]\*['\"]).*credentials\s*:\s*true|CORS_ALLOW_ALL_ORIGINS\s*=\s*True)"),
        "Replace wildcard / reflected origins with an explicit allowlist when credentials are enabled.",
    ),
    Rule(
        "DBG-01", "Debug mode enabled in code/config", "Medium", "medium", "CWE-489",
        ("A02:2025", "API8:2023"), "1.3.3 / 5 Config",
        re.compile(r"(?:^\s*(?:DEBUG\s*=\s*True|APP_DEBUG\s*=\s*true)\b|\bapp\.run\([^)]*debug\s*=\s*True)"),
        "Ensure DEBUG=False / APP_DEBUG=false in production and load it from environment config.",
    ),
    Rule(
        "COOKIE-01", "Session/auth cookie without Secure or HttpOnly flag", "Medium", "medium", "CWE-614",
        ("A02:2025", "A07:2025"), "2.2 Session Management",
        re.compile(r"(?:(?i:cookie|session)[^\n]*\b(?:httpOnly|secure)\s*[:=]\s*(?:false|False)\b|SESSION_COOKIE_(?:SECURE|HTTPONLY)\s*=\s*False|CSRF_COOKIE_SECURE\s*=\s*False)"),
        "Set Secure, HttpOnly and SameSite=Lax/Strict on session and auth cookies in production.",
    ),
    # --- Injection & RCE ---
    Rule(
        "INJ-01", "SQL built with string interpolation / raw unsafe query", "High", "medium", "CWE-89",
        ("A05:2025",), "1.2.2 / 6A.1 SQLi",
        re.compile(r"(?:\.(?:query|execute|executemany|raw|whereRaw|orderByRaw|FromSqlRaw|ExecuteSqlRaw)\s*\(\s*(?:f['\"]|`[^`]*\$\{|['\"][^'\"]*['\"]\s*(?:\+|%\s*[(\w])|['\"][^'\"]*['\"]\s*\.format\s*\()|\$queryRawUnsafe|\$executeRawUnsafe)"),
        "Use parameterized queries / prepared statements ($1, ?, :param) or tagged-template Prisma.$queryRaw.",
    ),
    Rule(
        "INJ-02", "OS command injection risk (shell=True / exec / system)", "High", "medium", "CWE-78",
        ("A05:2025",), "1.2.3 Command Injection",
        re.compile(r"(?:subprocess\.\w+\([^)]*shell\s*=\s*True|\bchild_process\.exec(?:Sync)?\s*\(|(?<![\w.])execSync\s*\(\s*`[^`]*\$\{|\bos\.system\s*\(|\bos\.popen\s*\(|\bshell_exec\s*\(|\bpassthru\s*\(|Runtime\.getRuntime\(\)\.exec\s*\()"),
        "Avoid shells: use subprocess.run([...], shell=False) / execFile() with allowlisted arguments.",
    ),
    Rule(
        "INJ-03", "Dynamic code execution (eval / new Function)", "High", "medium", "CWE-95",
        ("A05:2025",), "1.2.9 RCE",
        # (?<![\w.]) excludes method calls such as PyTorch model.eval() and ast.literal_eval()
        re.compile(r"(?:(?<![\w.$])eval\s*\(\s*(?!\s*\))|\bnew\s+Function\s*\(|(?<![\w.])exec\s*\(\s*(?:request|req|input|data|code|payload|body|user)\b)"),
        "Never pass external strings to eval()/exec()/new Function(); use a parser or an allowlisted dispatch table.",
    ),
    Rule(
        "DESER-01", "Unsafe deserialization of potentially untrusted data", "High", "medium", "CWE-502",
        ("A08:2025",), "1.2.9 Deserialization",
        re.compile(r"(?:\bpickle\.loads?\s*\(|\bcPickle\.loads?\s*\(|\bdill\.loads?\s*\(|\byaml\.load\s*\((?![^)]*SafeLoader)|\byaml\.unsafe_load\s*\(|\bunserialize\s*\(|\bObjectInputStream\s*\(|\bBinaryFormatter\b|\bMarshal\.load\s*\()"),
        "Use JSON / yaml.safe_load; never deserialize untrusted binary payloads with native object serializers.",
    ),
    Rule(
        "SSTI-01", "Server-side template built from a dynamic string (SSTI)", "High", "medium", "CWE-1336",
        ("A05:2025",), "1.2 Injection / 5 Templates",
        re.compile(r"(?:\brender_template_string\s*\(\s*(?!['\"])|\bjinja2\.Template\s*\(\s*(?!['\"])|\bEnvironment\([^)]*\)\.from_string\s*\(\s*(?!['\"])|\b(?:ejs|pug|handlebars|Handlebars|nunjucks)\.(?:render|compile|renderString)\s*\(\s*req\.)"),
        "Render fixed template files and pass user data only as context variables; never compile user-controlled templates.",
    ),
    Rule(
        "XSS-01", "Raw HTML injection / framework escape hatch", "High", "medium", "CWE-79",
        ("A05:2025",), "4.1.2 XSS Prevention",
        re.compile(r"(?:dangerouslySetInnerHTML|\bv-html\s*=|\bbypassSecurityTrust(?:Html|Script|ResourceUrl|Style|Url)|\{@html\b|\.(?:inner|outer)HTML\s*=(?!=)\s*(?!['\"`][^'\"`$]*['\"`]\s*;?\s*$)|document\.write\s*\(|\|\s*safe\b|\bmark_safe\s*\(|\bMarkup\s*\(\s*(?!['\"]))"),
        "Prefer framework auto-escaping; if HTML must be rendered, sanitize strictly with DOMPurify / bleach first.",
    ),
    Rule(
        "NOSQL-01", "MongoDB server-side JS ($where) or raw req.body in query", "High", "medium", "CWE-943",
        ("A05:2025", "API3:2023"), "6B NoSQL Injection",
        re.compile(r"(?:['\"]?\$where['\"]?\s*:|\.(?:find|findOne|findOneAndUpdate|findByIdAndUpdate|create|updateOne|updateMany|deleteMany)\(\s*req\.(?:body|query)\b)"),
        "Remove $where and validate/allowlist req.body fields with Zod/Joi (and cast types) before database queries.",
    ),
    Rule(
        "PATH-01", "File path built from request input (path traversal)", "High", "medium", "CWE-22",
        ("A01:2025", "API1:2023"), "1.2 Input Validation",
        re.compile(r"(?:\b(?:send_file|send_from_directory|open|FileResponse)\s*\(\s*(?:f['\"][^'\"]*\{)?\s*request\.|\bres\.(?:sendFile|download)\s*\([^)]*req\.(?:params|query|body)|\b(?:readFile|readFileSync|createReadStream|unlink|unlinkSync)\s*\([^)]*req\.(?:params|query|body)|path\.(?:join|resolve)\s*\([^)]*req\.(?:params|query|body)|\bfile_get_contents\s*\(\s*\$_(?:GET|POST|REQUEST))"),
        "Resolve the path, then verify it stays under an allowlisted base directory; prefer opaque IDs over file names.",
    ),
    Rule(
        "XXE-01", "XML parser with external entity expansion enabled (XXE)", "High", "high", "CWE-611",
        ("A02:2025",), "1.2 XML / XXE",
        re.compile(r"(?:resolve_entities\s*=\s*True|\bnoent\s*:\s*true|\bLIBXML_NOENT\b|setExpandEntityReferences\s*\(\s*true|libxml_disable_entity_loader\s*\(\s*false|XmlResolver\s*=\s*new\s+XmlUrlResolver)"),
        "Disable DTDs and external entities (e.g. defusedxml in Python, disallow-doctype-decl in Java).",
    ),
    Rule(
        "REDIR-01", "Open redirect to a request-controlled URL", "Medium", "medium", "CWE-601",
        ("A01:2025",), "4.6 Unvalidated Redirects",
        re.compile(r"(?:\bres\.redirect\s*\(\s*(?:\d+\s*,\s*)?req\.(?:query|body|params)|\bredirect\s*\(\s*request\.(?:args|GET|POST|query_params|form)|\bRedirectResponse\s*\(\s*(?:url\s*=\s*)?request\.query_params|header\s*\(\s*['\"]Location:\s*['\"]\s*\.\s*\$_(?:GET|POST|REQUEST))"),
        "Redirect only to relative paths or an allowlist of hosts; reject absolute and protocol-relative (//) URLs.",
    ),
    Rule(
        "MASS-01", "Potential mass assignment (whole request body bound to model)", "High", "medium", "CWE-915",
        ("A01:2025", "API3:2023"), "3.4 / 5D.1 Mass Assignment",
        re.compile(r"(?:\$request->all\s*\(|::create\s*\(\s*\$request->all|\.(?:create|update|build)\s*\(\s*req\.body\s*\)|Object\.assign\s*\(\s*\w+\s*,\s*req\.body\s*\)|\bparams\.permit!)"),
        "Bind only allowlisted fields ($request->validated(), $fillable, DTOs, strong params) and never role/owner fields.",
    ),
    # --- Cryptography ---
    Rule(
        "CRYPTO-01", "Weak hash (MD5/SHA-1) used for passwords", "High", "medium", "CWE-916",
        ("A04:2025", "A07:2025"), "2.1 Password Storage",
        re.compile(r"(?i:(?:\bmd5|\bsha1|hashlib\.(?:md5|sha1)|createHash\s*\(\s*['\"](?:md5|sha1)['\"]\s*\)|MessageDigest\.getInstance\s*\(\s*['\"](?:MD5|SHA-?1)['\"])[^\n]*pass(?:word|wd)?)"),
        "Store passwords with Argon2id, scrypt or bcrypt (or PBKDF2 with a high work factor), never fast hashes.",
    ),
    Rule(
        "CRYPTO-02", "Non-cryptographic RNG used for a security token", "Medium", "medium", "CWE-338",
        ("A04:2025",), "15 Cryptography",
        re.compile(r"(?i:(?:token|secret|password|passwd|otp|nonce|salt|session|api_?key|reset)\w*\s*[:=][^\n]*(?:Math\.random\s*\(|\brandom\.(?:random|randint|choice|choices|getrandbits)\s*\(|\brand\s*\(|\bmt_rand\s*\(|new\s+Random\s*\())"),
        "Use a CSPRNG: crypto.randomBytes / crypto.randomUUID, Python secrets, random_bytes(), SecureRandom.",
    ),
    Rule(
        "CRYPTO-03", "Broken cipher or mode (ECB / DES / RC4 / IV-less createCipher)", "Medium", "high", "CWE-327",
        ("A04:2025",), "15 Cryptography",
        re.compile(r"(?:\bMODE_ECB\b|AES/ECB|['\"](?:des|des-ede3?|rc4|aes-\d+-ecb)['\"]|\bcrypto\.createCipher\s*\(|\bDES\.new\s*\(|\bARC4\.new\s*\()"),
        "Use an AEAD cipher (AES-GCM or ChaCha20-Poly1305) with a unique random nonce per message.",
    ),
    # --- BaaS (Firebase / Supabase) ---
    Rule(
        "BAAS-01", "Permissive Firestore / Storage Security Rule (allow if true)", "Critical", "high", "CWE-284",
        ("A01:2025", "API1:2023"), "8.1 Firebase Rules",
        re.compile(r"allow\s+[\w,\s]+:\s*if\s+true\s*;"),
        "Deny by default and require authentication plus resource ownership / role validation.",
        extensions=(".rules",),
    ),
    Rule(
        "BAAS-02", "Supabase RLS policy referencing editable user_metadata", "Critical", "medium", "CWE-639",
        ("A01:2025",), "9.3 Supabase RLS",
        re.compile(r"(?:user_metadata|raw_user_meta_data)"),
        "Never authorize via user-editable user_metadata; use app_metadata or server-controlled role tables.",
        extensions=(".sql",),
    ),
    # --- AI / LLM / Agents ---
    Rule(
        "LLM-01", "Model loaded with trust_remote_code=True (arbitrary code from model hub)", "High", "high", "CWE-494",
        ("LLM03:2025", "A03:2025"), "10 AI Supply Chain",
        re.compile(r"\btrust_remote_code\s*=\s*True"),
        "Pin a reviewed model revision (revision=<commit sha>) or vendor the model code; avoid trust_remote_code.",
    ),
    Rule(
        "LLM-02", "Pickle-based model load without weights_only=True", "High", "medium", "CWE-502",
        ("LLM03:2025", "A08:2025"), "10 AI Supply Chain",
        re.compile(r"(?:\btorch\.load\s*\((?![^)]*weights_only\s*=\s*True)|\bjoblib\.load\s*\(|\bpd\.read_pickle\s*\()"),
        "Use torch.load(..., weights_only=True) or safetensors; only load pickled artifacts from trusted, verified sources.",
    ),
    Rule(
        "LLM-03", "Agent given code-execution / shell / unrestricted request tools", "High", "medium", "CWE-250",
        ("LLM06:2025", "LLM05:2025"), "10.3.1 Least-Privilege Tools",
        re.compile(r"(?:\bPythonREPLTool\b|\bPythonAstREPLTool\b|\bShellTool\s*\(|\bBashProcess\s*\(|allow_dangerous_code\s*=\s*True|allow_dangerous_requests\s*=\s*True|allow_dangerous_deserialization\s*=\s*True)"),
        "Remove dangerous tools or run them in an isolated sandbox with no secrets, and gate side effects behind human approval.",
    ),
    # --- CI/CD & Containers ---
    Rule(
        "GHA-02", "GitHub Actions script injection via untrusted event field", "High", "high", "CWE-78",
        ("A03:2025", "A05:2025"), "12C CI/CD Security",
        re.compile(r"\$\{\{\s*(?:github\.event\.(?:issue\.(?:title|body)|pull_request\.(?:title|body|head\.ref|head\.label)|comment\.body|review\.body|review_comment\.body|discussion\.(?:title|body)|head_commit\.(?:message|author\.(?:name|email))|commits\[?\S*\]?\.message|pages\[?\S*\]?\.page_name)|github\.head_ref)\s*\}\}"),
        "Pass untrusted values through env: (e.g. env: TITLE: ${{ github.event.issue.title }}) and use \"$TITLE\" in the script.",
        path_globs=(".github/workflows/*", ".github/actions/*", "*action.yml", "*action.yaml"),
    ),
    Rule(
        "GHA-03", "Third-party GitHub Action not pinned to a full commit SHA", "Low", "high", "CWE-829",
        ("A03:2025",), "12C CI/CD Security",
        re.compile(r"\buses:\s*['\"]?(?!actions/|github/|\./|docker://)[\w.-]+/[\w./-]+@(?![0-9a-f]{40}\b)[\w.-]+"),
        "Pin third-party actions to a full 40-character commit SHA and let Dependabot keep them updated.",
        path_globs=(".github/workflows/*", ".github/actions/*", "*action.yml", "*action.yaml"),
    ),
    # --- Loop & Resource Exhaustion Hazards ---
    Rule(
        "LOOP-01", "Potential ReDoS regex (nested quantifier)", "Medium", "low", "CWE-1333",
        ("A06:2025", "API4:2023"), "1.2.7 ReDoS Loop",
        re.compile(r"(?:re\.compile\s*\(|new\s+RegExp\s*\(|=\s*/).*\([^()]*[+*][^()]*\)[+*]"),
        "Rewrite without nested quantifiers (atomic/possessive groups or bounded checks) and verify with recheck.",
    ),
    Rule(
        "LOOP-02", "AI agent executor without explicit iteration / time cap nearby", "Medium", "medium", "CWE-770",
        ("LLM10:2025", "LLM06:2025", "API4:2023"), "10.3.4 Agent Loop",
        re.compile(r"\b(?:AgentExecutor|create_react_agent|initialize_agent)\s*\("),
        "Set max_iterations / recursion_limit and max_execution_time, plus per-user token and cost caps.",
    ),
    Rule(
        "LOOP-03", "Unbounded while(true) / while True loop: inspect exit conditions", "Low", "low", "CWE-835",
        ("A10:2025",), "1.2 / 10.3.4 Loop Check",
        re.compile(r"\bwhile\s*(?:\(\s*true\s*\)|True\s*:)"),
        "Ensure the loop has deterministic break conditions, max retry/iteration caps, timeouts, and backoff.",
    ),
    Rule(
        "SSRF-01", "Outbound HTTP request following redirects (SSRF / redirect loop)", "Medium", "low", "CWE-918",
        ("A01:2025", "API7:2023"), "14.5 SSRF / Redirect Loop",
        re.compile(r"(?:allow_redirects\s*=\s*True|maxRedirects\s*:\s*(?:[2-9]\d|[1-9]\d{2,})|follow_redirects\s*=\s*True)"),
        "Disable automatic redirects or re-validate every hop against domain and private-IP allowlists.",
    ),
]

RULES_BY_ID: dict[str, Rule] = {r.rule_id: r for r in RULES}

# Metadata for findings produced by whole-file / repo checks rather than line regexes.
FILE_CHECK_META: dict[str, dict] = {
    "GIT-01": {"title": "Missing .gitignore while sensitive files are present", "cwe": "CWE-538", "owasp": ["A02:2025"], "module": "1.5.2 Secrets Management"},
    "GIT-02": {"title": "Sensitive file present but not git-ignored", "cwe": "CWE-538", "owasp": ["A02:2025"], "module": "1.5.2 Secrets Management"},
    "GIT-03": {"title": "Sensitive file is tracked in git", "cwe": "CWE-540", "owasp": ["A02:2025", "A04:2025"], "module": "1.5.2 Secrets Management"},
    "GIT-04": {"title": ".env.example exists but .gitignore does not exclude .env", "cwe": "CWE-538", "owasp": ["A02:2025"], "module": "1.5.2 Secrets Management"},
    "GHA-01": {"title": "pull_request_target workflow checks out untrusted PR code", "cwe": "CWE-829", "owasp": ["A03:2025", "A08:2025"], "module": "12C CI/CD Security"},
    "DOCKER-01": {"title": "Container base image uses :latest or no tag", "cwe": "CWE-1357", "owasp": ["A03:2025"], "module": "12A Container Security"},
    "DOCKER-02": {"title": "Container runs as root (no non-root USER in final stage)", "cwe": "CWE-250", "owasp": ["A02:2025"], "module": "12A Container Security"},
}

SENSITIVE_FILE_GLOBS = (
    ".env", ".env.*", "*.pem", "*.key", "*.p12", "*.pfx", "*.jks", "*.keystore",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "*serviceAccount*.json",
    "*service-account*.json", "credentials.json", ".npmrc", ".pypirc",
)
SENSITIVE_FILE_ALLOW = (".env.example", ".env.sample", ".env.template", ".env.dist", ".env.defaults")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def redact_value(value: str) -> str:
    """Keep a short prefix (to identify the key type) and the last 2 characters."""
    if len(value) <= 8:
        return "*" * len(value)
    keep = 4 if len(value) < 20 else 6
    return f"{value[:keep]}{'*' * min(12, len(value) - keep - 2)}{value[-2:]}"


def mask_connection_string(value: str) -> str:
    return re.sub(r"(://[^:\s/]+:)([^@\s]+)(@)", lambda m: f"{m.group(1)}****{m.group(3)}", value)


MASKED_RULES = [r for r in RULES if r.masked]
RAW_VALUE_FIELD = re.compile(r"((?:\"Raw(?:V2)?\"|Raw result|RawV2|Secret|Match)\s*[:=]\s*\"?)([^\s\",]{6,})", re.IGNORECASE)


def redact_text(text: str) -> str:
    """Mask known secret shapes anywhere in free text (used for external tool output)."""
    for rule in MASKED_RULES:
        if rule.rule_id == "SEC-04":
            text = rule.pattern.sub(lambda m: mask_connection_string(m.group(0)), text)
        else:
            text = rule.pattern.sub(lambda m: redact_value(m.group(0)), text)
    return RAW_VALUE_FIELD.sub(lambda m: m.group(1) + redact_value(m.group(2)), text)


def is_non_production(rel_path: str) -> bool:
    parts = rel_path.lower().split("/")
    if any(p in NON_PROD_DIRS for p in parts[:-1]):
        return True
    name = rel_path.split("/")[-1]
    return any(fnmatch.fnmatch(name, g) for g in NON_PROD_FILE_GLOBS)


def downgrade(severity: str) -> str:
    idx = SEVERITY_RANK.get(severity, 3)
    return SEVERITIES[min(idx + 1, len(SEVERITIES) - 1)]


def suppressed_ids(line: str) -> set[str] | None:
    """Return None when the line has no suppression, an empty set to suppress all rules, or a set of rule ids."""
    m = SUPPRESS_RE.search(line)
    if not m:
        return None
    if not m.group(1):
        return set()
    return {x.strip().upper() for x in m.group(1).split(",") if x.strip()}


def is_suppressed(lines: list[str], idx: int, rule_id: str) -> bool:
    for candidate in (lines[idx - 1], lines[idx - 2] if idx >= 2 else ""):
        ids = suppressed_ids(candidate)
        if ids is not None and (not ids or rule_id in ids):
            return True
    return False


def fingerprint(rule_id: str, rel_path: str, snippet: str) -> str:
    # Line-number independent so a baseline survives unrelated edits above the finding.
    norm = re.sub(r"\s+", " ", snippet.strip())
    return hashlib.sha256(f"{rule_id}|{rel_path}|{norm}".encode("utf-8")).hexdigest()[:24]


def path_matches(rel_path: str, globs: tuple[str, ...]) -> bool:
    name = rel_path.split("/")[-1]
    return any(fnmatch.fnmatch(rel_path, g) or fnmatch.fnmatch(name, g) for g in globs)


def make_finding(rule_id: str, severity: str, confidence: str, rel: str, line: int, snippet: str,
                 remediation: str, title: str | None = None) -> Finding:
    rule = RULES_BY_ID.get(rule_id)
    meta = FILE_CHECK_META.get(rule_id, {})
    non_prod = is_non_production(rel)
    sev = severity
    conf = confidence
    if non_prod and not rule_id.startswith(("SEC-", "GIT-")):
        # Leaked secrets are real even in tests; everything else is usually unreachable in prod.
        sev = downgrade(severity)
        conf = "low"
    return Finding(
        rule_id=rule_id,
        title=title or (rule.title if rule else meta.get("title", rule_id)),
        severity=sev,
        confidence=conf,
        cwe=rule.cwe if rule else meta.get("cwe", ""),
        owasp=list(rule.owasp) if rule else list(meta.get("owasp", [])),
        module=rule.module if rule else meta.get("module", ""),
        file=rel,
        line=line,
        snippet=snippet,
        remediation=remediation,
        context="non-production" if non_prod else "code",
        fingerprint=fingerprint(rule_id, rel, snippet),
    )


# ---------------------------------------------------------------------------
# File walking & checks
# ---------------------------------------------------------------------------

def is_dockerfile(name: str) -> bool:
    return name == "Dockerfile" or name.startswith("Dockerfile.") or name.endswith(".dockerfile")


def iter_files(root: Path) -> Iterable[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            path = Path(dirpath) / fname
            ext = path.suffix.lower()
            if ext not in SCAN_EXTENSIONS and not fname.startswith(".env") and not is_dockerfile(fname):
                continue
            try:
                if path.stat().st_size > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            yield path


def _git(root: Path, *args: str) -> subprocess.CompletedProcess | None:
    git = shutil.which("git")
    if not git or not (root / ".git").exists():
        return None
    try:
        return subprocess.run([git, *args], cwd=root, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return None


def find_sensitive_files(root: Path) -> list[str]:
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            if fname in SENSITIVE_FILE_ALLOW:
                continue
            if any(fnmatch.fnmatch(fname, g) for g in SENSITIVE_FILE_GLOBS):
                found.append((Path(dirpath) / fname).relative_to(root).as_posix())
    return sorted(found)


def check_git_hygiene(root: Path) -> list[Finding]:
    """Flag secrets-bearing files that are tracked or not ignored. Silent when the repo is clean."""
    if not (root / ".git").exists():
        return []
    findings: list[Finding] = []
    sensitive = find_sensitive_files(root)

    tracked: set[str] = set()
    proc = _git(root, "ls-files", "-z")
    if proc and proc.returncode == 0:
        tracked = {p for p in proc.stdout.split("\0") if p}

    ignored: set[str] = set()
    if sensitive:
        proc = _git(root, "check-ignore", "--no-index", *sensitive)
        if proc and proc.returncode in (0, 1):
            ignored = {p.strip() for p in proc.stdout.splitlines() if p.strip()}

    for rel in sensitive:
        if rel in tracked:
            findings.append(make_finding(
                "GIT-03", "High", "high", rel, 0, f"{rel} is committed",
                "Remove the file with git rm --cached, purge it from history (git filter-repo), rotate any secrets it held, and git-ignore it.",
            ))
        elif rel not in ignored:
            findings.append(make_finding(
                "GIT-02", "Medium", "high", rel, 0, f"{rel} is not covered by .gitignore",
                "Add a matching pattern to .gitignore so the file cannot be committed by accident.",
            ))

    gitignore = root / ".gitignore"
    if not gitignore.exists() and findings:
        findings.append(make_finding(
            "GIT-01", "Medium", "high", ".gitignore", 0, "No .gitignore at project root",
            "Add a .gitignore excluding .env, *.key, *.pem, *.p12, *.jks, *.keystore and build artifacts.",
        ))
    elif gitignore.exists() and any((root / n).exists() for n in SENSITIVE_FILE_ALLOW):
        content = gitignore.read_text(encoding="utf-8", errors="ignore")
        if not re.search(r"^\s*/?\.env(?:\*|\.\*)?\s*$", content, re.MULTILINE):
            findings.append(make_finding(
                "GIT-04", "Low", "medium", ".gitignore", 0, ".env not listed in .gitignore",
                "The project uses .env files: add .env (and .env.*, with !.env.example) to .gitignore.",
            ))
    return findings


def check_workflow_file(rel: str, text: str) -> list[Finding]:
    if "pull_request_target" not in text:
        return []
    risky_ref = re.search(r"ref:\s*\$\{\{\s*(?:github\.event\.pull_request\.head\.(?:sha|ref)|github\.head_ref)", text)
    if not risky_ref:
        return []
    line = text[: risky_ref.start()].count("\n") + 1
    return [make_finding(
        "GHA-01", "High", "high", rel, line, risky_ref.group(0)[:140],
        "Never check out PR head code in pull_request_target workflows that have secrets or write tokens; use pull_request, "
        "or split into an unprivileged build job and a privileged workflow_run job.",
    )]


FROM_RE = re.compile(r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?", re.IGNORECASE)


def check_dockerfile(rel: str, text: str) -> list[Finding]:
    lines = text.splitlines()
    findings: list[Finding] = []
    stages: set[str] = set()
    for i, l in enumerate(lines, start=1):
        m = FROM_RE.match(l)
        if not m:
            continue
        image, alias = m.group(1), m.group(2)
        last_segment = image.rsplit("/", 1)[-1]
        unpinned = "@" not in image and (":" not in last_segment or last_segment.endswith(":latest"))
        if (unpinned and image.lower() != "scratch" and "$" not in image and image.lower() not in stages):
            findings.append(make_finding(
                "DOCKER-01", "Low", "high", rel, i, l.strip()[:140],
                "Pin base images to a specific version tag, ideally by digest (image@sha256:...).",
            ))
        if alias:
            stages.add(alias.lower())
    last_from = max((i for i, l in enumerate(lines) if re.match(r"^\s*FROM\s", l, re.IGNORECASE)), default=-1)
    if last_from < 0:
        return findings
    if re.search(r"^\s*FROM\s+(?:--platform=\S+\s+)?scratch\b", lines[last_from], re.IGNORECASE):
        return findings
    if re.search(r"(?:distroless|chainguard)[^\s]*:[^\s]*nonroot", lines[last_from], re.IGNORECASE):
        return findings
    users = [l for l in lines[last_from:] if re.match(r"^\s*USER\s+\S+", l, re.IGNORECASE)]
    if users and not re.match(r"^\s*USER\s+(?:root|0)(?::\S+)?\s*$", users[-1], re.IGNORECASE):
        return findings
    return findings + [make_finding(
        "DOCKER-02", "Medium", "medium", rel, last_from + 1, lines[last_from].strip()[:140],
        "Create an unprivileged user and switch to it with USER in the final stage (distroless :nonroot images also work).",
    )]


def post_adjust(rule: Rule, line: str, severity: str, confidence: str) -> tuple[str, str] | None:
    """Rule-specific tweaks to cut false positives. Return None to drop the match."""
    if rule.rule_id == "SEC-04" and re.search(r"@(?:localhost|127\.0\.0\.1|0\.0\.0\.0|db|postgres|mysql|mongo|redis|example\.com)\b", line):
        return "Low", "low"  # local dev / docker-compose defaults
    if rule.rule_id == "SEC-04" and re.search(r":(?:password|pass|changeme|secret|example|user)@", line, re.IGNORECASE):
        return "Low", "low"  # obvious placeholder credentials
    if rule.rule_id == "INJ-02" and re.search(r"\bexec(?:Sync)?\s*\(\s*['\"][^'\"$`]*['\"]\s*[,)]", line):
        return "Low", "low"  # constant command string, no interpolation
    if rule.rule_id == "TLS-01" and re.search(r"(?i)\b(?:test|mock|fixture)\b", line):
        return "Low", "low"
    return severity, confidence


def scan_repo(root: Path) -> tuple[list[Finding], int]:
    """Return (findings, inline_suppressed_count)."""
    self_path = Path(__file__).resolve()
    findings = check_git_hygiene(root)
    suppressed = 0
    for path in iter_files(root):
        if path.resolve() == self_path:
            continue
        rel = path.relative_to(root).as_posix()
        ext = path.suffix.lower()
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        if any(IGNORE_FILE_RE.search(l) for l in text.splitlines()[:5]):
            suppressed += 1
            continue

        if is_dockerfile(path.name):
            findings.extend(check_dockerfile(rel, text))
        if rel.startswith(".github/workflows/") and ext in (".yml", ".yaml"):
            findings.extend(check_workflow_file(rel, text))

        lines = text.splitlines()
        for idx, line in enumerate(lines, start=1):
            if len(line) > 500:
                continue
            is_comment = bool(COMMENT_LINE.match(line))
            for rule in RULES:
                if rule.extensions and ext not in rule.extensions:
                    continue
                if rule.path_globs and not path_matches(rel, rule.path_globs):
                    continue
                if is_comment and not rule.rule_id.startswith("SEC-"):
                    continue
                match = rule.pattern.search(line)
                if not match:
                    continue
                if rule.rule_id == "LOOP-02":
                    window = "\n".join(lines[max(0, idx - 1): min(len(lines), idx + 10)])
                    if any(k in window for k in ("max_iterations", "max_execution_time", "recursion_limit")):
                        continue
                if rule.rule_id == "LOOP-03":
                    loop_indent = len(line) - len(line.lstrip())
                    body_lines = []
                    for sub_line in lines[idx: min(len(lines), idx + 30)]:
                        stripped = sub_line.strip()
                        if not stripped:
                            continue
                        if (len(sub_line) - len(sub_line.lstrip())) <= loop_indent and not stripped.startswith("}"):
                            break
                        body_lines.append(stripped)
                    window = "\n".join(body_lines)
                    if any(k in window for k in ("break", "return", "max_retries", "max_iter", "attempts", "raise", "sys.exit")):
                        continue
                adjusted = post_adjust(rule, line, rule.severity, rule.confidence)
                if adjusted is None:
                    continue
                if is_suppressed(lines, idx, rule.rule_id):
                    suppressed += 1
                    continue

                snippet = line.strip()
                if rule.masked:
                    snippet = redact_text(snippet)
                snippet = snippet[:140]
                findings.append(make_finding(rule.rule_id, adjusted[0], adjusted[1], rel, idx, snippet, rule.remediation))

    findings.sort(key=lambda f: (SEVERITY_RANK.get(f.severity, 9), f.file, f.line))
    return findings, suppressed


# ---------------------------------------------------------------------------
# Baseline
# ---------------------------------------------------------------------------

def load_baseline(path: Path) -> set[str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return set()
    return {e["fingerprint"] for e in data.get("findings", []) if isinstance(e, dict) and e.get("fingerprint")}


def write_baseline(path: Path, findings: list[Finding]) -> None:
    payload = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "description": "Accepted findings. Entries here are hidden from future scans. Review periodically.",
        "findings": [
            {"fingerprint": f.fingerprint, "rule_id": f.rule_id, "file": f.file, "title": f.title}
            for f in findings
        ],
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# External tools
# ---------------------------------------------------------------------------

SECURITY_TOOLS: dict[str, list[str] | None] = {
    "gitleaks": ["gitleaks", "dir", "--source", ".", "--no-banner", "--redact"],
    # Offline by default. Verification sends candidate secrets to provider APIs: opt in with --allow-network-verify.
    "trufflehog": ["trufflehog", "filesystem", ".", "--no-verification", "--no-update"],
    # Registry rule packs with telemetry off. ("--config auto" needs metrics on, so it is not used.)
    "semgrep": ["semgrep", "scan", "--config", "p/owasp-top-ten", "--config", "p/secrets", "--metrics=off", "--quiet", "."],
    "osv-scanner": ["osv-scanner", "-r", "."],
    "trivy": ["trivy", "fs", ".", "--scanners", "vuln,secret", "--quiet"],
    "checkov": ["checkov", "-d", ".", "--quiet", "--compact"],
    "bandit": ["bandit", "-r", ".", "-q"],
    "pip-audit": ["pip-audit"],
    "npm": ["npm", "audit"],
    "govulncheck": ["govulncheck", "./..."],
    "dependency-check": ["dependency-check", "--scan", ".", "--format", "JSON", "--out", "odc-reports", "--suppression", "suppression.xml"],
    "nuclei": None,       # Active DAST: never auto-run without a confirmed URL
    "sqlmap": None,       # Active DAST
    "ffuf": None,         # Active fuzzer
    "schemathesis": None, # API fuzzer
    "dalfox": None,       # Active XSS
    "garak": None,        # LLM red-team
    "docker": None,       # Container runtime (can run ghcr.io/zaproxy/zaproxy:stable)
    "zap": None,          # OWASP ZAP Scoop/PATH shim
    "zap.bat": None,      # OWASP ZAP Windows CLI/daemon
    "zap.sh": None,       # OWASP ZAP Unix CLI/daemon
    "flutter": ["flutter", "analyze"],
}


def detect_tools() -> dict[str, str | None]:
    found: dict[str, str | None] = {}
    venv_root = Path.home() / ".security-skill" / "venvs"
    bin_dir = "Scripts" if os.name == "nt" else "bin"
    for tool in SECURITY_TOOLS:
        loc = shutil.which(tool)
        if not loc:
            names = (f"{tool}.exe", f"{tool}.cmd", f"{tool}.bat", tool) if os.name == "nt" else (tool,)
            for candidate_name in names:
                candidate = venv_root / tool / bin_dir / candidate_name
                if candidate.exists():
                    loc = str(candidate)
                    break
        found[tool] = loc
    return found


def run_safe_tools(root: Path, installed: dict[str, str | None], allow_network_verify: bool = False) -> list[dict]:
    results = []
    for tool, base_cmd in SECURITY_TOOLS.items():
        tool_path = installed.get(tool)
        if not base_cmd or not tool_path:
            continue
        cmd = list(base_cmd)
        if tool == "npm" and not (root / "package.json").exists():
            continue
        if tool == "flutter" and not (root / "pubspec.yaml").exists():
            continue
        if tool == "govulncheck" and not (root / "go.mod").exists():
            continue
        if tool == "pip-audit" and not any((root / f).exists() for f in ("requirements.txt", "pyproject.toml", "Pipfile")):
            continue
        if tool == "trufflehog" and allow_network_verify:
            cmd = [c for c in cmd if c != "--no-verification"] + ["--only-verified"]

        prop_file: str | None = None
        if tool == "dependency-check":
            if not (root / "suppression.xml").exists():
                cmd = [c for c in cmd if c not in ("--suppression", "suppression.xml")]
            nvd_key = os.environ.get("NVD_API_KEY")
            if nvd_key:
                # Pass the key through a private properties file, not argv, so it never shows up
                # in process listings or in the "command" field of this report.
                fd, prop_file = tempfile.mkstemp(prefix="odc-", suffix=".properties")
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    fh.write(f"nvd.api.key={nvd_key}\n")
                os.chmod(prop_file, 0o600)
                cmd = [*cmd, "--propertyfile", prop_file]

        exec_cmd = [tool_path, *cmd[1:]]
        if os.name == "nt" and tool_path.lower().endswith((".cmd", ".bat")):
            exec_cmd = ["cmd.exe", "/c", *exec_cmd]
        display_cmd = " ".join("<nvd-properties-file>" if c == prop_file else c for c in cmd)
        try:
            proc = subprocess.run(
                exec_cmd, cwd=root, capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=300,
            )
            results.append({
                "tool": tool,
                "command": display_cmd,
                "exit_code": proc.returncode,
                "output_preview": redact_text((proc.stdout or proc.stderr)[:3000].strip()),
            })
        except (subprocess.TimeoutExpired, OSError) as exc:
            results.append({"tool": tool, "command": display_cmd, "error": str(exc)})
        finally:
            if prop_file:
                try:
                    os.remove(prop_file)
                except OSError:
                    pass
    return results


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def summarize(findings: list[Finding]) -> dict[str, int]:
    return {s.lower(): sum(1 for f in findings if f.severity == s) for s in SEVERITIES}


def format_markdown(root: Path, findings: list[Finding], tools: dict[str, str | None], tool_runs: list[dict],
                    suppressed: int, baselined: int) -> str:
    available = [k for k, v in tools.items() if v]
    missing = [k for k, v in tools.items() if not v]
    c = summarize(findings)
    out = [
        "# Loophole & Loop Security Scan Report",
        f"- **Target**: `{root}`",
        f"- **Heuristic Findings**: {len(findings)} (Critical: {c['critical']}, High: {c['high']}, Medium: {c['medium']}, Low: {c['low']})",
        f"- **Suppressed**: {suppressed} inline, {baselined} by baseline",
        f"- **Installed Security CLIs**: {', '.join(available) if available else 'None detected'}",
        f"- **Available to Install**: {', '.join(missing[:10])}{'...' if len(missing) > 10 else ''}",
        "",
        "> Heuristic matches are leads, not verdicts. Confirm each one in context before reporting it.",
        "",
    ]
    if findings:
        out.append("## Heuristic Findings")
        out.append("| Rule | Severity | Confidence | CWE | OWASP | Location | Issue |")
        out.append("|:---|:---|:---|:---|:---|:---|:---|")
        for f in findings[:150]:
            loc = f"`{f.file}:{f.line}`" if f.line else f"`{f.file}`"
            ctx = " _(test/example)_" if f.context != "code" else ""
            out.append(f"| `{f.rule_id}` | {f.severity} | {f.confidence} | {f.cwe} | {', '.join(f.owasp)} | {loc} | {f.title}{ctx} |")
        if len(findings) > 150:
            out.append(f"\n_{len(findings) - 150} more findings omitted; use --format json for the full list._")
        out.append("")
    else:
        out.append("No heuristic loophole patterns matched in static scan.\n")

    if tool_runs:
        out.append("## External Tool Execution Summary")
        for run in tool_runs:
            out.append(f"### `{run['tool']}` (exit code: {run.get('exit_code', 'err')})")
            preview = run.get("output_preview") or run.get("error") or "(no output)"
            out.append(f"```text\n{preview}\n```")
    return "\n".join(out)


def format_json(root: Path, findings: list[Finding], tools: dict[str, str | None], tool_runs: list[dict],
                suppressed: int, baselined: int) -> str:
    payload = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "tool": {"name": SCANNER_NAME, "version": SCANNER_VERSION},
        "target": str(root),
        "summary": {"total": len(findings), **summarize(findings),
                    "suppressed_inline": suppressed, "suppressed_baseline": baselined},
        "findings": [asdict(f) for f in findings],
        "installed_tools": {k: bool(v) for k, v in tools.items()},
        "tool_runs": tool_runs,
    }
    return json.dumps(payload, indent=2)


def format_sarif(findings: list[Finding]) -> str:
    used = sorted({f.rule_id for f in findings})
    rules = []
    for rid in used:
        rule = RULES_BY_ID.get(rid)
        meta = FILE_CHECK_META.get(rid, {})
        title = rule.title if rule else meta.get("title", rid)
        cwe = rule.cwe if rule else meta.get("cwe", "")
        owasp = list(rule.owasp) if rule else list(meta.get("owasp", []))
        sev = rule.severity if rule else next((f.severity for f in findings if f.rule_id == rid), "Medium")
        tags = ["security"] + ([f"external/cwe/{cwe.lower()}"] if cwe else []) + [f"owasp/{o}" for o in owasp]
        entry = {
            "id": rid,
            "name": re.sub(r"[^A-Za-z0-9]+", "", title.title())[:60] or rid,
            "shortDescription": {"text": title},
            "properties": {"tags": tags, "security-severity": SARIF_SECURITY_SEVERITY.get(sev, "5.5")},
        }
        if rule:
            entry["help"] = {"text": rule.remediation}
        rules.append(entry)

    results = []
    for f in findings:
        results.append({
            "ruleId": f.rule_id,
            "level": SARIF_LEVEL.get(f.severity, "warning"),
            "message": {"text": f"{f.title}. {f.remediation}"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": f.file, "uriBaseId": "%SRCROOT%"},
                "region": {"startLine": max(1, f.line)},
            }}],
            "partialFingerprints": {"securitySkill/v1": f.fingerprint},
            "properties": {"severity": f.severity, "confidence": f.confidence, "context": f.context,
                           "security-severity": SARIF_SECURITY_SEVERITY.get(f.severity, "5.5")},
        })

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "owasp-security-audit-skill",
                "version": SCANNER_VERSION,
                "informationUri": "https://github.com/engrshoaibh/owasp-security-audit-skill",
                "rules": rules,
            }},
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2)


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(description="Static loophole, loop-hazard & security CLI scanner")
    parser.add_argument("--target", default=".", help="Target project directory to scan")
    parser.add_argument("--format", choices=("markdown", "json", "sarif"), default="markdown", help="Output format")
    parser.add_argument("--output", help="Write the report to this file instead of stdout")
    parser.add_argument("--fail-on", choices=("critical", "high", "medium", "low", "none"), default="none",
                        help="Exit with code 1 if any finding is at or above this severity (for CI)")
    parser.add_argument("--min-confidence", choices=("low", "medium", "high"), default="low",
                        help="Hide findings below this confidence level")
    parser.add_argument("--baseline", help=f"Baseline file of accepted findings (default: <target>/{DEFAULT_BASELINE} if present)")
    parser.add_argument("--write-baseline", metavar="PATH", help="Write all current findings to a baseline file and exit 0")
    parser.add_argument("--run-tools", action="store_true", help="Also execute installed local static scanners")
    parser.add_argument("--allow-network-verify", action="store_true",
                        help="Let TruffleHog verify candidate secrets against provider APIs (sends them over the network)")
    parser.add_argument("--list-rules", action="store_true", help="Print the rule catalog with CWE/OWASP mappings and exit")
    args = parser.parse_args(argv)

    if args.list_rules:
        for r in RULES:
            print(f"{r.rule_id:10} {r.severity:8} {r.confidence:6} {r.cwe:9} {','.join(r.owasp):30} {r.title}")
        for rid, meta in FILE_CHECK_META.items():
            print(f"{rid:10} {'varies':8} {'high':6} {meta['cwe']:9} {','.join(meta['owasp']):30} {meta['title']}")
        return 0

    root = Path(args.target).resolve()
    if not root.is_dir():
        print(f"Error: target directory not found: {root}", file=sys.stderr)
        return 2

    findings, suppressed = scan_repo(root)

    conf_rank = {"low": 0, "medium": 1, "high": 2}
    findings = [f for f in findings if conf_rank.get(f.confidence, 0) >= conf_rank[args.min_confidence]]

    if args.write_baseline:
        write_baseline(Path(args.write_baseline), findings)
        print(f"Wrote {len(findings)} findings to baseline {args.write_baseline}", file=sys.stderr)
        return 0

    baseline_path = Path(args.baseline) if args.baseline else root / DEFAULT_BASELINE
    accepted = load_baseline(baseline_path) if baseline_path.exists() else set()
    baselined = sum(1 for f in findings if f.fingerprint in accepted)
    findings = [f for f in findings if f.fingerprint not in accepted]

    tools = detect_tools()
    tool_runs = run_safe_tools(root, tools, args.allow_network_verify) if args.run_tools else []

    if args.format == "json":
        report = format_json(root, findings, tools, tool_runs, suppressed, baselined)
    elif args.format == "sarif":
        report = format_sarif(findings)
    else:
        report = format_markdown(root, findings, tools, tool_runs, suppressed, baselined)

    if args.output:
        Path(args.output).write_text(report + "\n", encoding="utf-8")
    else:
        print(report)

    if args.fail_on != "none":
        threshold = SEVERITY_RANK[args.fail_on.capitalize()]
        if any(SEVERITY_RANK.get(f.severity, 9) <= threshold for f in findings):
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
