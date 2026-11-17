#!/usr/bin/env python3
"""
Cross-platform static loophole, loop-hazard, and security-tool discovery scanner.
Uses only Python standard library so it works anywhere (Windows, macOS, Linux).

Usage:
  python scripts/loophole_scanner.py --target .
  python scripts/loophole_scanner.py --target /path/to/repo --format json
  python scripts/loophole_scanner.py --target . --run-tools
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "vendor",
    "venv",
    ".venv",
    "env",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    "dist",
    "build",
    "out",
    ".next",
    ".nuxt",
    "target",
    "bin",
    "obj",
    ".dart_tool",
    ".gradle",
    "Pods",
    "coverage",
}

SCAN_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".php", ".rb", ".java", ".kt", ".cs", ".go", ".rs",
    ".dart", ".swift", ".sql", ".rules", ".yaml", ".yml",
    ".json", ".toml", ".env", ".tf", ".tfvars", ".xml", ".html",
    ".sh", ".ps1",
}

MAX_FILE_BYTES = 512 * 1024  # Skip huge/minified bundles


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    module: str
    file: str
    line: int
    snippet: str
    remediation: str


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    severity: str
    module: str
    pattern: re.Pattern[str]
    remediation: str
    extensions: tuple[str, ...] | None = None


RULES: list[Rule] = [
    # --- Hardcoded Secrets & Key Leaks ---
    Rule(
        "SEC-01",
        "Potential AWS Access Key ID hardcoded",
        "Critical",
        "1.5 Secrets Management",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "Revoke key immediately, remove from code/git history, and load via IAM Role or Secrets Manager.",
    ),
    Rule(
        "SEC-02",
        "Potential Private Key material committed in file",
        "Critical",
        "1.5 Secrets Management",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
        "Remove private key from repo, rotate credentials, and add *.pem/*.key to .gitignore.",
    ),
    Rule(
        "SEC-03",
        "Potential Live LLM / Stripe / GitHub API Key hardcoded",
        "Critical",
        "1.5 / 10.5.3 Secrets",
        re.compile(r"\b(?:sk-proj-[A-Za-z0-9_-]{20,}|sk-ant-[A-Za-z0-9_-]{20,}|sk_live_[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|AIza[0-9A-Za-z_-]{35})\b"),
        "Move API keys to server-side environment/secrets manager and rotate exposed keys. (Note: AIza Firebase client keys require GCP API restrictions + strict Rules.)",
    ),
    Rule(
        "SEC-04",
        "Hardcoded DB connection string with embedded credentials",
        "High",
        "1.5 / 6 Database",
        re.compile(r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss)://[^:\s'\"`]+:[^@\s'\"`${}]+@[^\s'\"`]+"),
        "Move database credentials out of source files into secret manager / runtime environment variables.",
    ),
    Rule(
        "SEC-05",
        "Hardcoded fallback JWT / session secret",
        "High",
        "2.3 JWT / Session",
        re.compile(r"(?:JWT_SECRET|SESSION_SECRET|APP_KEY|SECRET_KEY)\s*(?:=[^#\n]*)?(?:\|\||\?\?|\bor\b)\s*['\"][^'\"]{3,}['\"]", re.IGNORECASE),
        "Fail closed on startup if signing secret env var is unset; never fall back to a hardcoded default.",
    ),
    # --- TLS / Auth / Config Bypasses ---
    Rule(
        "TLS-01",
        "TLS certificate verification disabled",
        "Critical",
        "1.1.4 / 11.2.1 TLS",
        re.compile(r"(?:NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0|rejectUnauthorized\s*:\s*false|verify\s*=\s*False|InsecureSkipVerify\s*:\s*true|badCertificateCallback\s*=\s*\([^)]*\)\s*=>\s*true)"),
        "Remove TLS verification bypasses in production code; fix certificate trust properly.",
    ),
    Rule(
        "JWT-01",
        "JWT decoded without verification or 'none' algorithm permitted",
        "Critical",
        "2.3.1 JWT Security",
        re.compile(r"(?:algorithms\s*[:=]\s*\[[^\]]*['\"]none['\"]|verify_signature\s*:\s*False|jwt\.decode\([^)]*verify\s*=\s*False)"),
        "Explicitly pin secure algorithms (e.g., ['RS256']) and verify JWT signatures and claims on every request.",
    ),
    Rule(
        "CORS-01",
        "Permissive wildcard CORS with credentials enabled",
        "High",
        "4.3.3 CORS",
        re.compile(r"(?:allow_origins\s*=\s*\[\s*['\"]\*['\"]\s*\].*allow_credentials\s*=\s*True|origin\s*:\s*(?:true|\*).*credentials\s*:\s*true)"),
        "Replace wildcard origin with an explicit allowlist of trusted origins when credentials are enabled.",
    ),
    Rule(
        "DBG-01",
        "Debug mode potentially enabled in code/config",
        "Medium",
        "1.3.3 / 5 Config",
        re.compile(r"^(?:DEBUG\s*=\s*True|APP_DEBUG\s*=\s*true)\b"),
        "Ensure DEBUG=False / APP_DEBUG=false in production environments and load via environment config.",
    ),
    # --- Injection & RCE Loopholes ---
    Rule(
        "INJ-01",
        "Potential SQL string interpolation / raw unsafe query",
        "High",
        "1.2.2 / 6A.1 SQLi",
        re.compile(r"(?:\.(?:query|execute|raw|whereRaw|FromSqlRaw)\s*\(\s*(?:f['\"]|`[^`]*\$\{|['\"][^'\"]*['\"]\s*\+)|\$queryRawUnsafe|\$executeRawUnsafe)"),
        "Use parameterized queries / prepared statements ($1, ?, :param) or tagged template Prisma.$queryRaw instead of string interpolation.",
    ),
    Rule(
        "INJ-02",
        "OS command injection risk (shell=True or child_process.exec)",
        "Critical",
        "1.2.3 Command Injection",
        re.compile(r"(?:subprocess\.\w+\([^)]*shell\s*=\s*True|\bchild_process\.exec(?:Sync)?\s*\(|\bos\.system\s*\()"),
        "Avoid shell=True and exec(); use subprocess.run([...], shell=False) or execFile() with allowlisted arguments.",
    ),
    Rule(
        "INJ-03",
        "Dangerous eval / dynamic code execution or unsafe deserialization",
        "High",
        "1.2.9 Deserialization / RCE",
        re.compile(r"(?:\bpickle\.loads?\s*\(|\byaml\.load\s*\((?![^)]*SafeLoader)|\bunserialize\s*\(|\bnew\s+Function\s*\(|\beval\s*\()"),
        "Replace with JSON/yaml.safe_load; never deserialize untrusted binary payloads or pass external strings to eval().",
    ),
    Rule(
        "XSS-01",
        "Raw HTML injection / framework escape hatch",
        "High",
        "4.1.2 XSS Prevention",
        re.compile(r"(?:dangerouslySetInnerHTML|\bv-html\s*=|\bbypassSecurityTrust(?:Html|Script|ResourceUrl|Style|Url)|\{@html\b|\.innerHTML\s*=|document\.write\s*\()"),
        "Prefer framework auto-escaping; if HTML rendering is required, sanitize strictly with DOMPurify first.",
    ),
    Rule(
        "NOSQL-01",
        "MongoDB server-side JS execution ($where) or raw req.body query",
        "High",
        "6B NoSQL Injection",
        re.compile(r"(?:['\"]?\$where['\"]?\s*:|\.(?:find|findOne|findByIdAndUpdate|create|updateOne)\(\s*req\.body\b)"),
        "Remove $where operators and validate/whitelist req.body fields with Zod/Joi before database queries.",
    ),
    Rule(
        "MASS-01",
        "Potential mass assignment ($request->all() passed directly)",
        "High",
        "3.4 / 5D.1 Mass Assignment",
        re.compile(r"\$request->all\s*\("),
        "Use $request->validated() or explicit $fillable allowlists on Eloquent models.",
    ),
    # --- BaaS (Firebase / Supabase) Loopholes ---
    Rule(
        "BAAS-01",
        "Permissive Firestore / Storage Security Rule (allow read/write)",
        "Critical",
        "8.1 Firebase Rules",
        re.compile(r"allow\s+(?:read|write|read,\s*write)\s*:\s*if\s+true\s*;"),
        "Deny by default and require authentication + resource ownership / role validation.",
        extensions=(".rules",),
    ),
    Rule(
        "BAAS-02",
        "Supabase RLS policy referencing editable user_metadata",
        "Critical",
        "9.3 Supabase RLS",
        re.compile(r"(?:user_metadata|raw_user_meta_data)"),
        "Never authorize via user-editable user_metadata; use app_metadata or server-controlled role tables.",
        extensions=(".sql",),
    ),
    # --- Loop & Resource Exhaustion Hazards ---
    Rule(
        "LOOP-01",
        "Potential ReDoS catastrophic backtracking regex (nested quantifier)",
        "Medium",
        "1.2.7 ReDoS Loop",
        re.compile(r"(?:re\.compile\s*\(|new\s+RegExp\s*\(|=\s*/).*\([^()]*[+*][^()]*\)[+*]"),
        "Rewrite regex without nested quantifiers (e.g., use atomic/possessive pattern or bounded string checks) and test with recheck.",
    ),
    Rule(
        "LOOP-02",
        "AI Agent / Graph executor without explicit iteration or recursion cap nearby",
        "Medium",
        "10.3.4 Agent Loop",
        re.compile(r"\bAgentExecutor\s*\("),
        "Verify max_iterations, max_execution_time, and tool-cycle safeguards are explicitly configured to prevent runaway loops.",
    ),
    Rule(
        "LOOP-03",
        "Unbounded while(true) / while True loop — inspect exit conditions",
        "Low",
        "1.2 / 10.3.4 Loop Check",
        re.compile(r"\bwhile\s*(?:\(\s*true\s*\)|True\s*:)"),
        "Ensure loop has deterministic break conditions, max retry/iteration caps, timeouts, and backoff.",
    ),
    Rule(
        "SSRF-01",
        "Outbound HTTP request with automatic redirect following on dynamic URL",
        "Medium",
        "14.5 SSRF / Redirect Loop",
        re.compile(r"(?:allow_redirects\s*=\s*True|maxRedirects\s*:\s*(?:[2-9]\d|[1-9]\d{2,}))"),
        "Disable automatic redirects or re-validate every redirect hop against domain & private-IP allowlists.",
    ),
]

COMMENT_LINE = re.compile(r"^\s*(?:#|//|/\*|\*)")

SECURITY_TOOLS = {
    "gitleaks": ["gitleaks", "dir", "--source", ".", "--no-banner", "--redact"],
    "trufflehog": ["trufflehog", "filesystem", ".", "--only-verified", "--no-update"],
    "semgrep": ["semgrep", "scan", "--config", "auto", "--quiet", "."],
    "osv-scanner": ["osv-scanner", "-r", "."],
    "trivy": ["trivy", "fs", ".", "--scanners", "vuln,secret", "--quiet"],
    "checkov": ["checkov", "-d", ".", "--quiet", "--compact"],
    "bandit": ["bandit", "-r", ".", "-q"],
    "pip-audit": ["pip-audit"],
    "npm": ["npm", "audit"],
    "govulncheck": ["govulncheck", "./..."],
    "nuclei": None,       # Active DAST — never auto-run against target without URL
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


def iter_files(root: Path) -> Iterable[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            path = Path(dirpath) / fname
            ext = path.suffix.lower()
            if ext not in SCAN_EXTENSIONS and not fname.startswith(".env") and fname != "Dockerfile":
                continue
            try:
                if path.stat().st_size > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            yield path


def check_gitignore(root: Path) -> list[Finding]:
    if not (root / ".git").exists():
        return []
    gitignore = root / ".gitignore"
    findings: list[Finding] = []
    if not gitignore.exists():
        findings.append(
            Finding(
                "GIT-01",
                "Missing .gitignore file",
                "Medium",
                "1.5.2 Secrets Management",
                ".gitignore",
                0,
                "No .gitignore at project root",
                "Add a .gitignore excluding .env, *.key, *.pem, *.p12, *.jks, *.keystore, and build artifacts.",
            )
        )
        return findings

    content = gitignore.read_text(encoding="utf-8", errors="ignore")
    missing = [pat for pat in (".env", "*.pem", "*.key") if pat not in content]
    if missing:
        findings.append(
            Finding(
                "GIT-02",
                f".gitignore missing sensitive file exclusions: {', '.join(missing)}",
                "Medium",
                "1.5.2 Secrets Management",
                ".gitignore",
                1,
                f"Missing entries: {', '.join(missing)}",
                "Exclude .env, *.pem, *.key, *.jks, and service-account files in .gitignore.",
            )
        )
    return findings


def scan_repo(root: Path) -> list[Finding]:
    self_path = Path(__file__).resolve()
    findings = check_gitignore(root)
    for path in iter_files(root):
        if path.resolve() == self_path:
            continue
        rel = path.relative_to(root).as_posix()
        ext = path.suffix.lower()
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        lines = text.splitlines()
        for idx, line in enumerate(lines, start=1):
            if len(line) > 500:
                continue
            is_comment = bool(COMMENT_LINE.match(line))
            for rule in RULES:
                if rule.extensions and ext not in rule.extensions:
                    continue
                if is_comment and not rule.rule_id.startswith("SEC-"):
                    continue
                if rule.pattern.search(line):
                    # Special check for AgentExecutor loop guard nearby
                    if rule.rule_id == "LOOP-02":
                        window = "\n".join(lines[max(0, idx - 1) : min(len(lines), idx + 10)])
                        if "max_iterations" in window or "max_execution_time" in window:
                            continue
                    # Special check for while(true) having break/return within its own loop body
                    if rule.rule_id == "LOOP-03":
                        loop_indent = len(line) - len(line.lstrip())
                        body_lines = []
                        for sub_line in lines[idx : min(len(lines), idx + 30)]:
                            stripped = sub_line.strip()
                            if not stripped:
                                continue
                            if (len(sub_line) - len(sub_line.lstrip())) <= loop_indent and not stripped.startswith("}"):
                                break
                            body_lines.append(stripped)
                        window = "\n".join(body_lines)
                        if any(k in window for k in ("break", "return", "max_retries", "max_iter", "attempts")):
                            continue

                    snippet = line.strip()[:140]
                    findings.append(
                        Finding(
                            rule_id=rule.rule_id,
                            title=rule.title,
                            severity=rule.severity,
                            module=rule.module,
                            file=rel,
                            line=idx,
                            snippet=snippet,
                            remediation=rule.remediation,
                        )
                    )
    severity_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    findings.sort(key=lambda f: (severity_rank.get(f.severity, 9), f.file, f.line))
    return findings


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


def run_safe_tools(root: Path, installed: dict[str, str | None]) -> list[dict]:
    results = []
    for tool, cmd in SECURITY_TOOLS.items():
        tool_path = installed.get(tool)
        if not cmd or not tool_path:
            continue
        # Only run ecosystem tools when relevant manifest exists
        if tool == "npm" and not (root / "package.json").exists():
            continue
        if tool == "flutter" and not (root / "pubspec.yaml").exists():
            continue
        if tool == "govulncheck" and not (root / "go.mod").exists():
            continue
        if tool == "pip-audit" and not any((root / f).exists() for f in ("requirements.txt", "pyproject.toml", "Pipfile")):
            continue

        exec_cmd = [tool_path, *cmd[1:]]
        if os.name == "nt" and tool_path.lower().endswith((".cmd", ".bat")):
            exec_cmd = ["cmd.exe", "/c", *exec_cmd]
        try:
            proc = subprocess.run(
                exec_cmd,
                cwd=root,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=120,
            )
            results.append(
                {
                    "tool": tool,
                    "command": " ".join(cmd),
                    "exit_code": proc.returncode,
                    "output_preview": (proc.stdout or proc.stderr)[:1500].strip(),
                }
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            results.append({"tool": tool, "command": " ".join(cmd), "error": str(exc)})
    return results


def format_markdown(root: Path, findings: list[Finding], tools: dict[str, str | None], tool_runs: list[dict]) -> str:
    available = [k for k, v in tools.items() if v]
    missing = [k for k, v in tools.items() if not v]
    counts = {s: sum(1 for f in findings if f.severity == s) for s in ("Critical", "High", "Medium", "Low")}

    out = [
        f"# Loophole & Loop Security Scan Report",
        f"- **Target**: `{root}`",
        f"- **Heuristic Findings**: {len(findings)} (Critical: {counts['Critical']}, High: {counts['High']}, Medium: {counts['Medium']}, Low: {counts['Low']})",
        f"- **Installed Security CLIs**: {', '.join(available) if available else 'None detected'}",
        f"- **Available to Install**: {', '.join(missing[:10])}{'...' if len(missing) > 10 else ''}",
        "",
    ]

    if findings:
        out.append("## Heuristic Loophole & Loop Findings")
        out.append("| Rule | Severity | Module | Location | Issue |")
        out.append("|:---|:---|:---|:---|:---|")
        for f in findings[:100]:
            loc = f"`{f.file}:{f.line}`" if f.line else f"`{f.file}`"
            out.append(f"| `{f.rule_id}` | {f.severity} | {f.module} | {loc} | {f.title} |")
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


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(description="Static loophole, loop-hazard & security CLI scanner")
    parser.add_argument("--target", default=".", help="Target project directory to scan")
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown", help="Output format")
    parser.add_argument("--run-tools", action="store_true", help="Also execute installed safe local static scanners")
    args = parser.parse_args()

    root = Path(args.target).resolve()
    if not root.is_dir():
        print(f"Error: target directory not found: {root}", file=sys.stderr)
        return 2

    findings = scan_repo(root)
    tools = detect_tools()
    tool_runs = run_safe_tools(root, tools) if args.run_tools else []

    if args.format == "json":
        payload = {
            "target": str(root),
            "findings": [asdict(f) for f in findings],
            "installed_tools": {k: bool(v) for k, v in tools.items()},
            "tool_runs": tool_runs,
        }
        print(json.dumps(payload, indent=2))
    else:
        print(format_markdown(root, findings, tools, tool_runs))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
