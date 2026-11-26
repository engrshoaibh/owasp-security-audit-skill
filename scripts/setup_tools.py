#!/usr/bin/env python3
"""
Prerequisite Checker & Automated Installer/Setup for the Universal Security Audit Skill.
Checks required runtimes and security CLIs, then downloads and sets up missing tools
automatically using available system package managers (Scoop, Winget, Chocolatey, Homebrew, pip).

Zero third-party dependencies — Python standard library only.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


COMMON_ZAP_PATHS = [
    str(Path.home() / "scoop" / "apps" / "zaproxy" / "current" / "zap.bat"),
    str(Path.home() / "scoop" / "shims" / "zap.cmd"),
    r"C:\Program Files\ZAP\Zed Attack Proxy\zap.bat",
    r"C:\Program Files (x86)\ZAP\Zed Attack Proxy\zap.bat",
    "/usr/share/zaproxy/zap.sh",
    "/opt/zaproxy/zap.sh",
    "/Applications/ZAP.app/Contents/Java/zap.sh",
]

COMMON_DEPENDENCY_CHECK_PATHS = [
    str(Path.home() / "scoop" / "apps" / "dependency-check" / "current" / "bin" / "dependency-check.bat"),
    str(Path.home() / "scoop" / "shims" / "dependency-check.cmd"),
    r"C:\Program Files\OWASP\Dependency-Check\bin\dependency-check.bat",
    r"C:\Program Files (x86)\OWASP\Dependency-Check\bin\dependency-check.bat",
    "/usr/local/bin/dependency-check",
    "/opt/homebrew/bin/dependency-check",
    "/usr/share/dependency-check/bin/dependency-check.sh",
]

VENV_ROOT = Path.home() / ".security-skill" / "venvs"


@dataclass(frozen=True)
class ToolSpec:
    name: str
    profile: str          # runtime | core | web | python | sast | iac
    description: str
    binary_names: tuple[str, ...] = ()
    extra_paths: tuple[str, ...] = ()
    python_module: str | None = None
    scoop_pkg: str | None = None
    scoop_bucket: str | None = None
    winget_id: str | None = None
    choco_pkg: str | None = None
    brew_pkg: str | None = None
    brew_cask: bool = False
    pip_pkg: str | None = None
    isolated_venv: bool = False
    version_args: tuple[str, ...] = ("--version",)
    post_install_cmd: tuple[str, ...] | None = None


TOOLS: list[ToolSpec] = [
    # Runtimes (checked only)
    ToolSpec("python", "runtime", "Python 3.10+ runtime", ("python", "python3"), version_args=("--version",)),
    ToolSpec("java", "runtime", "Java JDK/JRE (required by OWASP ZAP)", ("java",), version_args=("-version",)),
    ToolSpec("git", "runtime", "Git CLI (git secret & history scans)", ("git",), winget_id="Git.Git", scoop_pkg="git", brew_pkg="git"),
    ToolSpec("npm", "runtime", "Node.js / npm CLI (npm audit)", ("npm",), winget_id="OpenJS.NodeJS.LTS", scoop_pkg="nodejs-lts", brew_pkg="node"),

    # Core cross-stack security scanners
    ToolSpec(
        "gitleaks", "core", "Fast secret & credential leak scanner",
        ("gitleaks",), scoop_pkg="gitleaks", winget_id="Gitleaks.Gitleaks", choco_pkg="gitleaks", brew_pkg="gitleaks",
        version_args=("version",),
    ),
    ToolSpec(
        "trufflehog", "core", "Verified secret & credential leak detector",
        ("trufflehog",), scoop_pkg="trufflehog", brew_pkg="trufflehog",
        version_args=("--version",),
    ),
    ToolSpec(
        "osv-scanner", "core", "Multi-language dependency CVE scanner (OSV)",
        ("osv-scanner",), scoop_pkg="osv-scanner", brew_pkg="osv-scanner",
        version_args=("--version",),
    ),
    ToolSpec(
        "trivy", "core", "Vulnerability, secret, IaC & container scanner",
        ("trivy",), scoop_pkg="trivy", winget_id="AquaSecurity.Trivy", choco_pkg="trivy", brew_pkg="trivy",
        version_args=("--version",),
    ),
    ToolSpec(
        "dependency-check", "core", "OWASP Dependency-Check (NIST NVD / CPE deep vulnerability scanner)",
        ("dependency-check", "dependency-check.bat", "dependency-check.sh"),
        extra_paths=tuple(COMMON_DEPENDENCY_CHECK_PATHS),
        scoop_pkg="dependency-check", scoop_bucket="main", brew_pkg="dependency-check",
        version_args=("--version",),
    ),

    # Web & API DAST (OWASP ZAP + probers)
    ToolSpec(
        "zap", "web", "OWASP ZAP Web & API security scanner",
        ("zap", "zap.cmd", "zap.bat", "zap.sh", "zaproxy"),
        extra_paths=tuple(COMMON_ZAP_PATHS),
        scoop_pkg="zaproxy", scoop_bucket="extras", winget_id="ZAP.ZAP", brew_pkg="zap", brew_cask=True,
        version_args=(),
    ),
    ToolSpec(
        "zaproxy", "web", "OWASP ZAP Python client (zapv2)",
        python_module="zapv2", pip_pkg="zaproxy",
        version_args=(),
    ),
    ToolSpec(
        "nuclei", "web", "Template-based OWASP & CVE DAST scanner",
        ("nuclei",), scoop_pkg="nuclei", brew_pkg="nuclei",
        version_args=("-version",),
        post_install_cmd=("nuclei", "-update-templates", "-silent"),
    ),
    ToolSpec(
        "ffuf", "web", "Web endpoint & parameter fuzzer",
        ("ffuf",), scoop_pkg="ffuf", brew_pkg="ffuf",
        version_args=("-V",),
    ),
    ToolSpec(
        "sqlmap", "web", "Automated SQL injection detection & verification",
        ("sqlmap",), pip_pkg="sqlmap", brew_pkg="sqlmap",
        version_args=("--version",),
    ),
    ToolSpec(
        "schemathesis", "web", "OpenAPI & GraphQL schema loophole fuzzer",
        ("schemathesis",), pip_pkg="schemathesis",
        version_args=("--version",),
    ),

    # Python SAST & SCA
    ToolSpec(
        "bandit", "python", "Python static application security testing (SAST)",
        ("bandit",), pip_pkg="bandit", brew_pkg="bandit",
        version_args=("--version",),
    ),
    ToolSpec(
        "pip-audit", "python", "Python dependency vulnerability scanner",
        ("pip-audit",), pip_pkg="pip-audit", brew_pkg="pip-audit",
        version_args=("--version",),
    ),

    # Multi-language SAST & IaC
    ToolSpec(
        "semgrep", "sast", "Multi-language OWASP SAST rule engine",
        ("semgrep",), pip_pkg="semgrep", brew_pkg="semgrep",
        version_args=("--version",),
    ),
    ToolSpec(
        "checkov", "iac", "Terraform, Kubernetes & Dockerfile IaC scanner",
        ("checkov",), pip_pkg="checkov", brew_pkg="checkov", isolated_venv=True,
        version_args=("--version",),
    ),
]


def _which_outside_cwd(name: str) -> str | None:
    """Resolve an executable to an absolute path, ignoring the current directory.

    On Windows a bare command name can resolve to a file in the current working directory,
    which may be the untrusted project being audited (CWE-427). Always launch package
    managers by the absolute path found here.
    """
    cwd = os.path.normcase(os.path.abspath(os.getcwd()))
    search = [d for d in os.environ.get("PATH", "").split(os.pathsep)
              if d and d != "." and os.path.normcase(os.path.abspath(d)) != cwd]
    found = shutil.which(name, path=os.pathsep.join(search))
    return os.path.abspath(found) if found else None


def detect_managers() -> dict[str, str | None]:
    return {
        "scoop": _which_outside_cwd("scoop"),
        "winget": _which_outside_cwd("winget"),
        "choco": _which_outside_cwd("choco"),
        "brew": _which_outside_cwd("brew"),
        "pip": _which_outside_cwd("pip") or sys.executable,
    }


def _venv_bin_path(tool_name: str) -> Path | None:
    bin_dir = "Scripts" if os.name == "nt" else "bin"
    base = VENV_ROOT / tool_name / bin_dir
    names = (f"{tool_name}.exe", f"{tool_name}.cmd", f"{tool_name}.bat", tool_name) if os.name == "nt" else (tool_name,)
    for candidate in names:
        p = base / candidate
        if p.exists():
            return p
    return None


def _find_tool(spec: ToolSpec) -> str | None:
    if spec.python_module:
        if importlib.util.find_spec(spec.python_module) is not None:
            return f"python-module:{spec.python_module}"
    for name in spec.binary_names:
        found = shutil.which(name)
        if found:
            return found
    venv_exe = _venv_bin_path(spec.name)
    if venv_exe is not None:
        return str(venv_exe)
    for path_str in spec.extra_paths:
        if Path(path_str).exists():
            return path_str
    return None


def _run_cmd(cmd: list[str], timeout: int = 300) -> tuple[int, str]:
    # On Windows .cmd/.bat shims require cmd.exe if invoked via CreateProcess cleanly
    exec_cmd = cmd
    if os.name == "nt" and cmd:
        first = cmd[0].lower()
        if first.endswith((".cmd", ".bat", ".ps1")) or Path(first).name in ("scoop", "npm", "npx"):
            exec_cmd = ["cmd.exe", "/c", *cmd]
    proc = subprocess.run(
        exec_cmd,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )
    out = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
    return proc.returncode, out.strip()


def _probe_version(spec: ToolSpec, location: str | None) -> str:
    if not location:
        return ""
    if location.startswith("python-module:"):
        try:
            code, out = _run_cmd([sys.executable, "-m", "pip", "show", spec.pip_pkg or spec.name], timeout=15)
            for line in out.splitlines():
                if line.lower().startswith("version:"):
                    return line.split(":", 1)[1].strip()
        except Exception:
            pass
        return "installed"
    if not spec.version_args:
        return "installed"
    try:
        code, out = _run_cmd([location, *spec.version_args], timeout=15)
        if code != 0:
            return f"installed (probe exited {code})"
        first_line = next((ln.strip() for ln in out.splitlines() if ln.strip()), "")
        return first_line[:80] if first_line else "installed"
    except Exception:
        return "installed"


def check_prerequisites(profiles: set[str] | None = None, verify_versions: bool = False) -> dict[str, Any]:
    managers = detect_managers()
    results: list[dict[str, Any]] = []
    for spec in TOOLS:
        if profiles and spec.profile not in profiles and spec.profile != "runtime":
            continue
        loc = _find_tool(spec)
        ver = _probe_version(spec, loc) if (loc and verify_versions) else ("installed" if loc else "")
        results.append({
            "name": spec.name,
            "profile": spec.profile,
            "description": spec.description,
            "installed": loc is not None,
            "location": loc,
            "version": ver,
        })
    return {
        "os": platform.system(),
        "python": platform.python_version(),
        "package_managers": {k: bool(v) for k, v in managers.items()},
        "tools": results,
    }


def _install_tool(spec: ToolSpec, managers: dict[str, str | None], verbose: bool = False) -> dict[str, Any]:
    system = platform.system().lower()
    attempts: list[tuple[str, list[str]]] = []

    if system == "windows":
        if spec.scoop_pkg and managers.get("scoop"):
            if spec.scoop_bucket:
                if verbose:
                    print(f"[*] Ensuring Scoop bucket '{spec.scoop_bucket}'...", file=sys.stderr)
                _run_cmd([managers["scoop"], "bucket", "add", spec.scoop_bucket], timeout=120)
            attempts.append((f"scoop install {spec.scoop_pkg}", [managers["scoop"], "install", spec.scoop_pkg]))
        if spec.winget_id and managers.get("winget"):
            attempts.append((
                f"winget install {spec.winget_id}",
                [
                    managers["winget"], "install", "--id", spec.winget_id, "-e",
                    "--accept-package-agreements", "--accept-source-agreements", "--silent",
                ],
            ))
        if spec.choco_pkg and managers.get("choco"):
            attempts.append((f"choco install {spec.choco_pkg}", [managers["choco"], "install", spec.choco_pkg, "-y"]))
    else:
        if spec.brew_pkg and managers.get("brew"):
            brew = managers["brew"]
            cmd = [brew, "install", "--cask", spec.brew_pkg] if spec.brew_cask else [brew, "install", spec.brew_pkg]
            attempts.append((" ".join(["brew", *cmd[1:]]), cmd))

    if spec.pip_pkg and not spec.isolated_venv:
        attempts.append((f"pip install {spec.pip_pkg}", [sys.executable, "-m", "pip", "install", "--quiet", spec.pip_pkg]))

    if spec.isolated_venv and spec.pip_pkg:
        venv_dir = VENV_ROOT / spec.name
        bin_dir = "Scripts" if os.name == "nt" else "bin"
        venv_py = venv_dir / bin_dir / ("python.exe" if os.name == "nt" else "python")
        if verbose:
            print(f"[*] Installing {spec.name} in isolated venv: {venv_dir}", file=sys.stderr)
        try:
            venv_dir.parent.mkdir(parents=True, exist_ok=True)
            if not venv_py.exists():
                v_code, v_out = _run_cmd([sys.executable, "-m", "venv", str(venv_dir)], timeout=120)
                if v_code != 0:
                    raise RuntimeError(f"venv creation failed: {v_out[-250:]}")
            p_code, p_out = _run_cmd([str(venv_py), "-m", "pip", "install", "--quiet", spec.pip_pkg], timeout=300)
            if p_code == 0:
                if os.name == "nt":
                    raw_script = venv_dir / "Scripts" / spec.name
                    exe_file = venv_dir / "Scripts" / f"{spec.name}.exe"
                    cmd_shim = venv_dir / "Scripts" / f"{spec.name}.cmd"
                    if raw_script.exists() and not exe_file.exists():
                        cmd_shim.write_text(f'@echo off\r\n"%~dp0python.exe" "%~dp0{spec.name}" %*\r\n', encoding="utf-8")
                loc = _find_tool(spec)
                return {
                    "name": spec.name,
                    "status": "installed" if loc else "installed_restart_path",
                    "method": f"isolated venv pip install {spec.pip_pkg}",
                    "location": loc,
                }
            errors.append(f"isolated venv pip install {spec.pip_pkg} -> exit {p_code}: {p_out[-250:]}")
        except Exception as exc:  # noqa: BLE001
            errors.append(f"isolated venv {spec.name} -> {exc}")

    if not attempts:
        return {"name": spec.name, "status": "skipped", "reason": "No supported package manager configured for this OS"}

    errors: list[str] = []
    for label, cmd in attempts:
        if verbose:
            print(f"[*] Installing {spec.name} via: {label}", file=sys.stderr)
        try:
            code, out = _run_cmd(cmd, timeout=300)
            if code == 0:
                loc = _find_tool(spec)
                post_note = ""
                if spec.post_install_cmd and loc:
                    if verbose:
                        print(f"[*] Running post-install setup for {spec.name}...", file=sys.stderr)
                    try:
                        p_code, p_out = _run_cmd(list(spec.post_install_cmd), timeout=240)
                        if p_code != 0:
                            post_note = f" (post-setup exited {p_code})"
                    except Exception as p_exc:  # noqa: BLE001
                        post_note = f" (post-setup warning: {p_exc})"
                return {
                    "name": spec.name,
                    "status": "installed" if loc else "installed_restart_path",
                    "method": label + post_note,
                    "location": loc,
                }
            errors.append(f"{label} -> exit {code}: {out[-250:]}")
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{label} -> {exc}")

    return {"name": spec.name, "status": "failed", "reason": " | ".join(errors)}


def format_markdown(status: dict[str, Any], install_actions: list[dict[str, Any]] | None = None) -> str:
    tools = status["tools"]
    installed_cnt = sum(1 for t in tools if t["installed"])
    missing = [t["name"] for t in tools if not t["installed"]]
    pms = ", ".join(k for k, ok in status["package_managers"].items() if ok) or "none"

    lines = [
        "# Security Skill Prerequisites Report",
        f"- **Platform**: {status['os']} | **Python**: {status['python']}",
        f"- **Detected Package Managers**: {pms}",
        f"- **Checked Tools**: {len(tools)} | **Installed**: {installed_cnt} | **Missing**: {len(missing)}",
        "",
        "| Tool | Profile | Status | Location / Version | Purpose |",
        "|:---|:---|:---|:---|:---|",
    ]
    for t in tools:
        st = "Installed" if t["installed"] else "Missing"
        loc = t["version"] if (t["version"] and t["version"] != "installed") else (t["location"] or "-")
        lines.append(f"| `{t['name']}` | `{t['profile']}` | {st} | `{loc}` | {t['description']} |")

    if install_actions:
        lines.append("\n## Download & Setup Actions")
        for act in install_actions:
            detail = act.get("method") or act.get("reason", "")
            lines.append(f"- **`{act['name']}`**: `{act['status']}` ({detail})")
    return "\n".join(lines)


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(description="Check & auto-install Security Skill prerequisites")
    parser.add_argument("--check", action="store_true", help="Check prerequisite status (default action)")
    parser.add_argument("--install", action="store_true", help="Download and set up missing prerequisites automatically")
    parser.add_argument(
        "--profile",
        default="core,web,python",
        help="Comma-separated tool profiles to check/install (core,web,python,sast,iac,all). Default: core,web,python",
    )
    parser.add_argument("--tools", help="Explicit comma-separated tool names to install/check (overrides --profile)")
    parser.add_argument("--verify", action="store_true", help="Probe installed tool versions")
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown", help="Output format")
    parser.add_argument("--verbose", action="store_true", help="Print progress to stderr")
    args = parser.parse_args()

    raw_profiles = {p.strip().lower() for p in args.profile.split(",") if p.strip()}
    if "all" in raw_profiles:
        target_profiles = {"runtime", "core", "web", "python", "sast", "iac"}
    else:
        target_profiles = raw_profiles | {"runtime"}

    explicit_tools = {t.strip().lower() for t in args.tools.split(",") if t.strip()} if args.tools else None

    install_actions: list[dict[str, Any]] = []
    if args.install:
        managers = detect_managers()
        for spec in TOOLS:
            if explicit_tools is not None:
                if spec.name.lower() not in explicit_tools:
                    continue
            elif spec.profile not in target_profiles or spec.profile == "runtime":
                # Runtimes (python/java/git/npm) are only auto-installed if explicitly named in --tools
                continue
            if _find_tool(spec) is not None:
                install_actions.append({"name": spec.name, "status": "already_installed", "method": _find_tool(spec)})
                continue
            install_actions.append(_install_tool(spec, managers, verbose=args.verbose))

    status = check_prerequisites(None if explicit_tools else target_profiles, verify_versions=args.verify or args.install)
    if explicit_tools is not None:
        status["tools"] = [t for t in status["tools"] if t["name"].lower() in explicit_tools]

    if args.format == "json":
        payload: dict[str, Any] = dict(status)
        if install_actions:
            payload["install_actions"] = install_actions
        print(json.dumps(payload, indent=2))
    else:
        print(format_markdown(status, install_actions or None))

    if args.install and any(a["status"] == "failed" for a in install_actions):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
