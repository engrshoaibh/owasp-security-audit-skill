#!/usr/bin/env python3
"""
OWASP ZAP (Zed Attack Proxy) Python Automation Wrapper for Web & API Security Audits.
Uses Python standard library only (no external packages required) to talk directly
to a running OWASP ZAP daemon REST API, or run official ZAP Docker containers.

Official website: https://www.zaproxy.org/

Usage examples:
  # 1. Check local ZAP / Docker availability
  python scripts/zap_web_scan.py --check

  # 2. Safe passive baseline scan (auto-starts & cleans up local ZAP daemon if needed)
  python scripts/zap_web_scan.py --target http://localhost:3000 --mode baseline

  # 3. OpenAPI / GraphQL / SOAP schema scan (local ZAP daemon or Docker)
  python scripts/zap_web_scan.py --target http://localhost:8000/openapi.json --mode api --api-format openapi

  # 4. Active vulnerability attack scan (SQLi, XSS, SSRF, CmdInj — authorized dev/staging ONLY)
  python scripts/zap_web_scan.py --target http://localhost:3000 --mode full --confirm-authorized
"""

from __future__ import annotations

import argparse
import contextlib
import importlib.util
import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterator
from pathlib import Path
from typing import Any

DOCKER_ZAP_IMAGE = "ghcr.io/zaproxy/zaproxy:stable"

COMMON_ZAP_PATHS = [
    str(Path.home() / "scoop" / "apps" / "zaproxy" / "current" / "zap.bat"),
    str(Path.home() / "scoop" / "shims" / "zap.cmd"),
    r"C:\Program Files\ZAP\Zed Attack Proxy\zap.bat",
    r"C:\Program Files (x86)\ZAP\Zed Attack Proxy\zap.bat",
    "/usr/share/zaproxy/zap.sh",
    "/opt/zaproxy/zap.sh",
    "/Applications/ZAP.app/Contents/Java/zap.sh",
]

RISK_ORDER = {"High": 0, "Medium": 1, "Low": 2, "Informational": 3}


class ScanIncomplete(RuntimeError):
    """Raised when a scan did not finish, so its results must not be reported as a clean pass."""

    def __init__(self, reason: str, partial_alerts: list[dict[str, Any]]):
        super().__init__(reason)
        self.partial_alerts = partial_alerts

ALERT_MODULE_MAP = [
    (("sql", "injection"), "1.2.2 / 6A.1 SQL Injection"),
    (("cross site scripting", "xss"), "4.1 XSS Prevention"),
    (("csrf", "anti-csrf", "cross-site request"), "4.3 CSRF Prevention"),
    (("content security policy", "csp"), "4.2 Content Security Policy"),
    (("cors", "cross-domain"), "4.3.3 / 7A CORS"),
    (("cookie", "httponly", "samesite", "secure flag"), "2.2.2 Session Cookies"),
    (("strict-transport-security", "hsts", "tls", "ssl", "cleartext"), "1.1 Transport Layer Security"),
    (("x-frame-options", "clickjack", "frame-ancestors"), "4.2.3 Clickjacking Defense"),
    (("x-content-type-options", "nosniff", "header"), "4.4 HTTP Security Headers"),
    (("redirect",), "4.6 / 14.5 Unvalidated Redirects"),
    (("path traversal", "directory", "file inclusion"), "1.2.4 Path Traversal"),
    (("ssrf", "server side request"), "14 SSRF Prevention"),
    (("stack trace", "error", "debug", "disclosure", "server leaks", "x-powered-by"), "1.3 Error Handling & Info Disclosure"),
    (("jwt", "token", "session", "auth"), "2 Auth & Session Management"),
]


def map_alert_to_module(alert_name: str) -> str:
    low = alert_name.lower()
    for keywords, module in ALERT_MODULE_MAP:
        if any(k in low for k in keywords):
            return module
    return "4 / 7A Web & API Security"


def find_local_zap() -> str | None:
    for name in ("zap", "zap.cmd", "zap.bat", "zap.sh", "zaproxy"):
        found = shutil.which(name)
        if found:
            return found
    for candidate in COMMON_ZAP_PATHS:
        if Path(candidate).exists():
            return candidate
    return None


def validate_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError(f"Invalid target URL '{url}'. Expected http:// or https:// URL.")
    return url


def zap_api_get(zap_url: str, path: str, params: dict[str, Any] | None = None, api_key: str | None = None, timeout: int = 15) -> dict[str, Any]:
    query: dict[str, Any] = dict(params or {})
    qs = urllib.parse.urlencode({k: v for k, v in query.items() if v is not None})
    endpoint = f"{zap_url.rstrip('/')}{path}"
    if qs:
        endpoint = f"{endpoint}?{qs}"

    headers = {"Accept": "application/json"}
    if api_key:
        # Header instead of ?apikey= so the key does not end up in ZAP / proxy access logs.
        headers["X-ZAP-API-Key"] = api_key
    req = urllib.request.Request(endpoint, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"ZAP API HTTP {exc.code} on {path}: {body[:300]}") from exc
    except urllib.error.URLError as exc:
        raise ConnectionError(f"Cannot reach ZAP daemon at {zap_url}: {exc.reason}") from exc


def check_environment(zap_url: str, api_key: str | None) -> dict[str, Any]:
    daemon_version = None
    daemon_error = None
    try:
        data = zap_api_get(zap_url, "/JSON/core/view/version/", api_key=api_key, timeout=4)
        daemon_version = data.get("version")
    except Exception as exc:
        daemon_error = str(exc)

    local_bin = find_local_zap()
    docker_bin = shutil.which("docker")
    zaproxy_pkg = importlib.util.find_spec("zapv2") is not None

    return {
        "zap_url": zap_url,
        "daemon_running": daemon_version is not None,
        "daemon_version": daemon_version,
        "daemon_error": daemon_error,
        "local_zap_binary": local_bin,
        "docker_installed": bool(docker_bin),
        "python_zaproxy_installed": zaproxy_pkg,
    }


def print_setup_guide(env: dict[str, Any]) -> None:
    print("# OWASP ZAP Environment Check")
    print(f"- **ZAP Daemon (`{env['zap_url']}`)**: {'RUNNING (v' + str(env['daemon_version']) + ')' if env['daemon_running'] else 'Not running (auto-started on demand when local ZAP is present)'}")
    print(f"- **Local ZAP Binary**: `{env['local_zap_binary']}`" if env["local_zap_binary"] else "- **Local ZAP Binary**: Not found")
    print(f"- **Docker CLI**: {'Available' if env['docker_installed'] else 'Not installed'}")
    print(f"- **Python `zaproxy` (`zapv2`) package**: {'Installed' if env['python_zaproxy_installed'] else 'Not installed (optional — stdlib client built-in)'}")
    if env["local_zap_binary"] or env["daemon_running"] or env["docker_installed"]:
        print("\nReady: `zap_web_scan.py` manages ZAP startup and shutdown automatically (`--engine auto`).")
        return
    print("\n## Missing ZAP Runtime (For Agent Installation)")
    print("- Windows: `winget install ZAP.ZAP` or `scoop bucket add extras; scoop install zaproxy`")
    print("- macOS: `brew install --cask zap`")
    print(f"- Docker fallback: `docker pull {DOCKER_ZAP_IMAGE}`")


def _pick_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _build_zap_launch_command(zap_bin: str, args: list[str]) -> tuple[list[str], Path | None]:
    zap_path = Path(zap_bin).resolve()
    if os.name == "nt" and zap_bin.lower().endswith((".bat", ".cmd")):
        return ["cmd.exe", "/c", str(zap_path), *args], zap_path.parent
    return [str(zap_path), *args], zap_path.parent


def _read_log_tail(log_path: Path, max_chars: int = 2000) -> str:
    if not log_path.exists():
        return ""
    return log_path.read_text(encoding="utf-8", errors="replace")[-max_chars:].strip()


@contextlib.contextmanager
def managed_zap_daemon(
    zap_bin: str,
    startup_timeout: int = 90,
    verbose: bool = False,
) -> Iterator[tuple[str, str]]:
    """Launch an isolated ephemeral ZAP daemon on a free port and cleanly tear it down."""
    port = _pick_free_port()
    api_key = secrets.token_hex(16)
    zap_url = f"http://127.0.0.1:{port}"
    zap_dir = Path(tempfile.mkdtemp(prefix="zap_agent_"))
    log_path = zap_dir / "zap_daemon.log"

    zap_args = [
        "-daemon",
        "-silent",
        "-host",
        "127.0.0.1",
        "-port",
        str(port),
        "-dir",
        str(zap_dir),
        "-config",
        f"api.key={api_key}",
    ]
    cmd, cwd = _build_zap_launch_command(zap_bin, zap_args)
    if verbose:
        print(f"[*] Auto-starting isolated ZAP daemon on {zap_url}...", file=sys.stderr)

    proc: subprocess.Popen[str] | None = None
    try:
        with open(log_path, "w", encoding="utf-8", errors="replace") as log_file:
            try:
                proc = subprocess.Popen(
                    cmd,
                    cwd=str(cwd) if cwd and cwd.exists() else None,
                    stdin=subprocess.DEVNULL,
                    stdout=log_file,
                    stderr=subprocess.STDOUT,
                    text=True,
                )
                deadline = time.monotonic() + startup_timeout
                last_err = ""
                while time.monotonic() < deadline:
                    if proc.poll() is not None:
                        log_file.flush()
                        raise RuntimeError(
                            f"Managed ZAP daemon exited early (code {proc.returncode}).\n{_read_log_tail(log_path)}"
                        )
                    try:
                        ver = zap_api_get(zap_url, "/JSON/core/view/version/", api_key=api_key, timeout=3)
                        if "version" in ver:
                            if verbose:
                                print(f"[*] Managed ZAP v{ver['version']} ready.", file=sys.stderr)
                            break
                    except Exception as exc:  # noqa: BLE001
                        last_err = str(exc)
                    time.sleep(1.5)
                else:
                    log_file.flush()
                    raise TimeoutError(
                        f"Managed ZAP daemon did not respond within {startup_timeout}s ({last_err}).\n{_read_log_tail(log_path)}"
                    )

                yield zap_url, api_key
            finally:
                try:
                    zap_api_get(zap_url, "/JSON/core/action/shutdown/", api_key=api_key, timeout=5)
                except Exception:  # noqa: BLE001
                    pass
                if proc is not None:
                    try:
                        proc.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        if os.name == "nt":
                            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], capture_output=True)
                        else:
                            proc.terminate()
                            try:
                                proc.wait(timeout=5)
                            except subprocess.TimeoutExpired:
                                proc.kill()
    finally:
        # Remove zap_dir after log_file handle closes (Windows file-lock safe)
        for _ in range(5):
            if not zap_dir.exists():
                break
            try:
                shutil.rmtree(zap_dir)
                break
            except PermissionError:
                time.sleep(0.3)
        shutil.rmtree(zap_dir, ignore_errors=True)


def run_daemon_scan(
    zap_url: str,
    api_key: str | None,
    target: str,
    mode: str,
    max_wait_sec: int,
    verbose: bool = False,
    api_format: str = "openapi",
    active_scan_api: bool = False,
) -> list[dict[str, Any]]:
    if mode == "full" and not active_scan_api:
        # Defence in depth: never start active attacks unless the caller passed explicit authorization.
        raise PermissionError("Active scan requested without --confirm-authorized.")
    parsed = urllib.parse.urlparse(target)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    deadline = time.monotonic() + max_wait_sec
    incomplete: list[str] = []

    if mode == "api":
        if verbose:
            print(f"[*] Importing {api_format.upper()} specification into ZAP: {target}", file=sys.stderr)
        if api_format == "openapi":
            zap_api_get(zap_url, "/JSON/openapi/action/importUrl/", {"url": target, "hostOverride": base_url}, api_key, timeout=30)
        elif api_format == "graphql":
            zap_api_get(zap_url, "/JSON/graphql/action/importUrl/", {"url": target, "endurl": target}, api_key, timeout=30)
        elif api_format == "soap":
            zap_api_get(zap_url, "/JSON/soap/action/importUrl/", {"url": target}, api_key, timeout=30)
    else:
        # Seed target URL so ZAP registers it in the Sites tree
        if verbose:
            print(f"[*] Seeding target URL in ZAP: {target}", file=sys.stderr)
        zap_api_get(zap_url, "/JSON/core/action/accessUrl/", {"url": target, "followRedirects": "false"}, api_key)
        time.sleep(1)

        # Phase 1: Spider
        if verbose:
            print(f"[*] Starting ZAP Spider on {target}...", file=sys.stderr)
        spider_resp = zap_api_get(zap_url, "/JSON/spider/action/scan/", {"url": target, "recurse": "true"}, api_key)
        scan_id = spider_resp.get("scan")
        if scan_id is None:
            raise RuntimeError(f"Unexpected ZAP spider response: {spider_resp}")

        while True:
            status = int(zap_api_get(zap_url, "/JSON/spider/view/status/", {"scanId": scan_id}, api_key).get("status", 100))
            if verbose:
                print(f"    Spider progress: {status}%", file=sys.stderr)
            if status >= 100:
                break
            if time.monotonic() >= deadline:
                incomplete.append(f"spider stopped at {status}% (timeout)")
                zap_api_get(zap_url, "/JSON/spider/action/stop/", {"scanId": scan_id}, api_key)
                break
            time.sleep(2)

    # Phase 2: Wait for Passive Scanner queue to drain
    if verbose:
        print("[*] Draining Passive Scanner queue...", file=sys.stderr)
    remaining = 0
    while True:
        remaining = int(zap_api_get(zap_url, "/JSON/pscan/view/recordsToScan/", api_key=api_key).get("recordsToScan", 0))
        if remaining <= 0:
            break
        if time.monotonic() >= deadline:
            incomplete.append(f"passive scan left {remaining} records unscanned (timeout)")
            break
        time.sleep(1)

    # Phase 3: Active Scan (only when explicitly requested + authorized)
    if mode == "full" or (mode == "api" and active_scan_api):
        if verbose:
            print(f"[*] Starting Active Scan on {base_url}...", file=sys.stderr)
        # Scope the active scan to the authorized target URL, not every path on the host.
        ascan_resp = zap_api_get(zap_url, "/JSON/ascan/action/scan/", {"url": target, "recurse": "true"}, api_key)
        ascan_id = ascan_resp.get("scan")
        if ascan_id is None:
            raise RuntimeError(f"Unexpected ZAP active scan response: {ascan_resp}")
        while True:
            status = int(zap_api_get(zap_url, "/JSON/ascan/view/status/", {"scanId": ascan_id}, api_key).get("status", 100))
            if verbose:
                print(f"    Active scan progress: {status}%", file=sys.stderr)
            if status >= 100:
                break
            if time.monotonic() >= deadline:
                incomplete.append(f"active scan stopped at {status}% (timeout)")
                zap_api_get(zap_url, "/JSON/ascan/action/stop/", {"scanId": ascan_id}, api_key)
                break
            time.sleep(3)

    alerts_resp = zap_api_get(zap_url, "/JSON/core/view/alerts/", {"baseurl": base_url}, api_key, timeout=30)
    alerts = alerts_resp.get("alerts", [])
    if incomplete:
        raise ScanIncomplete("; ".join(incomplete), alerts)
    return alerts


def run_docker_scan(
    target: str,
    mode: str,
    api_format: str,
    work_dir: Path,
    authorized: bool = False,
) -> tuple[int, list[dict[str, Any]], str]:
    if mode == "full" and not authorized:
        raise PermissionError("Active scan requested without --confirm-authorized.")
    work_dir.mkdir(parents=True, exist_ok=True)
    json_name = f"zap-{mode}-report.json"
    html_name = f"zap-{mode}-report.html"

    script_map = {
        "baseline": "zap-baseline.py",
        "api": "zap-api-scan.py",
        "full": "zap-full-scan.py",
    }
    zap_script = script_map[mode]
    cmd = [
        "docker", "run", "--rm",
        "-v", f"{work_dir.resolve()}:/zap/wrk:rw",
        "-t", DOCKER_ZAP_IMAGE,
        zap_script,
        "-t", target,
        "-J", json_name,
        "-r", html_name,
    ]
    if mode == "api":
        cmd.extend(["-f", api_format])
        if not authorized:
            # zap-api-scan.py runs an ACTIVE scan by default; -S (safe mode) limits it to a passive baseline.
            cmd.append("-S")

    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=900)
    report_path = work_dir / json_name
    alerts: list[dict[str, Any]] = []
    if report_path.exists():
        raw = json.loads(report_path.read_text(encoding="utf-8", errors="replace"))
        for site in raw.get("site", []):
            for alert in site.get("alerts", []):
                risk_desc = alert.get("riskdesc", "Informational")
                risk = risk_desc.split()[0] if risk_desc else "Informational"
                alerts.append({
                    "alert": alert.get("name") or alert.get("alert"),
                    "risk": risk,
                    "confidence": alert.get("confidence", ""),
                    "cweid": alert.get("cweid", ""),
                    "wascid": alert.get("wascid", ""),
                    "count": alert.get("count", "1"),
                    "url": (alert.get("instances") or [{}])[0].get("uri", target),
                    "solution": alert.get("solution", ""),
                })
    if not report_path.exists():
        # No report means the scan did not run (bad target, Docker error). Never treat that as "no alerts".
        raise ScanIncomplete(f"ZAP Docker scan produced no report (exit {proc.returncode}): "
                             f"{(proc.stderr or proc.stdout or '').strip()[-400:]}", [])
    return proc.returncode, alerts, (proc.stdout or proc.stderr).strip()


def deduplicate_alerts(alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    for a in alerts:
        name = a.get("alert") or a.get("name") or "Unknown Alert"
        risk = a.get("risk", "Informational")
        occ = int(a.get("count", 1)) if str(a.get("count", "")).isdigit() else 1
        key = (risk, name)
        if key not in grouped:
            grouped[key] = {
                "alert": name,
                "risk": risk,
                "confidence": a.get("confidence", ""),
                "cweid": a.get("cweid", ""),
                "module": map_alert_to_module(name),
                "sample_url": a.get("url", ""),
                "occurrences": occ,
                "solution": (a.get("solution") or "").strip().replace("<p>", "").replace("</p>", " "),
            }
        else:
            grouped[key]["occurrences"] += occ

    items = list(grouped.values())
    items.sort(key=lambda x: (RISK_ORDER.get(x["risk"], 9), x["alert"]))
    return items


def format_markdown(target: str, mode: str, engine: str, alerts: list[dict[str, Any]]) -> str:
    counts = {r: sum(1 for a in alerts if a["risk"] == r) for r in ("High", "Medium", "Low", "Informational")}
    lines = [
        "# OWASP ZAP Web Security Scan Report",
        f"- **Target**: `{target}`",
        f"- **Mode / Engine**: `{mode}` / `{engine}`",
        f"- **Unique Alert Types**: {len(alerts)} (High: {counts['High']}, Medium: {counts['Medium']}, Low: {counts['Low']}, Info: {counts['Informational']})",
        "",
    ]
    if not alerts:
        lines.append("No alerts reported by OWASP ZAP.")
        return "\n".join(lines)

    lines.append("| Risk | Alert | Skill Module | Occurrences | Sample URL |")
    lines.append("|:---|:---|:---|:---|:---|")
    for a in alerts:
        lines.append(f"| {a['risk']} | {a['alert']} | {a['module']} | {a['occurrences']} | `{a['sample_url']}` |")
    return "\n".join(lines)


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(description="OWASP ZAP Python automation scanner for Web & APIs")
    parser.add_argument("--check", action="store_true", help="Check local ZAP/Docker/Python environment and exit")
    parser.add_argument("--target", help="Authorized dev/staging web or API URL (http:// or https://)")
    parser.add_argument("--mode", choices=("baseline", "api", "full"), default="baseline", help="Scan mode (default: baseline passive)")
    parser.add_argument("--api-format", choices=("openapi", "soap", "graphql"), default="openapi", help="API spec type for --mode api")
    parser.add_argument("--engine", choices=("auto", "local", "daemon", "docker"), default="auto", help="Execution backend (auto prefers running daemon -> managed local ZAP -> Docker)")
    parser.add_argument("--zap-url", default=os.environ.get("ZAP_URL", "http://127.0.0.1:8080"), help="Existing ZAP daemon URL")
    parser.add_argument("--api-key", default=os.environ.get("ZAP_API_KEY"), help="ZAP API key (or set ZAP_API_KEY)")
    parser.add_argument("--work-dir", default="zap-reports", help="Output folder for Docker HTML/JSON reports")
    parser.add_argument("--timeout", type=int, default=300, help="Max scan wait seconds for daemon/local mode")
    parser.add_argument("--startup-timeout", type=int, default=90, help="Max wait seconds for auto-started local ZAP daemon")
    parser.add_argument("--confirm-authorized", action="store_true", help="Required flag before running active attacks (--mode full, or active phase of --mode api)")
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown", help="Output format")
    parser.add_argument("--fail-on", choices=("high", "medium", "low", "none"), default="none", help="Exit 1 if alerts meet severity threshold")
    parser.add_argument("--verbose", action="store_true", help="Print scan progress to stderr")
    args = parser.parse_args()

    env = check_environment(args.zap_url, args.api_key)
    if args.check:
        if args.format == "json":
            print(json.dumps(env, indent=2))
        else:
            print_setup_guide(env)
        return 0

    if not args.target:
        parser.error("--target is required unless --check is specified.")

    try:
        target = validate_url(args.target)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    if args.mode == "full" and not args.confirm_authorized:
        print(
            "Refusing active attack scan without explicit authorization flag.\n"
            "Re-run with --confirm-authorized ONLY for authorized dev/staging targets, or use --mode baseline.",
            file=sys.stderr,
        )
        return 2

    engine = args.engine
    if engine == "auto":
        if env["daemon_running"]:
            engine = "daemon"
        elif env["local_zap_binary"]:
            engine = "local"
        elif env["docker_installed"]:
            engine = "docker"
        else:
            print_setup_guide(env)
            return 3

    incomplete_reason: str | None = None
    try:
        if engine == "daemon":
            if not env["daemon_running"]:
                print(f"Error: ZAP daemon not reachable at {args.zap_url}. Use --engine local or --engine auto to auto-start ZAP.", file=sys.stderr)
                return 3
            raw_alerts = run_daemon_scan(
                args.zap_url,
                args.api_key,
                target,
                args.mode,
                args.timeout,
                args.verbose,
                api_format=args.api_format,
                active_scan_api=args.confirm_authorized,
            )
        elif engine == "local":
            zap_bin = env["local_zap_binary"]
            if not zap_bin:
                print("Error: Local ZAP binary not found. Install ZAP or run with --engine docker.", file=sys.stderr)
                return 3
            with managed_zap_daemon(zap_bin, startup_timeout=args.startup_timeout, verbose=args.verbose) as (zap_url, api_key):
                raw_alerts = run_daemon_scan(
                    zap_url,
                    api_key,
                    target,
                    args.mode,
                    args.timeout,
                    args.verbose,
                    api_format=args.api_format,
                    active_scan_api=args.confirm_authorized,
                )
        else:
            if not env["docker_installed"]:
                print("Error: Docker is not installed. Use --engine local or run --check for details.", file=sys.stderr)
                return 3
            _, raw_alerts, _ = run_docker_scan(target, args.mode, args.api_format, Path(args.work_dir),
                                          authorized=args.confirm_authorized)
    except ScanIncomplete as exc:
        # Fail closed: report what we have, but mark the run incomplete and exit non-zero.
        incomplete_reason = str(exc)
        raw_alerts = exc.partial_alerts
    except PermissionError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    alerts = deduplicate_alerts(raw_alerts)
    if args.format == "json":
        print(json.dumps({"target": target, "mode": args.mode, "engine": engine, "complete": incomplete_reason is None,
                          "incomplete_reason": incomplete_reason, "alerts": alerts}, indent=2))
    else:
        report = format_markdown(target, args.mode, engine, alerts)
        if incomplete_reason:
            report = f"> **INCOMPLETE SCAN:** {incomplete_reason}. Results below are partial.\n\n" + report
        print(report)

    if incomplete_reason:
        print(f"Scan incomplete: {incomplete_reason}", file=sys.stderr)
        return 3
    if args.fail_on != "none":
        threshold = {"high": 0, "medium": 1, "low": 2}[args.fail_on]
        # Unknown risk labels count as High so a parsing change can never turn into a silent pass.
        if any(RISK_ORDER.get(a["risk"], 0) <= threshold for a in alerts):
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
