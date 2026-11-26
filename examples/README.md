# Examples

| File | What it is |
|:---|:---|
| [prompts.md](./prompts.md) | Copy-paste prompts for quick checks, full audits, focused reviews, DAST and CI |
| [sample-report.md](./sample-report.md) | A full audit report in the skill's report format |
| [juice-shop-report.md](./juice-shop-report.md) | Sample audit of OWASP Juice Shop `v20.4.0` (`routes/` and `lib/`) |
| [sample-scan.json](./sample-scan.json) | Raw `loophole_scanner.py --format json` output for the demo app |
| [demo/](./demo/) | 60-second demo script and recording plan against OWASP Juice Shop |
| [vulnerable-flask-app/](./vulnerable-flask-app/) | A small, intentionally vulnerable Flask app to try the skill on. **Never deploy it.** |

The Python file is stored as `app.py.demo` so GitHub code scanning does not report the intentional vulnerabilities as
alerts on this repository. Copy it out before trying the skill:

```bash
cp -r examples/vulnerable-flask-app /tmp/vuln-demo && mv /tmp/vuln-demo/app.py.demo /tmp/vuln-demo/app.py
python scripts/loophole_scanner.py --target /tmp/vuln-demo
```
