# security-skill: ignore-file  (this file is full of intentionally vulnerable snippets)
"""Rule tests for scripts/loophole_scanner.py (stdlib unittest, no dependencies).

Each rule gets at least one snippet it must flag and one look-alike it must not flag.
Fake secrets are assembled at runtime so this file never contains a real-looking key.

Run: python -m unittest discover -s tests -v
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import loophole_scanner as ls  # noqa: E402

SAMPLE_AWS_ID = "AKIA" + "Z" * 4 + "7QWERTY2" + "ABCD"          # 20 chars, matches AKIA[0-9A-Z]{16}
SAMPLE_OPENAI = "sk-" + "proj-" + "a1B2c3D4e5F6g7H8i9J0kLmN"
SAMPLE_GITHUB = "gh" + "p_" + "A" * 36


def scan(files: dict[str, str], git: bool = False) -> list[ls.Finding]:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for rel, content in files.items():
            p = root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")
        if git:
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
        findings, _ = ls.scan_repo(root)
        return findings


def rule_ids(files: dict[str, str], **kw) -> set[str]:
    return {f.rule_id for f in scan(files, **kw)}


# (rule_id, filename, must_match, must_not_match)
CASES = [
    ("SEC-01", "app.py", f'key = "{SAMPLE_AWS_ID}"', 'key = "AKIA_NOT_A_KEY"'),
    ("SEC-03", "app.js", f'const k = "{SAMPLE_OPENAI}";', 'const k = process.env.OPENAI_API_KEY;'),
    ("SEC-04", "db.py", 'URL = "postgres://admin:Xk29fLq@prod-db.internal:5432/app"', 'URL = os.environ["DATABASE_URL"]'),
    ("SEC-05", "auth.js", "const s = process.env.JWT_SECRET || 'dev-secret';", "const s = process.env.JWT_SECRET;"),
    ("TLS-01", "client.py", "requests.get(url, verify=False)", "requests.get(url, verify=True)"),
    ("JWT-01", "auth.py", 'jwt.decode(tok, key, algorithms=["none"])', 'jwt.decode(tok, key, algorithms=["RS256"])'),
    ("CORS-01", "main.py", 'app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)',
     'app.add_middleware(CORSMiddleware, allow_origins=["https://a.com"], allow_credentials=True)'),
    ("DBG-01", "settings.py", "DEBUG = True", "DEBUG = os.getenv('DEBUG') == '1'"),
    ("COOKIE-01", "app.js", "app.use(session({ cookie: { secure: false } }))",
     "nodemailer.createTransport({ host, port: 587, secure: false })"),
    ("INJ-01", "repo.py", 'cur.execute(f"SELECT * FROM u WHERE id={uid}")', 'cur.execute("SELECT * FROM u WHERE id=%s", (uid,))'),
    ("INJ-02", "run.py", "subprocess.run(cmd, shell=True)", "subprocess.run(['ls', path])"),
    ("INJ-03", "calc.js", "const r = eval(userInput);", "model.eval()"),
    ("DESER-01", "load.py", "obj = pickle.loads(blob)", "obj = json.loads(blob)"),
    ("SSTI-01", "views.py", "return render_template_string(request.args['t'])", "return render_template_string('<p>hi</p>')"),
    ("XSS-01", "View.jsx", "<div dangerouslySetInnerHTML={{__html: html}} />", "<div>{html}</div>"),
    ("NOSQL-01", "api.js", "User.findOne(req.body)", "User.findOne({ email: String(req.body.email) })"),
    ("PATH-01", "files.js", "res.sendFile(path.join(base, req.params.name))", "res.sendFile(path.join(base, 'index.html'))"),
    ("XXE-01", "xml.py", "parser = etree.XMLParser(resolve_entities=True)", "parser = etree.XMLParser(resolve_entities=False)"),
    ("REDIR-01", "auth.js", "res.redirect(req.query.next)", "res.redirect('/dashboard')"),
    ("MASS-01", "UserController.php", "User::create($request->all());", "User::create($request->validated());"),
    ("CRYPTO-01", "auth.py", "h = hashlib.md5(password.encode()).hexdigest()", "h = hashlib.md5(file_bytes).hexdigest()"),
    ("CRYPTO-02", "token.js", "const resetToken = Math.random().toString(36);", "const resetToken = crypto.randomUUID();"),
    ("CRYPTO-03", "enc.py", "c = AES.new(k, AES.MODE_ECB)", "c = AES.new(k, AES.MODE_GCM)"),
    ("BAAS-01", "firestore.rules", "allow read, write: if true;", "allow read: if request.auth != null;"),
    ("LLM-01", "model.py", 'AutoModel.from_pretrained(name, trust_remote_code=True)', 'AutoModel.from_pretrained(name)'),
    ("LLM-02", "model.py", "state = torch.load(path)", "state = torch.load(path, weights_only=True)"),
    ("LLM-03", "agent.py", "tools = [PythonREPLTool()]", "tools = [search_tool]"),
    ("GHA-02", ".github/workflows/ci.yml", '      run: echo "${{ github.event.issue.title }}"', '      run: echo "$TITLE"'),
    ("GHA-03", ".github/workflows/ci.yml", "      - uses: someorg/some-action@v2",
     "      - uses: someorg/some-action@0123456789abcdef0123456789abcdef01234567 # v2"),
    ("LOOP-02", "agent.py", "ex = AgentExecutor(agent=a, tools=t)", "ex = AgentExecutor(agent=a, tools=t, max_iterations=5)"),
    ("LOOP-03", "worker.py", "while True:\n    poll()\n", "while True:\n    if done():\n        break\n"),
    ("SSRF-01", "fetch.py", "requests.get(url, allow_redirects=True)", "requests.get(url, allow_redirects=False)"),
]


class RuleCases(unittest.TestCase):
    def test_positive_and_negative_cases(self):
        for rule_id, fname, bad, good in CASES:
            with self.subTest(rule=rule_id, kind="positive"):
                self.assertIn(rule_id, rule_ids({fname: bad + "\n"}), f"{rule_id} should flag: {bad!r}")
            with self.subTest(rule=rule_id, kind="negative"):
                self.assertNotIn(rule_id, rule_ids({fname: good + "\n"}), f"{rule_id} should NOT flag: {good!r}")

    def test_every_line_rule_has_a_case(self):
        covered = {c[0] for c in CASES}
        # SEC-02 (PEM header) and LOOP-01 (ReDoS) are exercised in dedicated tests below.
        missing = {r.rule_id for r in ls.RULES} - covered - {"SEC-02", "LOOP-01", "BAAS-02"}
        self.assertFalse(missing, f"rules without test cases: {sorted(missing)}")

    def test_private_key_header(self):
        header = "-----BEGIN " + "RSA PRIVATE KEY-----"
        self.assertIn("SEC-02", rule_ids({"key.txt.py": f'K = """{header}"""\n'}))

    def test_redos(self):
        self.assertIn("LOOP-01", rule_ids({"v.py": 'r = re.compile(r"(a+)+$")\n'}))
        self.assertNotIn("LOOP-01", rule_ids({"v.py": 'r = re.compile(r"^[a-z]+$")\n'}))

    def test_supabase_rls(self):
        self.assertIn("BAAS-02", rule_ids({"p.sql": "using ((auth.jwt() -> 'user_metadata' ->> 'role') = 'admin');\n"}))


class FalsePositiveControls(unittest.TestCase):
    def test_pytorch_eval_and_literal_eval_not_flagged(self):
        ids = rule_ids({"train.py": "model.eval()\nx = ast.literal_eval(s)\n"})
        self.assertNotIn("INJ-03", ids)

    def test_localhost_connection_string_is_low(self):
        f = scan({"docker.py": 'URL = "postgres://app:Xk29fLq@localhost:5432/app"\n'})
        sec = [x for x in f if x.rule_id == "SEC-04"]
        self.assertTrue(sec)
        self.assertEqual(sec[0].severity, "Low")

    def test_test_paths_are_downgraded(self):
        f = scan({"tests/test_x.py": "subprocess.run(cmd, shell=True)\n"})
        inj = [x for x in f if x.rule_id == "INJ-02"][0]
        self.assertEqual(inj.severity, "Medium")
        self.assertEqual(inj.context, "non-production")
        self.assertEqual(inj.confidence, "low")

    def test_secrets_in_tests_keep_severity(self):
        f = scan({"tests/test_x.py": f'k = "{SAMPLE_AWS_ID}"\n'})
        self.assertEqual([x for x in f if x.rule_id == "SEC-01"][0].severity, "Critical")

    def test_inline_suppression_specific_rule(self):
        src = "subprocess.run(cmd, shell=True)  # security-skill: ignore[INJ-02]\n"
        self.assertNotIn("INJ-02", rule_ids({"a.py": src}))

    def test_inline_suppression_previous_line(self):
        src = "# security-skill: ignore\nsubprocess.run(cmd, shell=True)\n"
        self.assertNotIn("INJ-02", rule_ids({"a.py": src}))

    def test_suppression_for_other_rule_does_not_hide(self):
        src = "subprocess.run(cmd, shell=True)  # security-skill: ignore[XSS-01]\n"
        self.assertIn("INJ-02", rule_ids({"a.py": src}))

    def test_ignore_file_marker(self):
        src = "# security-skill: ignore-file\nsubprocess.run(cmd, shell=True)\n"
        self.assertNotIn("INJ-02", rule_ids({"fixture.py": src}))
        # The marker only counts near the top of the file.
        late = "\n" * 10 + "# security-skill: ignore-file\nsubprocess.run(cmd, shell=True)\n"
        self.assertIn("INJ-02", rule_ids({"fixture.py": late}))

    def test_clean_gitignore_repo_has_no_git_findings(self):
        ids = rule_ids({".gitignore": "node_modules/\n", "app.py": "print('hi')\n"}, git=True)
        self.assertFalse({i for i in ids if i.startswith("GIT-")})


class ValueMasking(unittest.TestCase):
    def test_snippets_never_contain_full_secret(self):
        for sample in (SAMPLE_AWS_ID, SAMPLE_OPENAI, SAMPLE_GITHUB):
            with self.subTest(sample=sample[:6]):
                f = scan({"c.py": f'k = "{sample}"\n'})
                self.assertTrue(f)
                for finding in f:
                    self.assertNotIn(sample, finding.snippet)

    def test_connection_string_password_masked(self):
        f = scan({"db.py": 'URL = "postgres://admin:Xk29fLq@prod-db.internal:5432/app"\n'})
        self.assertNotIn("Xk29fLq", f[0].snippet)

    def test_redact_tool_output(self):
        out = ls.redact_text(f'Found: {SAMPLE_AWS_ID}\nRaw result: {SAMPLE_OPENAI}\n')
        self.assertNotIn(SAMPLE_AWS_ID, out)
        self.assertNotIn(SAMPLE_OPENAI, out)


class FileChecks(unittest.TestCase):
    def test_tracked_env_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".env").write_text("A=1\n")
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            subprocess.run(["git", "add", ".env"], cwd=root, check=True)
            ids = {f.rule_id for f in ls.scan_repo(root)[0]}
            self.assertIn("GIT-03", ids)

    def test_unignored_env_file(self):
        ids = rule_ids({".env": "A=1\n", ".gitignore": "node_modules/\n"}, git=True)
        self.assertIn("GIT-02", ids)

    def test_ignored_env_file(self):
        ids = rule_ids({".env": "A=1\n", ".gitignore": ".env\n"}, git=True)
        self.assertFalse({i for i in ids if i.startswith("GIT-")})

    def test_pull_request_target_checkout(self):
        wf = (
            "on: pull_request_target\njobs:\n  b:\n    steps:\n      - uses: actions/checkout@v4\n"
            "        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
        )
        self.assertIn("GHA-01", rule_ids({".github/workflows/pr.yml": wf}))
        self.assertNotIn("GHA-01", rule_ids({".github/workflows/pr.yml": wf.replace("pull_request_target", "pull_request")}))

    def test_dockerfile_root_and_latest(self):
        ids = rule_ids({"Dockerfile": "FROM node:latest\nCOPY . .\nCMD node app.js\n"})
        self.assertIn("DOCKER-01", ids)
        self.assertIn("DOCKER-02", ids)

    def test_dockerfile_hardened(self):
        df = "FROM node:20 AS build\nRUN npm ci\nFROM build\nUSER node\nCMD node app.js\n"
        ids = rule_ids({"Dockerfile": df})
        self.assertNotIn("DOCKER-01", ids)  # "FROM build" references a stage, not an image
        self.assertNotIn("DOCKER-02", ids)


class Outputs(unittest.TestCase):
    def _run(self, *args: str, files: dict[str, str]) -> subprocess.CompletedProcess:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for rel, content in files.items():
                (root / rel).write_text(content, encoding="utf-8")
            return subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "loophole_scanner.py"), "--target", str(root), *args],
                capture_output=True, text=True,
            )

    def test_json_schema_fields(self):
        p = self._run("--format", "json", files={"a.py": "subprocess.run(cmd, shell=True)\n"})
        data = json.loads(p.stdout)
        self.assertEqual(data["schema_version"], ls.REPORT_SCHEMA_VERSION)
        f = data["findings"][0]
        for key in ("rule_id", "severity", "confidence", "cwe", "owasp", "file", "line", "remediation", "fingerprint"):
            self.assertIn(key, f)

    def test_sarif_is_valid_shape(self):
        p = self._run("--format", "sarif", files={"a.py": "subprocess.run(cmd, shell=True)\n"})
        sarif = json.loads(p.stdout)
        self.assertEqual(sarif["version"], "2.1.0")
        run = sarif["runs"][0]
        self.assertEqual(run["results"][0]["ruleId"], "INJ-02")
        self.assertIn("security-severity", run["tool"]["driver"]["rules"][0]["properties"])

    def test_fail_on_exit_code(self):
        files = {"a.py": "subprocess.run(cmd, shell=True)\n"}
        self.assertEqual(self._run("--fail-on", "high", files=files).returncode, 1)
        self.assertEqual(self._run("--fail-on", "critical", files=files).returncode, 0)
        self.assertEqual(self._run(files=files).returncode, 0)

    def test_baseline_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a.py").write_text("subprocess.run(cmd, shell=True)\n")
            script = str(ROOT / "scripts" / "loophole_scanner.py")
            base = root / ls.DEFAULT_BASELINE
            subprocess.run([sys.executable, script, "--target", str(root), "--write-baseline", str(base)], check=True,
                           capture_output=True)
            p = subprocess.run([sys.executable, script, "--target", str(root), "--format", "json", "--fail-on", "low"],
                               capture_output=True, text=True)
            data = json.loads(p.stdout)
            self.assertEqual(data["summary"]["total"], 0)
            self.assertEqual(data["summary"]["suppressed_baseline"], 1)
            self.assertEqual(p.returncode, 0)


if __name__ == "__main__":
    unittest.main()
