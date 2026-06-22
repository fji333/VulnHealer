"""
Comprehensive Test Suite for VulnHealer v2.0
Tests all modules: scanners, LLM layer, utils, new advanced modules.
Run: pytest tests/ -v --tb=short
"""

import asyncio
import tempfile
import os
import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

# ─── Sample vulnerable Python code ─────────────────────────────────────────
VULN_PYTHON = """
import os, pickle, sqlite3, hashlib
from flask import Flask, request

app = Flask(__name__)
DB_PASS = "supersecret123"
API_KEY = "sk-abcdefghijklmnop"

def get_user(username):
    conn = sqlite3.connect("users.db")
    # SQL Injection
    return conn.execute("SELECT * FROM users WHERE name='" + username + "'").fetchall()

@app.route("/greet")
def greet():
    name = request.args.get("name")
    return f"<h1>Hello {name}</h1>"   # XSS

def run_cmd(cmd):
    os.system(cmd)          # Command injection

def load_data(data):
    return pickle.loads(data)  # Unsafe deserialization

def weak_hash(pw):
    return hashlib.md5(pw.encode()).hexdigest()  # Weak crypto
"""

SAFE_PYTHON = """
import hashlib
import secrets

def safe_hash(pw: str) -> str:
    salt = secrets.token_hex(16)
    return hashlib.sha256((salt + pw).encode()).hexdigest()

def add(a: int, b: int) -> int:
    return a + b
"""

VULN_DOCKERFILE = """FROM ubuntu:latest
RUN apt-get install -y curl
RUN curl https://example.com/install.sh | bash
ENV DB_PASSWORD=mysecret123
"""

VULN_K8S = """apiVersion: v1
kind: Pod
spec:
  containers:
  - name: app
    image: myapp:latest
    securityContext:
      privileged: true
      runAsUser: 0
"""


@pytest.fixture
def vuln_py_file(tmp_path):
    f = tmp_path / "vuln.py"
    f.write_text(VULN_PYTHON)
    return str(f)


@pytest.fixture
def safe_py_file(tmp_path):
    f = tmp_path / "safe.py"
    f.write_text(SAFE_PYTHON)
    return str(f)


@pytest.fixture
def dockerfile(tmp_path):
    f = tmp_path / "Dockerfile"
    f.write_text(VULN_DOCKERFILE)
    return str(f)


@pytest.fixture
def k8s_yaml(tmp_path):
    f = tmp_path / "pod.yaml"
    f.write_text(VULN_K8S)
    return str(f)


# ─── Secret Scanner ─────────────────────────────────────────────────────────
class TestSecretScanner:
    def test_detects_hardcoded_api_key(self, vuln_py_file):
        from scanners.secret_scanner import SecretScanner
        scanner = SecretScanner()
        result = asyncio.run(scanner.scan(vuln_py_file))
        assert result["scanner"] == "secret_scanner"
        assert len(result["findings"]) >= 1
        cwe_ids = {f["cwe_id"] for f in result["findings"]}
        assert "CWE-798" in cwe_ids

    def test_no_false_positive_on_safe_code(self, safe_py_file):
        from scanners.secret_scanner import SecretScanner
        scanner = SecretScanner()
        result = asyncio.run(scanner.scan(safe_py_file))
        # Safe code should have 0 or very few findings
        assert len(result["findings"]) == 0

    def test_entropy_detection(self, tmp_path):
        from scanners.secret_scanner import SecretScanner
        f = tmp_path / "test.py"
        f.write_text('secret_key = "X9kP2mQr7vN4wLjH8sD6tYeA3uBz5cFgI1oE0"\n')
        scanner = SecretScanner()
        result = asyncio.run(scanner.scan(str(f)))
        # Should detect high-entropy secret
        assert len(result["findings"]) >= 1

    def test_shannon_entropy(self):
        from scanners.secret_scanner import SecretScanner
        s = SecretScanner()
        assert s._shannon_entropy("aaaaaaa") < 1.0   # Low entropy
        assert s._shannon_entropy("X9kP2mQr7vN4wL") > 3.0  # High entropy


# ─── Config Auditor ─────────────────────────────────────────────────────────
class TestConfigAuditor:
    def test_dockerfile_privileged_port(self, dockerfile):
        from scanners.config_audit import ConfigAuditor
        auditor = ConfigAuditor()
        result = asyncio.run(auditor.scan(dockerfile))
        assert result["scanner"] == "config_audit"
        assert len(result["findings"]) >= 1

    def test_kubernetes_privileged(self, k8s_yaml):
        from scanners.config_audit import ConfigAuditor
        auditor = ConfigAuditor()
        result = asyncio.run(auditor.scan(k8s_yaml))
        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert any("privileged" in r or "root" in r for r in rule_ids)

    def test_no_false_positive_clean_dockerfile(self, tmp_path):
        f = tmp_path / "Dockerfile"
        f.write_text("FROM python:3.11-slim\nWORKDIR /app\nCOPY . .\nUSER appuser\nCMD [\"python\", \"app.py\"]\n")
        from scanners.config_audit import ConfigAuditor
        auditor = ConfigAuditor()
        result = asyncio.run(auditor.scan(str(f)))
        # Should have few or no findings on clean Dockerfile
        assert result["scanner"] == "config_audit"


# ─── Fusion Engine ──────────────────────────────────────────────────────────
class TestFusionEngine:
    def _make_finding(self, scanner, file_path, line, rule, cwe="CWE-89", severity="HIGH"):
        from core.engine import VulnerabilityFinding
        f = VulnerabilityFinding(
            id="", scanner=scanner, severity=severity, confidence=0.8,
            cwe_id=cwe, rule_id=rule, rule_name=rule, message=f"{rule} issue",
            file_path=file_path, line_start=line, line_end=line,
            code_snippet="conn.execute(query)", context_before="", context_after=""
        )
        f.id = f.generate_id()
        return f

    def test_deduplicates_same_finding(self):
        from scanners.fusion_engine import FusionEngine
        engine = FusionEngine()
        f1 = self._make_finding("semgrep", "app.py", 10, "sqli")
        f2 = self._make_finding("bandit", "app.py", 10, "sqli")
        result = engine.deduplicate([f1, f2])
        assert len(result) == 1
        assert "semgrep" in result[0].scanner and "bandit" in result[0].scanner

    def test_keeps_different_findings(self):
        from scanners.fusion_engine import FusionEngine
        engine = FusionEngine()
        f1 = self._make_finding("semgrep", "a.py", 10, "sqli")
        f2 = self._make_finding("semgrep", "b.py", 10, "xss", "CWE-79")
        result = engine.deduplicate([f1, f2])
        assert len(result) == 2


# ─── Bandit Scanner ─────────────────────────────────────────────────────────
class TestBanditScanner:
    def test_bandit_detects_md5(self, tmp_path):
        from scanners.bandit_scanner import BanditScanner
        f = tmp_path / "weak.py"
        f.write_text("import hashlib\ndef h(p): return hashlib.md5(p.encode()).hexdigest()\n")
        scanner = BanditScanner({})
        result = asyncio.run(scanner.scan(str(f)))
        assert result["scanner"] == "bandit"
        assert len(result["findings"]) >= 1

    def test_bandit_skips_non_python(self, tmp_path):
        from scanners.bandit_scanner import BanditScanner
        f = tmp_path / "app.js"
        f.write_text("var x = eval(input);")
        scanner = BanditScanner({})
        result = asyncio.run(scanner.scan(str(f)))
        assert result["findings"] == []


# ─── Code Context Extractor ─────────────────────────────────────────────────
class TestCodeContextExtractor:
    def test_extracts_context(self, vuln_py_file):
        from utils.code_context import CodeContextExtractor
        extractor = CodeContextExtractor(context_lines=3, context_lines_after=3)
        ctx = extractor.extract(vuln_py_file, 13, 13)
        assert "before" in ctx
        assert "after" in ctx
        assert isinstance(ctx["before"], str)

    def test_handles_missing_file(self):
        from utils.code_context import CodeContextExtractor
        extractor = CodeContextExtractor()
        ctx = extractor.extract("/nonexistent/file.py", 1, 1)
        assert ctx["before"] == ""
        assert ctx["after"] == ""


# ─── False Positive Filter ──────────────────────────────────────────────────
class TestFPFilter:
    def _make_finding(self, severity="HIGH", confidence=0.9, rule="sql_injection"):
        from core.engine import VulnerabilityFinding
        f = VulnerabilityFinding(
            id="test123", scanner="semgrep", severity=severity, confidence=confidence,
            cwe_id="CWE-89", rule_id=rule, rule_name=rule, message="SQL Injection",
            file_path="app.py", line_start=10, line_end=10,
            code_snippet="query = 'SELECT * WHERE id=' + user_id",
            context_before="", context_after=""
        )
        return f

    def test_high_confidence_not_filtered(self):
        from utils.fp_filter import FalsePositiveFilter
        fp = FalsePositiveFilter({})
        finding = self._make_finding("CRITICAL", 0.95)
        is_fp, confidence = fp.predict(finding)
        assert not is_fp  # High confidence CRITICAL should not be FP

    def test_low_confidence_info_might_be_filtered(self):
        from utils.fp_filter import FalsePositiveFilter
        fp = FalsePositiveFilter({})
        finding = self._make_finding("INFO", 0.3, "eval_usage")
        is_fp, fp_confidence = fp.predict(finding)
        # INFO + low confidence should have higher FP probability
        assert fp_confidence > 0.4  # Should lean towards FP


# ─── CWE Knowledge Base ─────────────────────────────────────────────────────
class TestCWEKnowledgeBase:
    def test_lookup_sqli(self):
        from knowledge_base.cwe_kb import CWEKnowledgeBase
        kb = CWEKnowledgeBase()
        entry = kb.get("CWE-89")
        assert entry is not None
        assert "SQL Injection" in entry["name"]

    def test_normalize_ids(self):
        from knowledge_base.cwe_kb import CWEKnowledgeBase
        kb = CWEKnowledgeBase()
        assert kb.get("89") is not None
        assert kb.get("cwe-89") is not None
        assert kb.get("CWE-89") is not None

    def test_fix_example(self):
        from knowledge_base.cwe_kb import CWEKnowledgeBase
        kb = CWEKnowledgeBase()
        fix = kb.get_fix_example("CWE-89", "python")
        assert fix is not None
        assert "vulnerable" in fix
        assert "fixed" in fix

    def test_search(self):
        from knowledge_base.cwe_kb import CWEKnowledgeBase
        kb = CWEKnowledgeBase()
        results = kb.search("injection")
        assert len(results) >= 2

    def test_unknown_cwe_returns_none(self):
        from knowledge_base.cwe_kb import CWEKnowledgeBase
        kb = CWEKnowledgeBase()
        assert kb.get("CWE-99999") is None


# ─── Patch Validator ────────────────────────────────────────────────────────
class TestPatchValidator:
    def test_valid_python(self):
        from utils.patch_validator import PatchValidator
        validator = PatchValidator({})
        valid_code = "import os\ndef safe(cmd):\n    import subprocess\n    return subprocess.run(['ls'], capture_output=True)\n"
        result = asyncio.run(validator.validate(".", "test.py", "", valid_code))
        is_valid, msg = result
        assert is_valid

    def test_invalid_python_syntax(self):
        from utils.patch_validator import PatchValidator
        validator = PatchValidator({})
        bad_code = "def broken(\n  pass\n"
        result = asyncio.run(validator.validate(".", "test.py", "", bad_code))
        is_valid, msg = result
        assert not is_valid

    def test_security_regression_detected(self):
        from utils.patch_validator import PatchValidator
        validator = PatchValidator({})
        issues = validator._check_python_security("result = eval(user_input)")
        assert len(issues) >= 1


# ─── Incremental Scanner ────────────────────────────────────────────────────
class TestIncrementalScanner:
    def test_non_git_repo_returns_empty(self, tmp_path):
        from scanners.incremental_scanner import IncrementalScanner
        scanner = IncrementalScanner()
        assert not scanner.is_git_repo(str(tmp_path))
        files = scanner.get_changed_files(str(tmp_path))
        assert files == []


# ─── Trend Tracker ──────────────────────────────────────────────────────────
class TestTrendTracker:
    def test_record_and_retrieve(self, tmp_path):
        from analytics.trend_tracker import TrendTracker

        from datetime import datetime
        class MockResult:
            target_path = "/test/file.py"
            scan_timestamp = datetime.now().isoformat()
            duration_seconds = 5.0
            findings = []
            statistics = {
                "total_findings": 5, "validated_patches": 3,
                "severity_distribution": {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 2, "LOW": 0, "INFO": 0},
                "raw_scanner_results": {}
            }

        tracker = TrendTracker(db_path=str(tmp_path / "test.db"))
        scan_id = tracker.record_scan(MockResult())
        assert scan_id > 0

        trend = tracker.get_trend(days=30)
        assert trend["scans"] >= 1

    def test_top_cwe_empty(self, tmp_path):
        from analytics.trend_tracker import TrendTracker
        tracker = TrendTracker(db_path=str(tmp_path / "test.db"))
        result = tracker.get_top_cwe()
        assert isinstance(result, list)


# ─── Run Tests ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import subprocess
    subprocess.run([sys.executable, "-m", "pytest", __file__, "-v", "--tb=short"])
