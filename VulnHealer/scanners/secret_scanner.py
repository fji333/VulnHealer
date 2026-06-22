"""
Secret Scanner
Detects hardcoded credentials, API keys, tokens, and passwords.
Combines regex patterns, entropy analysis, and AI validation.
"""

import re
import math
import json
from pathlib import Path
from typing import List, Dict, Any, Tuple
import logging

logger = logging.getLogger(__name__)


class SecretScanner:
    """
    High-accuracy secret/credential scanner.

    Detection methods:
    1. Regex pattern matching (known formats)
    2. Shannon entropy analysis (high-entropy strings)
    3. Variable name heuristics
    4. Context analysis
    """

    SECRET_PATTERNS = [
        # API Keys
        ("openai_key",     r'sk-[A-Za-z0-9]{20,}',                  "OpenAI API Key",    "CRITICAL"),
        ("anthropic_key",  r'sk-ant-[A-Za-z0-9\-]{40,}',            "Anthropic API Key", "CRITICAL"),
        ("aws_access_key", r'AKIA[0-9A-Z]{16}',                      "AWS Access Key",    "CRITICAL"),
        ("aws_secret_key", r'[A-Za-z0-9/\+=]{40}',                  "AWS Secret Key (possible)", "HIGH"),
        ("github_token",   r'gh[pousr]_[A-Za-z0-9]{36,}',           "GitHub Token",      "CRITICAL"),
        ("stripe_key",     r'sk_live_[A-Za-z0-9]{24,}',             "Stripe Live Key",   "CRITICAL"),
        ("stripe_pub",     r'pk_live_[A-Za-z0-9]{24,}',             "Stripe Pub Key",    "HIGH"),
        ("google_api",     r'AIza[0-9A-Za-z\-_]{35}',               "Google API Key",    "HIGH"),
        ("jwt_token",      r'eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+', "JWT Token", "HIGH"),
        ("private_key",    r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----', "Private Key", "CRITICAL"),
        ("slack_token",    r'xox[baprs]-[0-9A-Za-z\-]{10,}',        "Slack Token",       "HIGH"),
        ("db_password",    r'(?i)(password|passwd|pwd)\s*=\s*["\'][^"\']{8,}["\']', "Hardcoded Password", "HIGH"),
        ("db_url",         r'(?i)(mysql|postgresql|mongodb|redis|sqlite)://[^@]+:[^@]+@', "DB Connection String", "CRITICAL"),
        ("generic_secret", r'(?i)(secret|token|key|credential)\s*=\s*["\'][A-Za-z0-9\-_\.]{16,}["\']', "Generic Secret", "MEDIUM"),
    ]

    # Known safe/test patterns to skip
    ALLOWLIST_PATTERNS = [
        r'example\.com', r'localhost', r'127\.0\.0\.1',
        r'test_?key', r'dummy_?key', r'fake_?key', r'placeholder',
        r'your_?api_?key', r'<your_', r'\$\{', r'\{\{',
        r'xxx+', r'aaa+', r'[0]+', r'\*+'
    ]

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.name = "secret_scanner"
        self.entropy_threshold = self.config.get("entropy_threshold", 3.8)
        self.min_secret_length = self.config.get("min_secret_length", 16)

        # Compile patterns
        self._compiled_patterns = [
            (name, re.compile(pattern), desc, severity)
            for name, pattern, desc, severity in self.SECRET_PATTERNS
        ]
        self._allowlist = [re.compile(p) for p in self.ALLOWLIST_PATTERNS]

    async def scan(self, target_path: str) -> Dict[str, Any]:
        """Scan target for secrets."""
        target = Path(target_path)
        findings = []

        if target.is_file():
            files = [target]
        else:
            files = [
                f for f in target.rglob("*")
                if f.is_file() and self._should_scan(f)
            ]

        for file_path in files:
            file_findings = self._scan_file(str(file_path))
            findings.extend(file_findings)

        return {"scanner": self.name, "findings": findings}

    def _scan_file(self, file_path: str) -> List[Dict]:
        """Scan a single file for secrets."""
        findings = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except Exception:
            return []

        for lineno, line in enumerate(lines, 1):
            # Pattern matching
            for name, pattern, desc, severity in self._compiled_patterns:
                match = pattern.search(line)
                if match:
                    matched_value = match.group()
                    if not self._is_allowlisted(matched_value) and not self._is_allowlisted(line):
                        findings.append({
                            "scanner": self.name,
                            "rule_id": f"secret.{name}",
                            "rule_name": name,
                            "message": f"{desc} detected in source code",
                            "severity": severity,
                            "confidence": 0.85,
                            "cwe_id": "CWE-798",
                            "owasp": "A07:2021 – Identification and Authentication Failures",
                            "file_path": file_path,
                            "line_start": lineno,
                            "line_end": lineno,
                            "code_snippet": line.rstrip(),
                            "metadata": {"matched_pattern": name, "secret_type": desc}
                        })
                        break  # One finding per line

            # Entropy-based detection for unmatched high-entropy strings
            if len(findings) == 0 or findings[-1].get("file_path") != file_path or findings[-1].get("line_start") != lineno:
                entropy_finding = self._entropy_check(file_path, line, lineno)
                if entropy_finding:
                    findings.append(entropy_finding)

        return findings

    def _entropy_check(self, file_path: str, line: str, lineno: int) -> Dict:
        """Detect high-entropy strings that might be secrets."""
        # Look for quoted strings long enough to be a secret
        quoted = re.findall(r'["\']([A-Za-z0-9\+/=\-_\.]{20,})["\']', line)
        for candidate in quoted:
            if self._shannon_entropy(candidate) > self.entropy_threshold:
                # Check if variable name is secret-related
                varname_match = re.search(r'(\w+)\s*[=:]\s*["\']' + re.escape(candidate), line)
                if varname_match:
                    varname = varname_match.group(1).lower()
                    if any(kw in varname for kw in ['key', 'secret', 'token', 'pass', 'credential', 'auth']):
                        return {
                            "scanner": self.name,
                            "rule_id": "secret.high_entropy",
                            "rule_name": "high_entropy_secret",
                            "message": f"High entropy string (entropy={self._shannon_entropy(candidate):.2f}) in security-sensitive variable",
                            "severity": "HIGH",
                            "confidence": 0.7,
                            "cwe_id": "CWE-798",
                            "owasp": "A07:2021",
                            "file_path": file_path,
                            "line_start": lineno,
                            "line_end": lineno,
                            "code_snippet": line.rstrip(),
                            "metadata": {"entropy": self._shannon_entropy(candidate), "variable": varname}
                        }
        return None

    def _shannon_entropy(self, s: str) -> float:
        """Calculate Shannon entropy of string."""
        if not s:
            return 0.0
        freq = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        length = len(s)
        return -sum((v / length) * math.log2(v / length) for v in freq.values())

    def _is_allowlisted(self, text: str) -> bool:
        """Check if text matches allowlist patterns (test/example data)."""
        return any(p.search(text) for p in self._allowlist)

    def _should_scan(self, path: Path) -> bool:
        """Determine if file should be scanned."""
        skip_dirs = {'.git', 'node_modules', '__pycache__', '.venv', 'venv', 'dist', 'build'}
        skip_exts = {'.pyc', '.pyo', '.class', '.o', '.so', '.dll', '.jpg', '.png', '.gif', '.zip', '.tar', '.gz', '.pdf'}
        skip_files = {'package-lock.json', 'yarn.lock', 'Pipfile.lock', 'poetry.lock'}

        if any(part in skip_dirs for part in path.parts):
            return False
        if path.suffix.lower() in skip_exts:
            return False
        if path.name in skip_files:
            return False
        return True
