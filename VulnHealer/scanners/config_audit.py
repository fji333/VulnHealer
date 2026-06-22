"""
Config Auditor
Detects security misconfigurations in Infrastructure-as-Code files.
Covers: Dockerfile, Kubernetes YAML, Terraform, GitHub Actions, nginx configs.
"""

import re
from pathlib import Path
from typing import List, Dict, Any
import logging

logger = logging.getLogger(__name__)


class ConfigAuditor:
    """
    Security configuration auditor for IaC files.
    Supports: Dockerfile, docker-compose, K8s YAML, Terraform, CI/CD configs.
    """

    DOCKERFILE_CHECKS = [
        {
            "id": "docker.root_user",
            "pattern": r'^USER\s+root\s*$',
            "message": "Container runs as root user. Use a non-root USER instruction.",
            "severity": "HIGH",
            "cwe": "CWE-250",
        },
        {
            "id": "docker.no_user",
            "check": "no_user_instruction",
            "message": "No USER instruction found. Container will run as root by default.",
            "severity": "HIGH",
            "cwe": "CWE-250",
        },
        {
            "id": "docker.apt_no_clean",
            "pattern": r'apt-get install(?!.*&&.*rm -rf /var/lib/apt)',
            "message": "apt-get install without cleanup increases image size and attack surface.",
            "severity": "LOW",
            "cwe": "CWE-1051",
        },
        {
            "id": "docker.latest_tag",
            "pattern": r'^FROM\s+\S+:latest',
            "message": "Using :latest tag is non-deterministic and can introduce vulnerabilities.",
            "severity": "MEDIUM",
            "cwe": "CWE-1104",
        },
        {
            "id": "docker.exposed_secret",
            "pattern": r'^(?:ENV|ARG)\s+\S*(?:PASSWORD|SECRET|KEY|TOKEN|CREDENTIAL)\s*=\s*\S+',
            "message": "Secret/credential exposed as Docker ENV or ARG.",
            "severity": "CRITICAL",
            "cwe": "CWE-798",
        },
        {
            "id": "docker.curl_bash_pipe",
            "pattern": r'curl\s+.*\|\s*(?:bash|sh)',
            "message": "Pipe curl output directly into bash is a supply chain risk.",
            "severity": "HIGH",
            "cwe": "CWE-829",
        },
        {
            "id": "docker.privileged_port",
            "pattern": r'^EXPOSE\s+([1-9]\d{0,3})\b',
            "message": "Exposing privileged port (<1024) in container.",
            "severity": "LOW",
            "cwe": "CWE-272",
        },
    ]

    KUBERNETES_CHECKS = [
        {
            "id": "k8s.privileged_container",
            "pattern": r'privileged:\s*true',
            "message": "Container is running in privileged mode. This grants host-level access.",
            "severity": "CRITICAL",
            "cwe": "CWE-250",
        },
        {
            "id": "k8s.allow_privilege_escalation",
            "pattern": r'allowPrivilegeEscalation:\s*true',
            "message": "Privilege escalation is allowed. Set to false.",
            "severity": "HIGH",
            "cwe": "CWE-269",
        },
        {
            "id": "k8s.run_as_root",
            "pattern": r'runAsNonRoot:\s*false|runAsUser:\s*0\b',
            "message": "Container configured to run as root user.",
            "severity": "HIGH",
            "cwe": "CWE-250",
        },
        {
            "id": "k8s.host_network",
            "pattern": r'hostNetwork:\s*true',
            "message": "Container uses host network namespace. Exposes all host ports.",
            "severity": "HIGH",
            "cwe": "CWE-250",
        },
        {
            "id": "k8s.host_pid",
            "pattern": r'hostPID:\s*true',
            "message": "Container shares host PID namespace.",
            "severity": "HIGH",
            "cwe": "CWE-250",
        },
        {
            "id": "k8s.no_resource_limits",
            "check": "no_resources_block",
            "message": "No resource limits defined. Container can exhaust host resources (DoS).",
            "severity": "MEDIUM",
            "cwe": "CWE-400",
        },
        {
            "id": "k8s.default_service_account",
            "pattern": r'automountServiceAccountToken:\s*true',
            "message": "Service account token auto-mounted. Reduce by setting to false if not needed.",
            "severity": "MEDIUM",
            "cwe": "CWE-272",
        },
    ]

    TERRAFORM_CHECKS = [
        {
            "id": "tf.s3_public_acl",
            "pattern": r'acl\s*=\s*"public-read|public-read-write"',
            "message": "S3 bucket has public ACL. Data exposure risk.",
            "severity": "CRITICAL",
            "cwe": "CWE-284",
        },
        {
            "id": "tf.sg_open_ingress",
            "pattern": r'cidr_blocks\s*=\s*\["0\.0\.0\.0/0"\]',
            "message": "Security group allows ingress from all IPs (0.0.0.0/0).",
            "severity": "HIGH",
            "cwe": "CWE-284",
        },
        {
            "id": "tf.rds_public",
            "pattern": r'publicly_accessible\s*=\s*true',
            "message": "RDS instance is publicly accessible from the internet.",
            "severity": "CRITICAL",
            "cwe": "CWE-668",
        },
        {
            "id": "tf.unencrypted_storage",
            "pattern": r'encrypted\s*=\s*false',
            "message": "Storage resource with encryption disabled.",
            "severity": "HIGH",
            "cwe": "CWE-311",
        },
    ]

    NGINX_CHECKS = [
        {
            "id": "nginx.server_tokens",
            "pattern": r'server_tokens\s+on',
            "message": "server_tokens is on. Disable to hide nginx version.",
            "severity": "LOW",
            "cwe": "CWE-200",
        },
        {
            "id": "nginx.clickjacking",
            "check": "missing_x_frame",
            "message": "Missing X-Frame-Options header. Clickjacking risk.",
            "severity": "MEDIUM",
            "cwe": "CWE-1021",
        },
        {
            "id": "nginx.ssl_weak_protocols",
            "pattern": r'ssl_protocols.*(?:SSLv2|SSLv3|TLSv1\b|TLSv1\.1)',
            "message": "Weak SSL/TLS protocols enabled (SSLv2/3, TLS 1.0/1.1).",
            "severity": "HIGH",
            "cwe": "CWE-326",
        },
    ]

    GITHUB_ACTIONS_CHECKS = [
        {
            "id": "gha.dangerous_pull_request_target",
            "pattern": r'pull_request_target',
            "message": "pull_request_target can allow attackers to run code with repo write permissions.",
            "severity": "HIGH",
            "cwe": "CWE-78",
        },
        {
            "id": "gha.secret_in_run",
            "pattern": r'\$\{\{\s*(?:secrets|github\.token)\s*\}\}.*run:',
            "message": "Secret directly passed to run command. Use env: block instead.",
            "severity": "HIGH",
            "cwe": "CWE-532",
        },
        {
            "id": "gha.third_party_unpinned",
            "pattern": r'uses:\s+[^/]+/[^@]+@(?:main|master|latest)',
            "message": "Third-party action pinned to mutable branch/tag. Pin to a commit SHA.",
            "severity": "MEDIUM",
            "cwe": "CWE-829",
        },
    ]

    FILE_TYPE_MAP = {
        'Dockerfile': DOCKERFILE_CHECKS,
        'docker-compose.yml': [],
        'docker-compose.yaml': [],
    }

    EXT_MAP = {
        '.tf': TERRAFORM_CHECKS,
        '.yaml': KUBERNETES_CHECKS,
        '.yml': KUBERNETES_CHECKS,
    }

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.name = "config_audit"

    async def scan(self, target_path: str) -> Dict[str, Any]:
        """Scan target for configuration vulnerabilities."""
        target = Path(target_path)
        findings = []

        if target.is_file():
            files = [target]
        else:
            files = [f for f in target.rglob("*") if f.is_file()]

        for f in files:
            checks = self._get_checks_for_file(f)
            if checks is not None:
                findings.extend(self._check_file(str(f), checks))

        return {"scanner": self.name, "findings": findings}

    def _get_checks_for_file(self, path: Path):
        """Return applicable checks for a file."""
        if path.name == 'Dockerfile' or path.name.startswith('Dockerfile.'):
            return self.DOCKERFILE_CHECKS
        if path.name.endswith('.tf'):
            return self.TERRAFORM_CHECKS
        if path.suffix in ('.yaml', '.yml'):
            # Try to distinguish K8s from GitHub Actions
            try:
                with open(path, 'r', errors='replace') as f:
                    content = f.read(200)
                if '.github/workflows' in str(path) or 'uses:' in content:
                    return self.GITHUB_ACTIONS_CHECKS
                if 'apiVersion:' in content or 'kind:' in content:
                    return self.KUBERNETES_CHECKS
            except:
                pass
            return self.KUBERNETES_CHECKS
        if path.name in ('nginx.conf', 'default.conf') or '.nginx' in str(path):
            return self.NGINX_CHECKS
        return None

    def _check_file(self, file_path: str, checks: List[Dict]) -> List[Dict]:
        """Run checks against a file."""
        findings = []
        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
                lines = content.splitlines()
        except Exception:
            return []

        has_user_instruction = any(re.match(r'^USER\s+(?!root)', l) for l in lines)
        has_resource_limits = 'resources:' in content
        has_x_frame = 'X-Frame-Options' in content or 'x-frame-options' in content

        for check in checks:
            check_id = check["id"]
            message = check["message"]
            severity = check["severity"]
            cwe = check.get("cwe", "")

            # Pattern-based check
            if "pattern" in check:
                pattern = re.compile(check["pattern"], re.IGNORECASE | re.MULTILINE)
                for i, line in enumerate(lines, 1):
                    if pattern.search(line):
                        findings.append(self._make_finding(check_id, message, severity, cwe, file_path, i, line))

            # Special logic checks
            elif "check" in check:
                special = check["check"]
                if special == "no_user_instruction" and not has_user_instruction:
                    findings.append(self._make_finding(check_id, message, severity, cwe, file_path, 1, ""))
                elif special == "no_resources_block" and not has_resource_limits:
                    findings.append(self._make_finding(check_id, message, severity, cwe, file_path, 1, ""))
                elif special == "missing_x_frame" and not has_x_frame:
                    findings.append(self._make_finding(check_id, message, severity, cwe, file_path, 1, ""))

        return findings

    def _make_finding(self, rule_id, message, severity, cwe, file_path, lineno, snippet) -> Dict:
        return {
            "scanner": self.name,
            "rule_id": rule_id,
            "rule_name": rule_id.split(".", 1)[-1],
            "message": message,
            "severity": severity,
            "confidence": 0.9,
            "cwe_id": cwe,
            "owasp": "A05:2021 – Security Misconfiguration",
            "file_path": file_path,
            "line_start": lineno,
            "line_end": lineno,
            "code_snippet": snippet,
            "metadata": {"config_type": rule_id.split(".")[0]}
        }
