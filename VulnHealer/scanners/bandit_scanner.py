"""
Bandit Scanner Integration
Python-specific security scanner.
"""

import json
import subprocess
import tempfile
from pathlib import Path
from typing import List, Dict, Any
import logging

logger = logging.getLogger(__name__)


class BanditScanner:
    """Bandit security scanner for Python code."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.name = "bandit"
        self.severity_levels = config.get('severity', ['HIGH', 'MEDIUM'])
        self.confidence_levels = config.get('confidence', ['HIGH', 'MEDIUM'])
        self.skipped_tests = config.get('skipped_tests', [])
        self.include_tests = config.get('include_tests', [])

    async def scan(self, target_path: str) -> Dict[str, Any]:
        """Run bandit scan on target."""
        target = Path(target_path)

        # Bandit only works on Python files
        if target.is_file() and target.suffix != '.py':
            return {'scanner': self.name, 'findings': [], 'note': 'Not a Python file'}

        cmd = self._build_command(target_path)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )

            if result.stdout:
                bandit_output = json.loads(result.stdout)
            else:
                bandit_output = {'results': [], 'errors': []}

            findings = self._parse_findings(bandit_output)

            return {
                'scanner': self.name,
                'findings': findings,
                'raw_output': bandit_output,
                'metrics': bandit_output.get('metrics', {})
            }

        except Exception as e:
            logger.error(f"Bandit scan failed: {e}")
            return {'scanner': self.name, 'findings': [], 'error': str(e)}

    def _build_command(self, target_path: str) -> List[str]:
        cmd = ['bandit', '-f', 'json']

        # bandit 1.9+: -l/-i take repeated flags, not comma-separated
        # Scan all severities; engine-level filtering handles thresholds
        cmd.append('-ll')   # MEDIUM + HIGH
        cmd.append('-ii')   # MEDIUM + HIGH confidence

        # Skip/include tests
        if self.skipped_tests:
            cmd.extend(['-s', ','.join(self.skipped_tests)])
        if self.include_tests:
            cmd.extend(['-t', ','.join(self.include_tests)])

        # Recursive for directories
        target = Path(target_path)
        if target.is_dir():
            cmd.append('-r')

        cmd.append(target_path)
        return cmd

    def _parse_findings(self, bandit_output: Dict) -> List[Dict[str, Any]]:
        findings = []

        for result in bandit_output.get('results', []):
            finding = {
                'scanner': self.name,
                'rule_id': result.get('test_id', ''),
                'rule_name': result.get('test_name', ''),
                'message': result.get('issue_text', ''),
                'severity': result.get('issue_severity', 'MEDIUM'),
                'confidence': result.get('issue_confidence', 'MEDIUM'),
                'cwe_id': result.get('cwe', ''),
                'file_path': result.get('filename', ''),
                'line_start': result.get('line_number', 0),
                'line_end': result.get('line_number', 0),
                'code_snippet': result.get('code', ''),
                'metadata': {
                    'bandit_test_ref_url': result.get('more_info', ''),
                    'bandit_col_offset': result.get('col_offset', 0),
                    'bandit_end_col_offset': result.get('end_col_offset', 0)
                }
            }

            # Convert confidence string to float
            confidence_map = {'HIGH': 0.9, 'MEDIUM': 0.7, 'LOW': 0.5}
            finding['confidence'] = confidence_map.get(finding['confidence'], 0.7)

            findings.append(finding)

        return findings
