"""
Semgrep Scanner Integration
Wraps semgrep CLI for advanced static analysis.
"""

import json
import subprocess
import tempfile
import os
from pathlib import Path
from typing import List, Dict, Any
import logging

logger = logging.getLogger(__name__)


class SemgrepScanner:
    """Semgrep-based static analysis scanner."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.name = "semgrep"
        # 'auto' auto-selects rules for detected languages, verified working with semgrep v1.x
        self.rules = config.get('rules', ['auto'])
        self.severity_map = {
            'ERROR': 'HIGH',
            'WARNING': 'MEDIUM',
            'INFO': 'LOW'
        }
        self.max_target_bytes = config.get('max_target_bytes', 10_000_000)
        self.timeout_threshold = config.get('timeout_threshold', 300)

    async def scan(self, target_path: str) -> Dict[str, Any]:
        """
        Run semgrep scan on target.

        Args:
            target_path: Path to file or directory

        Returns:
            Dict with standardized findings
        """
        target = Path(target_path)
        if not target.exists():
            raise FileNotFoundError(f"Target not found: {target_path}")

        # Build semgrep command
        cmd = self._build_command(target_path)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout_threshold
            )

            if result.returncode not in [0, 1]:  # 1 = findings found
                logger.warning(f"Semgrep exited with code {result.returncode}: {result.stderr}")

            # Parse JSON output
            if result.stdout:
                semgrep_output = json.loads(result.stdout)
            else:
                semgrep_output = {'results': [], 'errors': []}

            findings = self._parse_findings(semgrep_output)

            return {
                'scanner': self.name,
                'findings': findings,
                'raw_output': semgrep_output,
                'error_count': len(semgrep_output.get('errors', [])),
                'total_time': semgrep_output.get('time', {}).get('total_time', 0)
            }

        except subprocess.TimeoutExpired:
            logger.error(f"Semgrep scan timed out after {self.timeout_threshold}s")
            return {'scanner': self.name, 'findings': [], 'error': 'timeout'}
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse semgrep output: {e}")
            return {'scanner': self.name, 'findings': [], 'error': 'parse_error'}
        except Exception as e:
            logger.error(f"Semgrep scan failed: {e}")
            return {'scanner': self.name, 'findings': [], 'error': str(e)}

    def _build_command(self, target_path: str) -> List[str]:
        """Build semgrep CLI command."""
        # semgrep v1.x uses 'semgrep scan' subcommand
        cmd = ['semgrep', 'scan', '--json', '--quiet']

        # Add rules
        for rule in self.rules:
            cmd.extend(['--config', rule])

        # Performance options
        cmd.extend(['--max-target-bytes', str(self.max_target_bytes)])

        # Add target
        cmd.append(target_path)

        return cmd

    def _parse_findings(self, semgrep_output: Dict) -> List[Dict[str, Any]]:
        """Parse semgrep JSON output into standardized findings."""
        findings = []

        for result in semgrep_output.get('results', []):
            try:
                finding = {
                    'scanner': self.name,
                    'rule_id': result.get('check_id', ''),
                    'rule_name': result.get('check_id', '').split('.')[-1],
                    'message': result.get('extra', {}).get('message', ''),
                    'severity': self.severity_map.get(
                        result.get('extra', {}).get('severity', 'INFO').upper(),
                        'MEDIUM'
                    ),
                    'confidence': self._estimate_confidence(result),
                    'cwe_id': self._extract_cwe(result),
                    'owasp': self._extract_owasp(result),
                    'file_path': result.get('path', ''),
                    'line_start': result.get('start', {}).get('line', 0),
                    'line_end': result.get('end', {}).get('line', 0),
                    'column_start': result.get('start', {}).get('col', 0),
                    'column_end': result.get('end', {}).get('col', 0),
                    'code_snippet': result.get('extra', {}).get('lines', ''),
                    'metadata': {
                        'semgrep_fingerprint': result.get('extra', {}).get('fingerprint', ''),
                        'semgrep_metadata': result.get('extra', {}).get('metadata', {}),
                        'is_ignored': result.get('extra', {}).get('is_ignored', False),
                        'validation_state': result.get('extra', {}).get('validation_state', 'NO_VALIDATOR')
                    }
                }
                findings.append(finding)
            except Exception as e:
                logger.warning(f"Failed to parse semgrep result: {e}")
                continue

        return findings

    def _estimate_confidence(self, result: Dict) -> float:
        """Estimate confidence based on semgrep metadata."""
        metadata = result.get('extra', {}).get('metadata', {})
        confidence_str = metadata.get('confidence', 'MEDIUM')

        confidence_map = {
            'HIGH': 0.9,
            'MEDIUM': 0.7,
            'LOW': 0.5
        }

        return confidence_map.get(confidence_str.upper(), 0.7)

    def _extract_cwe(self, result: Dict) -> str:
        """Extract CWE ID from semgrep result."""
        metadata = result.get('extra', {}).get('metadata', {})
        cwe = metadata.get('cwe', '')
        if isinstance(cwe, list) and len(cwe) > 0:
            return cwe[0]
        return str(cwe) if cwe else ''

    def _extract_owasp(self, result: Dict) -> str:
        """Extract OWASP category from semgrep result."""
        metadata = result.get('extra', {}).get('metadata', {})
        owasp = metadata.get('owasp', '')
        if isinstance(owasp, list) and len(owasp) > 0:
            return owasp[0]
        return str(owasp) if owasp else ''

    def get_version(self) -> str:
        """Get semgrep version."""
        try:
            result = subprocess.run(['semgrep', '--version'], capture_output=True, text=True)
            return result.stdout.strip()
        except:
            return "unknown"
