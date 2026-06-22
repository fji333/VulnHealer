"""
Patch Generator
Generates secure code patches using LLM with structured prompts and validation.
"""

from typing import Dict, Any
import logging
import re

from llm.multi_provider import MultiLLMProvider

logger = logging.getLogger(__name__)


class PatchGenerator:
    """
    Generates security patches for vulnerabilities using LLM.

    Features:
    - Structured prompt engineering
    - Multiple patch strategies
    - Validation hints
    - Diff generation
    """

    def __init__(self, llm_provider: MultiLLMProvider):
        self.llm = llm_provider
        self.system_prompt = """You are an expert security engineer specializing in automated vulnerability remediation.
Your task is to generate precise, secure code patches for the provided vulnerable code.

Rules:
1. Provide ONLY the fixed code, no explanations in the code block
2. Maintain the original code structure and style
3. Do not change unrelated code
4. Ensure the fix addresses the root cause, not just symptoms
5. Use industry-standard secure coding practices
6. If multiple fixes are possible, provide the most robust one

Output format:
```<language>
<fixed code here>
```

If you cannot generate a safe fix, output:
```
UNABLE_TO_FIX: <reason>
```"""

    async def generate(self, finding) -> str:
        """
        Generate a patch for a vulnerability finding.

        Args:
            finding: VulnerabilityFinding object

        Returns:
            Patched code string or empty string if unable to fix
        """
        prompt = self._build_prompt(finding)

        try:
            response = await self.llm.complete(
                prompt=prompt,
                system_prompt=self.system_prompt,
                temperature=0.1,  # Low temperature for deterministic fixes
                max_tokens=2048
            )

            patch = self._extract_patch(response.content)
            return patch

        except Exception as e:
            logger.error(f"Patch generation failed: {e}")
            return ""

    def _build_prompt(self, finding) -> str:
        """Build structured prompt for patch generation."""
        severity_desc = {
            'CRITICAL': 'Critical - Immediate exploitation risk',
            'HIGH': 'High - Likely exploitable',
            'MEDIUM': 'Medium - Possible exploitation',
            'LOW': 'Low - Difficult to exploit'
        }

        prompt = f"""# Vulnerability Remediation Task

## Vulnerability Details
- Severity: {finding.severity} - {severity_desc.get(finding.severity, 'Unknown')}
- Type: {finding.rule_name}
- CWE: {finding.cwe_id or 'N/A'}
- Location: {finding.file_path}:{finding.line_start}
- Confidence: {finding.confidence:.0%}

## Problem Description
{finding.message}

## Vulnerable Code
```
{finding.code_snippet}
```

## Code Context (Before)
```
{finding.context_before}
```

## Code Context (After)
```
{finding.context_after}
```

## Task
Generate the secure fixed version of the vulnerable code section.
Replace ONLY the vulnerable lines while keeping the rest of the function/class intact.

## Additional Requirements
- Fix Type: {self._categorize_fix(finding)}
- Language: {self._detect_language(finding.file_path)}
- Must preserve: original function signatures, variable names, and overall structure
"""
        return prompt

    def _extract_patch(self, response: str) -> str:
        """Extract patch code from LLM response."""
        # Try to extract code from markdown code blocks
        code_block_pattern = r'```(?:\w+)?\n(.*?)\n```'
        matches = re.findall(code_block_pattern, response, re.DOTALL)

        if matches:
            patch = matches[0].strip()
            if patch.startswith('UNABLE_TO_FIX'):
                return ""
            return patch

        # If no code blocks, try to clean the response
        if response.strip().startswith('UNABLE_TO_FIX'):
            return ""

        # Return cleaned text as fallback
        lines = response.split('\n')
        # Remove common prefixes that LLM might add
        cleaned = []
        for line in lines:
            if not line.strip().startswith(('Here is', 'The fix', 'Fixed code', 'Below is')):
                cleaned.append(line)

        return '\n'.join(cleaned).strip()

    def _categorize_fix(self, finding) -> str:
        """Categorize the type of fix needed."""
        cwe = (finding.cwe_id or '').lower()
        message = (finding.message or '').lower()

        if 'sql' in cwe or 'sql' in message:
            return "Parameterized Query / Prepared Statement"
        elif 'xss' in cwe or 'xss' in message or 'cross-site' in message:
            return "Output Encoding / Context-aware Escaping"
        elif 'injection' in cwe or 'injection' in message:
            return "Input Validation / Sanitization"
        elif 'path' in cwe or 'traversal' in message:
            return "Path Canonicalization / Validation"
        elif 'crypto' in cwe or 'hash' in message:
            return "Strong Cryptographic Primitive"
        elif 'auth' in cwe or 'session' in message:
            return "Authentication / Session Hardening"
        elif 'deserialization' in cwe:
            return "Safe Deserialization / Type Whitelisting"
        elif 'race' in cwe or 'condition' in message:
            return "Synchronization / Atomic Operations"
        else:
            return "Input Validation / Secure API Usage"

    def _detect_language(self, file_path: str) -> str:
        """Detect programming language from file extension."""
        ext = file_path.split('.')[-1].lower()
        lang_map = {
            'py': 'Python',
            'js': 'JavaScript',
            'ts': 'TypeScript',
            'java': 'Java',
            'c': 'C',
            'cpp': 'C++',
            'go': 'Go',
            'rb': 'Ruby',
            'php': 'PHP',
            'cs': 'C#',
            'rs': 'Rust'
        }
        return lang_map.get(ext, 'Unknown')

    async def generate_diff(self, original: str, patched: str) -> str:
        """Generate a unified diff of the patch."""
        import difflib

        original_lines = original.splitlines(keepends=True)
        patched_lines = patched.splitlines(keepends=True)

        diff = difflib.unified_diff(
            original_lines,
            patched_lines,
            fromfile='original',
            tofile='patched',
            lineterm=''
        )

        return ''.join(diff)

    async def batch_generate(self, findings: list) -> Dict[str, str]:
        """Generate patches for multiple findings in parallel."""
        import asyncio

        tasks = [self.generate(f) for f in findings]
        patches = await asyncio.gather(*tasks, return_exceptions=True)

        results = {}
        for i, finding in enumerate(findings):
            patch = patches[i]
            if isinstance(patch, Exception):
                logger.error(f"Patch generation failed for {finding.id}: {patch}")
                results[finding.id] = ""
            else:
                results[finding.id] = patch

        return results
