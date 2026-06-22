"""
Vulnerability Explainer
Generates detailed vulnerability explanations using LLM.
"""

from typing import Dict, Any
import logging

from llm.multi_provider import MultiLLMProvider

logger = logging.getLogger(__name__)


class VulnerabilityExplainer:
    """
    Generates human-readable, developer-friendly vulnerability explanations.

    Output format:
    - Executive Summary (1 sentence)
    - Technical Details (what's wrong)
    - Impact Assessment (what could happen)
    - Root Cause Analysis (why it exists)
    - Fix Strategy (how to fix)
    - References (CWE, OWASP, etc.)
    """

    def __init__(self, llm_provider: MultiLLMProvider):
        self.llm = llm_provider
        self.system_prompt = """You are a senior application security engineer with 15 years of experience.
Your task is to explain security vulnerabilities to developers in a clear, actionable way.

Guidelines:
1. Be concise but thorough
2. Use concrete examples from the provided code
3. Explain the attack scenario realistically
4. Prioritize fixability - always suggest a practical fix
5. Reference industry standards (CWE, OWASP, NIST)
6. Write in Markdown format

Output Structure:
- **Summary**: One-line description
- **Severity Justification**: Why this severity level
- **Technical Analysis**: Detailed breakdown
- **Attack Scenario**: Step-by-step exploitation
- **Impact**: Potential consequences
- **Compliance**: Relevant standards/regulations
- **Fix Strategy**: Recommended approach
- **References**: Links/IDs to standards"""

    async def explain(self, finding) -> str:
        """Generate explanation for a vulnerability finding."""
        prompt = self._build_prompt(finding)

        try:
            response = await self.llm.complete(
                prompt=prompt,
                system_prompt=self.system_prompt,
                temperature=0.3,
                max_tokens=2048
            )
            return response.content

        except Exception as e:
            logger.error(f"Explanation generation failed: {e}")
            return self._generate_fallback_explanation(finding)

    def _build_prompt(self, finding) -> str:
        """Build structured explanation prompt."""
        return f"""# Security Vulnerability Analysis Request

## Vulnerability Information
- **Rule/Type**: {finding.rule_name}
- **Severity**: {finding.severity}
- **Confidence**: {finding.confidence:.0%}
- **CWE**: {finding.cwe_id or 'Unknown'}
- **OWASP Category**: {finding.owasp_category or 'Unknown'}
- **Location**: `{finding.file_path}:{finding.line_start}-{finding.line_end}`

## Scanner Message
{finding.message}

## Vulnerable Code
```
{finding.code_snippet}
```

## Context (Before)
```
{finding.context_before}
```

## Context (After)
```
{finding.context_after}
```

## Task
Provide a comprehensive vulnerability analysis using the specified output structure.
Focus on helping the developer understand WHY this is dangerous and HOW to fix it.
"""

    def _generate_fallback_explanation(self, finding) -> str:
        """Generate basic explanation if LLM fails."""
        severity_color = {
            'CRITICAL': '🔴',
            'HIGH': '🟠',
            'MEDIUM': '🟡',
            'LOW': '🟢',
            'INFO': '🔵'
        }
        icon = severity_color.get(finding.severity, '⚪')

        return f"""## {icon} {finding.rule_name}

**Severity**: {finding.severity} | **Confidence**: {finding.confidence:.0%}

### Summary
{finding.message}

### Location
`{finding.file_path}:{finding.line_start}`

### Vulnerable Code
```
{finding.code_snippet}
```

### Recommended Action
Review the identified code and apply secure coding practices to remediate the vulnerability.
Refer to CWE {finding.cwe_id or 'documentation'} for specific guidance.

*Note: AI-powered detailed analysis temporarily unavailable. Using scanner-provided information.*
"""

    async def batch_explain(self, findings: list) -> Dict[str, str]:
        """Generate explanations for multiple findings in parallel."""
        import asyncio
        tasks = [self.explain(f) for f in findings]
        explanations = await asyncio.gather(*tasks, return_exceptions=True)

        results = {}
        for i, finding in enumerate(findings):
            exp = explanations[i]
            results[finding.id] = exp if not isinstance(exp, Exception) else self._generate_fallback_explanation(finding)
        return results
