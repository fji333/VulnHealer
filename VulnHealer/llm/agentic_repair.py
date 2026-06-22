"""
Agentic Repair Bot
Autonomous vulnerability repair agent using LLM planning + execution loop.
Implements: Plan → Execute → Verify → Iterate cycle.
"""

import asyncio
import json
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class RepairPlan:
    """Structured repair plan for a vulnerability."""
    finding_id: str
    vulnerability_type: str
    root_cause: str
    fix_strategy: str
    steps: List[str]
    estimated_complexity: str  # low/medium/high
    potential_side_effects: List[str]
    success_criteria: str


@dataclass
class RepairAttempt:
    """Single repair attempt result."""
    attempt_num: int
    patch: str
    validation_passed: bool
    validation_message: str
    feedback: str = ""


@dataclass
class AgentRepairResult:
    """Complete repair result from the agent."""
    finding_id: str
    plan: RepairPlan
    attempts: List[RepairAttempt] = field(default_factory=list)
    final_patch: Optional[str] = None
    success: bool = False
    total_attempts: int = 0
    agent_reasoning: str = ""


class AgenticRepairBot:
    """
    LLM-powered autonomous repair agent.

    Implements the PLAN → GENERATE → VALIDATE → REFLECT loop:
    1. PLAN: Analyze vulnerability and create structured repair plan
    2. GENERATE: Generate patch based on plan
    3. VALIDATE: Syntax + security regression check
    4. REFLECT: If validation fails, analyze why and revise
    5. ITERATE: Up to max_attempts times
    """

    def __init__(self, llm_provider, patch_validator, config: Dict = None):
        self.llm = llm_provider
        self.validator = patch_validator
        self.config = config or {}
        self.max_attempts = self.config.get("max_attempts", 3)

        self.planner_system_prompt = """You are an expert security engineer and automated repair agent.
Your job is to create a precise, structured plan to fix a security vulnerability.

CRITICAL REQUIREMENTS:
- Be conservative: don't change more than necessary
- Preserve all function signatures and variable names
- Focus on root cause, not symptoms
- Consider side effects of your fix

Return ONLY a JSON object with exactly these fields:
{
  "root_cause": "string",
  "fix_strategy": "string",
  "steps": ["step1", "step2"],
  "estimated_complexity": "low|medium|high",
  "potential_side_effects": ["effect1"],
  "success_criteria": "string"
}"""

        self.repair_system_prompt = """You are an expert security engineer performing automated vulnerability repair.
You have analyzed the vulnerability and created a repair plan. Now implement it.

Rules:
1. Output ONLY the fixed code - no explanations
2. Preserve exact indentation and code style
3. Change ONLY what is necessary to fix the vulnerability
4. The fix must be complete and functional

Format: ```<language>\n<fixed_code>\n```"""

        self.reflect_system_prompt = """You are debugging a failed security patch.
The patch failed validation. Analyze why and create a better version.

Output ONLY the corrected code:
```<language>
<better_fixed_code>
```"""

    async def repair(self, finding, project_path: str = ".") -> AgentRepairResult:
        """
        Autonomously repair a vulnerability.

        Args:
            finding: VulnerabilityFinding object
            project_path: Root path for patch validation context

        Returns:
            AgentRepairResult with patch and success status
        """
        result = AgentRepairResult(finding_id=finding.id, plan=None, attempts=[])

        # Phase 1: Plan
        logger.info(f"[AgentBot] Planning repair for {finding.rule_name}")
        plan = await self._plan_repair(finding)
        result.plan = plan

        current_patch = None
        validation_feedback = ""

        # Phase 2-4: Generate → Validate → Reflect loop
        for attempt in range(1, self.max_attempts + 1):
            logger.info(f"[AgentBot] Repair attempt {attempt}/{self.max_attempts}")

            # Generate or revise patch
            if attempt == 1:
                patch = await self._generate_patch(finding, plan)
            else:
                patch = await self._reflect_and_revise(finding, current_patch, validation_feedback)

            current_patch = patch

            # Validate patch
            is_valid, validation_msg = await self.validator.validate(
                project_path, finding.file_path, finding.code_snippet, patch
            )

            attempt_result = RepairAttempt(
                attempt_num=attempt,
                patch=patch,
                validation_passed=is_valid,
                validation_message=validation_msg,
                feedback=validation_feedback
            )
            result.attempts.append(attempt_result)
            result.total_attempts = attempt

            if is_valid:
                result.final_patch = patch
                result.success = True
                result.agent_reasoning = f"Fixed in {attempt} attempt(s). Strategy: {plan.fix_strategy}"
                logger.info(f"[AgentBot] ✅ Repair succeeded on attempt {attempt}")
                break

            validation_feedback = validation_msg
            logger.warning(f"[AgentBot] Attempt {attempt} failed: {validation_msg[:100]}")

        if not result.success and current_patch:
            # Even if validation failed, provide best-effort patch
            result.final_patch = current_patch
            result.agent_reasoning = f"Best-effort patch after {self.max_attempts} attempts. Manual review required."

        return result

    async def _plan_repair(self, finding) -> RepairPlan:
        """Generate structured repair plan using LLM."""
        prompt = f"""Analyze this vulnerability and create a repair plan:

Vulnerability: {finding.rule_name}
Severity: {finding.severity}
CWE: {finding.cwe_id}
Message: {finding.message}

Vulnerable code:
```
{finding.code_snippet}
```

Context before:
```
{finding.context_before}
```
"""
        try:
            response = await self.llm.complete(
                prompt=prompt,
                system_prompt=self.planner_system_prompt,
                temperature=0.1,
                max_tokens=1024
            )

            # Parse JSON from response
            import re
            json_match = re.search(r'\{.*\}', response.content, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group())
                return RepairPlan(
                    finding_id=finding.id,
                    vulnerability_type=finding.rule_name,
                    root_cause=data.get("root_cause", ""),
                    fix_strategy=data.get("fix_strategy", ""),
                    steps=data.get("steps", []),
                    estimated_complexity=data.get("estimated_complexity", "medium"),
                    potential_side_effects=data.get("potential_side_effects", []),
                    success_criteria=data.get("success_criteria", "")
                )
        except Exception as e:
            logger.warning(f"Plan generation failed: {e}")

        # Fallback plan
        return RepairPlan(
            finding_id=finding.id,
            vulnerability_type=finding.rule_name,
            root_cause=finding.message,
            fix_strategy="Apply secure coding pattern",
            steps=["Identify vulnerability", "Apply fix", "Verify"],
            estimated_complexity="medium",
            potential_side_effects=[],
            success_criteria="No vulnerability flagged on rescan"
        )

    async def _generate_patch(self, finding, plan: RepairPlan) -> str:
        """Generate initial patch based on plan."""
        prompt = f"""## Vulnerability to Fix
Type: {finding.rule_name} ({finding.cwe_id})
Root Cause: {plan.root_cause}
Fix Strategy: {plan.fix_strategy}
Steps: {chr(10).join(f"  {i+1}. {s}" for i, s in enumerate(plan.steps))}

## Vulnerable Code
```
{finding.code_snippet}
```

## Context
```
{finding.context_before}
```
```
{finding.context_after}
```
"""
        try:
            response = await self.llm.complete(
                prompt=prompt,
                system_prompt=self.repair_system_prompt,
                temperature=0.05,
                max_tokens=2048
            )
            return self._extract_code(response.content)
        except Exception as e:
            logger.error(f"Patch generation failed: {e}")
            return ""

    async def _reflect_and_revise(self, finding, failed_patch: str, error: str) -> str:
        """Reflect on failure and generate improved patch."""
        prompt = f"""## Failed Patch
```
{failed_patch}
```

## Validation Error
{error}

## Original Vulnerability
{finding.message}

## Vulnerable Code
```
{finding.code_snippet}
```

The patch above failed validation. Fix the issue in the patch and return a corrected version.
"""
        try:
            response = await self.llm.complete(
                prompt=prompt,
                system_prompt=self.reflect_system_prompt,
                temperature=0.1,
                max_tokens=2048
            )
            return self._extract_code(response.content)
        except Exception as e:
            logger.error(f"Reflect failed: {e}")
            return failed_patch  # Return original if reflection fails

    def _extract_code(self, response: str) -> str:
        """Extract code from LLM response."""
        import re
        matches = re.findall(r'```(?:\w+)?\n(.*?)\n```', response, re.DOTALL)
        if matches:
            return matches[0].strip()
        return response.strip()

    async def batch_repair(self, findings: List, project_path: str = ".") -> List[AgentRepairResult]:
        """Repair multiple findings with controlled concurrency."""
        sem = asyncio.Semaphore(3)

        async def _repair_with_sem(finding):
            async with sem:
                return await self.repair(finding, project_path)

        return await asyncio.gather(*[_repair_with_sem(f) for f in findings])
