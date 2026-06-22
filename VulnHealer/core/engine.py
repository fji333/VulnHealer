"""
VulnHealer Core Engine
Orchestrates the entire AI-SAST pipeline: multi-scanner fusion, LLM analysis,
false-positive filtering, and patch validation.
"""

import json
import hashlib
import asyncio
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import logging

from rich.console import Console
from rich.progress import Progress, TaskID
from rich.table import Table
from rich.panel import Panel

# Local imports
from scanners.semgrep_scanner import SemgrepScanner
from scanners.bandit_scanner import BanditScanner
from scanners.secret_scanner import SecretScanner
from scanners.config_audit import ConfigAuditor
from scanners.fusion_engine import FusionEngine
from llm.patch_generator import PatchGenerator
from llm.explainer import VulnerabilityExplainer
from llm.multi_provider import MultiLLMProvider
from utils.fp_filter import FalsePositiveFilter
from utils.patch_validator import PatchValidator
from utils.code_context import CodeContextExtractor
from utils.report_generator import ReportGenerator

console = Console()
logger = logging.getLogger(__name__)


@dataclass
class VulnerabilityFinding:
    """Unified vulnerability finding across all scanners."""
    id: str
    scanner: str  # 'semgrep', 'bandit', 'codeql', 'fusion'
    severity: str  # 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'
    confidence: float  # 0.0 - 1.0
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    rule_id: str = ""
    rule_name: str = ""
    message: str = ""
    file_path: str = ""
    line_start: int = 0
    line_end: int = 0
    column_start: int = 0
    column_end: int = 0
    code_snippet: str = ""
    context_before: str = ""
    context_after: str = ""
    fix_suggestion: str = ""
    ai_analysis: str = ""
    ai_patch: str = ""
    patch_validated: bool = False
    patch_validation_result: str = ""
    is_false_positive: bool = False
    fp_confidence: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def generate_id(self) -> str:
        """Generate unique finding ID."""
        content = f"{self.file_path}:{self.line_start}:{self.rule_id}:{self.code_snippet}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]


@dataclass
class ScanResult:
    """Complete scan result for a target."""
    target_path: str
    scan_timestamp: str
    findings: List[VulnerabilityFinding] = field(default_factory=list)
    raw_results: Dict[str, Any] = field(default_factory=dict)
    statistics: Dict[str, Any] = field(default_factory=dict)
    duration_seconds: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            'target_path': self.target_path,
            'scan_timestamp': self.scan_timestamp,
            'findings': [asdict(f) for f in self.findings],
            'statistics': self.statistics,
            'duration_seconds': self.duration_seconds
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)


class VulnHealerEngine:
    """
    Main orchestration engine for AI-Enhanced SAST.

    Pipeline:
    1. Multi-scanner parallel execution
    2. Result fusion and deduplication
    3. Code context extraction
    4. LLM-powered analysis and patch generation
    5. False-positive filtering (ML-based + feedback learning)
    6. Patch validation (compilation + testing)
    7. Report generation
    """

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.scanners = []
        self.fusion_engine = FusionEngine()
        self.llm_provider = MultiLLMProvider(config)
        self.patch_generator = PatchGenerator(self.llm_provider)
        self.explainer = VulnerabilityExplainer(self.llm_provider)
        self.fp_filter = FalsePositiveFilter(config.get('fp_filter', {}))
        self.patch_validator = PatchValidator(config.get('patch_validation', {}))
        self.context_extractor = CodeContextExtractor(
            context_lines=config.get('context_lines_before', 5),
            context_lines_after=config.get('context_lines_after', 5)
        )
        self.report_generator = ReportGenerator()

        # Initialize scanners
        self._init_scanners()

        console.print(Panel.fit(
            "[bold cyan]VulnHealer Engine Initialized[/bold cyan]\n"
            "[green]AI-Enhanced SAST & Auto-Patch Engine v2.0[/green]",
            title="VulnHealer", border_style="cyan"
        ))

    def _init_scanners(self):
        """Initialize all configured scanners."""
        scanner_configs = self.config.get('scanners', {})

        if scanner_configs.get('semgrep', {}).get('enabled', True):
            self.scanners.append(SemgrepScanner(scanner_configs.get('semgrep', {})))
            console.print("[green]+[/green] Semgrep scanner loaded")

        if scanner_configs.get('bandit', {}).get('enabled', True):
            self.scanners.append(BanditScanner(scanner_configs.get('bandit', {})))
            console.print("[green]+[/green] Bandit scanner loaded")

        if scanner_configs.get('secret', {}).get('enabled', True):
            self.scanners.append(SecretScanner(scanner_configs.get('secret', {})))
            console.print("[green]+[/green] Secret scanner loaded")

        if scanner_configs.get('config_audit', {}).get('enabled', True):
            self.scanners.append(ConfigAuditor(scanner_configs.get('config_audit', {})))
            console.print("[green]+[/green] Config auditor loaded")

    async def scan(self, target_path: str, progress_callback=None) -> ScanResult:
        """
        Execute full scan pipeline on target.

        Args:
            target_path: Path to file or directory to scan
            progress_callback: Optional callback for progress updates

        Returns:
            ScanResult with all findings processed
        """
        start_time = datetime.now()
        target = Path(target_path)

        if not target.exists():
            raise FileNotFoundError(f"Target not found: {target_path}")

        console.print(f"\n[bold]Scanning target:[/bold] {target_path}")

        # Phase 1: Multi-scanner execution (parallel)
        raw_results = await self._execute_scanners(target_path, progress_callback)

        # Phase 2: Fusion and deduplication
        unified_findings = self._fuse_results(raw_results)
        console.print(f"[yellow]Found {len(unified_findings)} unique vulnerabilities[/yellow]")

        # Phase 3: Context extraction
        findings_with_context = self._extract_context(target_path, unified_findings)

        # Phase 4: LLM Analysis and Patch Generation (parallel)
        analyzed_findings = await self._analyze_findings(findings_with_context, progress_callback)

        # Phase 5: False-positive filtering
        filtered_findings = self._filter_false_positives(analyzed_findings)

        # Phase 6: Patch validation
        validated_findings = await self._validate_patches(target_path, filtered_findings)

        # Phase 7: Statistics
        duration = (datetime.now() - start_time).total_seconds()
        statistics = self._generate_statistics(raw_results, validated_findings)

        result = ScanResult(
            target_path=target_path,
            scan_timestamp=datetime.now().isoformat(),
            findings=validated_findings,
            raw_results=raw_results,
            statistics=statistics,
            duration_seconds=duration
        )

        self._print_summary(result)
        return result

    async def _execute_scanners(self, target_path: str, progress_callback=None) -> Dict[str, Any]:
        """Execute all scanners in parallel."""
        console.print("\n[bold blue]Phase 1: Multi-Scanner Execution[/bold blue]")

        results = {}

        with Progress() as progress:
            for scanner in self.scanners:
                task = progress.add_task(f"[cyan]Running {scanner.name}...", total=100)

                try:
                    scanner_result = await scanner.scan(target_path)
                    results[scanner.name] = scanner_result
                    progress.update(task, completed=100)
                    console.print(f"[green]{scanner.name}:[/green] Found {len(scanner_result.get('findings', []))} issues")
                except Exception as e:
                    console.print(f"[red]{scanner.name} failed:[/red] {str(e)}")
                    results[scanner.name] = {'error': str(e), 'findings': []}

        return results

    def _fuse_results(self, raw_results: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """Fuse and deduplicate results from multiple scanners."""
        console.print("\n[bold blue]Phase 2: Result Fusion & Deduplication[/bold blue]")

        all_findings = []
        for scanner_name, result in raw_results.items():
            if 'findings' in result:
                for finding in result['findings']:
                    vuln = self._convert_to_unified(finding, scanner_name)
                    vuln.id = vuln.generate_id()
                    all_findings.append(vuln)

        # Deduplication using Fusion Engine
        deduplicated = self.fusion_engine.deduplicate(all_findings)
        console.print(f"[green]Deduplicated:[/green] {len(all_findings)} -> {len(deduplicated)} findings")

        return deduplicated

    def _convert_to_unified(self, raw: Dict, scanner: str) -> VulnerabilityFinding:
        """Convert scanner-specific output to unified format."""
        return VulnerabilityFinding(
            id="",
            scanner=scanner,
            severity=raw.get('severity', 'MEDIUM').upper(),
            confidence=raw.get('confidence', 0.7),
            cwe_id=raw.get('cwe_id', raw.get('cwe', '')),
            owasp_category=raw.get('owasp', ''),
            rule_id=raw.get('rule_id', ''),
            rule_name=raw.get('rule_name', raw.get('check_name', '')),
            message=raw.get('message', raw.get('issue_text', '')),
            file_path=raw.get('file_path', raw.get('path', '')),
            line_start=raw.get('line_start', raw.get('line', 0)),
            line_end=raw.get('line_end', raw.get('line', 0)),
            column_start=raw.get('column_start', 0),
            column_end=raw.get('column_end', 0),
            code_snippet=raw.get('code_snippet', raw.get('code', '')),
            metadata=raw.get('metadata', {})
        )

    def _extract_context(self, target_path: str, findings: List[VulnerabilityFinding]) -> List[VulnerabilityFinding]:
        """Extract surrounding code context for each finding."""
        console.print("\n[bold blue]Phase 3: Context Extraction[/bold blue]")

        for finding in findings:
            try:
                context = self.context_extractor.extract(
                    finding.file_path,
                    finding.line_start,
                    finding.line_end
                )
                finding.context_before = context['before']
                finding.context_after = context['after']
            except Exception as e:
                logger.warning(f"Context extraction failed for {finding.file_path}:{finding.line_start}: {e}")

        return findings

    async def _analyze_findings(self, findings: List[VulnerabilityFinding], progress_callback=None) -> List[VulnerabilityFinding]:
        """Run LLM analysis and patch generation on all findings in parallel."""
        console.print("\n[bold blue]Phase 4: LLM Analysis & Patch Generation[/bold blue]")

        semaphore = asyncio.Semaphore(self.config.get('max_concurrent_llm', 5))

        async def analyze_one(finding: VulnerabilityFinding) -> VulnerabilityFinding:
            async with semaphore:
                try:
                    # Generate explanation
                    finding.ai_analysis = await self.explainer.explain(finding)

                    # Generate patch
                    finding.ai_patch = await self.patch_generator.generate(finding)

                    if progress_callback:
                        progress_callback()

                except Exception as e:
                    logger.error(f"LLM analysis failed for {finding.id}: {e}")
                    finding.ai_analysis = f"Analysis failed: {str(e)}"
                    finding.ai_patch = ""

                return finding

        tasks = [analyze_one(f) for f in findings]
        results = await asyncio.gather(*tasks)

        console.print(f"[green]Analyzed {len(results)} findings with LLM[/green]")
        return results

    def _filter_false_positives(self, findings: List[VulnerabilityFinding]) -> List[VulnerabilityFinding]:
        """Filter out likely false positives."""
        console.print("\n[bold blue]Phase 5: False-Positive Filtering[/bold blue]")

        if not self.config.get('enable_fp_filter', True):
            return findings

        filtered = []
        fp_count = 0

        for finding in findings:
            is_fp, confidence = self.fp_filter.predict(finding)
            finding.is_false_positive = is_fp
            finding.fp_confidence = confidence

            if is_fp and confidence > self.config.get('fp_threshold', 0.7):
                fp_count += 1
            else:
                filtered.append(finding)

        console.print(f"[yellow]Filtered {fp_count} likely false positives[/yellow]")
        console.print(f"[green]Remaining: {len(filtered)} high-confidence findings[/green]")

        return filtered

    async def _validate_patches(self, target_path: str, findings: List[VulnerabilityFinding]) -> List[VulnerabilityFinding]:
        """Validate generated patches."""
        console.print("\n[bold blue]Phase 6: Patch Validation[/bold blue]")

        if not self.config.get('enable_patch_validation', True):
            return findings

        validated_count = 0

        for finding in findings:
            if not finding.ai_patch:
                continue

            try:
                is_valid, message = await self.patch_validator.validate(
                    target_path,
                    finding.file_path,
                    finding.code_snippet,
                    finding.ai_patch
                )
                finding.patch_validated = is_valid
                finding.patch_validation_result = message

                if is_valid:
                    validated_count += 1

            except Exception as e:
                finding.patch_validation_result = f"Validation error: {str(e)}"

        console.print(f"[green]Validated {validated_count}/{len(findings)} patches[/green]")
        return findings

    def _generate_statistics(self, raw_results: Dict, findings: List[VulnerabilityFinding]) -> Dict[str, Any]:
        """Generate scan statistics."""
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        scanner_counts = {}
        cwe_counts = {}
        validated_patches = 0

        for f in findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
            scanner_counts[f.scanner] = scanner_counts.get(f.scanner, 0) + 1
            if f.cwe_id:
                cwe_counts[f.cwe_id] = cwe_counts.get(f.cwe_id, 0) + 1
            if f.patch_validated:
                validated_patches += 1

        return {
            'total_findings': len(findings),
            'severity_distribution': severity_counts,
            'scanner_distribution': scanner_counts,
            'top_cwes': dict(sorted(cwe_counts.items(), key=lambda x: x[1], reverse=True)[:10]),
            'validated_patches': validated_patches,
            'patch_success_rate': validated_patches / len(findings) if findings else 0,
            'raw_scanner_results': {k: len(v.get('findings', [])) for k, v in raw_results.items()}
        }

    def _print_summary(self, result: ScanResult):
        """Print scan summary to console."""
        console.print("\n" + "=" * 60)
        console.print("[bold green]SCAN COMPLETE[/bold green]")
        console.print("=" * 60)

        table = Table(title="Vulnerability Summary")
        table.add_column("Severity", style="cyan")
        table.add_column("Count", style="magenta")

        for severity, count in result.statistics['severity_distribution'].items():
            if count > 0:
                color = {'CRITICAL': 'red', 'HIGH': 'yellow', 'MEDIUM': 'blue', 'LOW': 'green', 'INFO': 'white'}
                table.add_row(f"[{color.get(severity, 'white')}]{severity}[/{color.get(severity, 'white')}]", str(count))

        table.add_row("[bold]Total[/bold]", str(result.statistics['total_findings']))
        console.print(table)

        console.print(f"\n[bold]Duration:[/bold] {result.duration_seconds:.2f}s")
        console.print(f"[bold]Patches Validated:[/bold] {result.statistics['validated_patches']}/{result.statistics['total_findings']}")

    def generate_report(self, result: ScanResult, output_format: str = 'html', output_path: str = None) -> str:
        """Generate scan report in specified format."""
        return self.report_generator.generate(result, output_format, output_path)

    def provide_feedback(self, finding_id: str, is_true_positive: bool):
        """Provide feedback to improve FP filter."""
        self.fp_filter.learn(finding_id, is_true_positive)
