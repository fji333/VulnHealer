"""
VulnHealer CLI Entry Point
Command-line interface for batch scanning and CI/CD integration.
"""

import os
import sys
import json
import asyncio
import argparse
from pathlib import Path
from datetime import datetime

from core.engine import VulnHealerEngine
from utils.report_generator import ReportGenerator


def setup_config(args) -> dict:
    """Build configuration from CLI arguments and environment."""
    return {
        'scanners': {
            'semgrep': {
                'enabled': not args.no_semgrep,
                'rules': args.semgrep_rules.split(',') if args.semgrep_rules else None
            },
            'bandit': {
                'enabled': not args.no_bandit
            }
        },
        'llm': {
            'openai_api_key': os.getenv('OPENAI_API_KEY'),
            'deepseek_api_key': os.getenv('DEEPSEEK_API_KEY'),
            'anthropic_api_key': os.getenv('ANTHROPIC_API_KEY'),
            'default_provider': args.llm_provider
        },
        'context_lines_before': args.context_lines,
        'context_lines_after': args.context_lines,
        'enable_fp_filter': not args.no_fp_filter,
        'enable_patch_validation': not args.no_patch_validation,
        'max_concurrent_llm': args.max_workers,
        'fp_filter': {
            'threshold': args.fp_threshold
        }
    }


def print_banner():
    """Print CLI banner."""
    print("""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗██╗  ██╗███████╗       ║
║   ██║   ██║██║   ██║██║     ████╗  ██║██║  ██║██╔════╝       ║
║   ██║   ██║██║   ██║██║     ██╔██╗ ██║███████║█████╗         ║
║   ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██╔══██║██╔══╝         ║
║    ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║██║  ██║███████╗       ║
║     ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝       ║
║                                                              ║
║   AI-Powered SAST & Auto-Patch Engine v2.0                   ║
╚══════════════════════════════════════════════════════════════╝
""")


async def scan_command(args):
    """Execute scan command."""
    print_banner()

    target = Path(args.target)
    if not target.exists():
        print(f"Error: Target not found: {args.target}")
        sys.exit(1)

    config = setup_config(args)
    engine = VulnHealerEngine(config)

    print(f"[INFO] Starting scan of: {args.target}")
    result = await engine.scan(args.target)

    # Generate reports
    report_gen = ReportGenerator()

    if args.output:
        output_path = Path(args.output)
        fmt = output_path.suffix.lstrip('.')

        if fmt == 'html':
            report_gen.generate(result, 'html', str(output_path))
        elif fmt == 'json':
            with open(output_path, 'w') as f:
                f.write(result.to_json())
        elif fmt == 'sarif':
            report_gen.generate(result, 'sarif', str(output_path))
        elif fmt in ['md', 'markdown']:
            report_gen.generate(result, 'markdown', str(output_path))
        else:
            print(f"[WARN] Unknown format: {fmt}, defaulting to JSON")
            with open(output_path, 'w') as f:
                f.write(result.to_json())

        print(f"[INFO] Report saved to: {args.output}")

    # Print summary
    print("\n" + "=" * 60)
    print("SCAN SUMMARY")
    print("=" * 60)
    print(f"Total findings: {result.statistics['total_findings']}")
    print(f"Critical: {result.statistics['severity_distribution'].get('CRITICAL', 0)}")
    print(f"High: {result.statistics['severity_distribution'].get('HIGH', 0)}")
    print(f"Medium: {result.statistics['severity_distribution'].get('MEDIUM', 0)}")
    print(f"Low: {result.statistics['severity_distribution'].get('LOW', 0)}")
    print(f"Info: {result.statistics['severity_distribution'].get('INFO', 0)}")
    print(f"\nPatches validated: {result.statistics.get('validated_patches', 0)}")
    print(f"Duration: {result.duration_seconds:.1f}s")

    # Exit code based on findings
    critical_high = result.statistics['severity_distribution'].get('CRITICAL', 0) + \
                    result.statistics['severity_distribution'].get('HIGH', 0)
    if critical_high > 0 and args.fail_on_high:
        sys.exit(2)


def main():
    parser = argparse.ArgumentParser(
        prog='vulnhealer',
        description='AI-Powered SAST & Auto-Patch Engine'
    )

    subparsers = parser.add_subparsers(dest='command')

    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Scan code for vulnerabilities')
    scan_parser.add_argument('target', help='Path to file or directory to scan')
    scan_parser.add_argument('-o', '--output', help='Output file path')
    scan_parser.add_argument('--format', choices=['html', 'json', 'sarif', 'markdown'],
                            default='json', help='Output format')
    scan_parser.add_argument('--llm-provider', choices=['deepseek', 'openai', 'anthropic', 'ollama'],
                            default='deepseek', help='Primary LLM provider')
    scan_parser.add_argument('--no-semgrep', action='store_true', help='Disable Semgrep')
    scan_parser.add_argument('--no-bandit', action='store_true', help='Disable Bandit')
    scan_parser.add_argument('--no-llm', action='store_true', help='Disable LLM analysis')
    scan_parser.add_argument('--no-fp-filter', action='store_true', help='Disable FP filter')
    scan_parser.add_argument('--no-patch-validation', action='store_true',
                            help='Disable patch validation')
    scan_parser.add_argument('--context-lines', type=int, default=5,
                            help='Context lines around finding')
    scan_parser.add_argument('--semgrep-rules', help='Comma-separated Semgrep rule configs')
    scan_parser.add_argument('--max-workers', type=int, default=4,
                            help='Max concurrent LLM requests')
    scan_parser.add_argument('--fp-threshold', type=float, default=0.7,
                            help='False positive confidence threshold')
    scan_parser.add_argument('--fail-on-high', action='store_true',
                            help='Exit with error if HIGH/CRITICAL findings')

    # Report command
    report_parser = subparsers.add_parser('report', help='Generate report from scan results')
    report_parser.add_argument('input', help='Input JSON file from previous scan')
    report_parser.add_argument('-o', '--output', required=True, help='Output file path')
    report_parser.add_argument('--format', choices=['html', 'sarif', 'markdown'],
                              required=True, help='Output format')

    args = parser.parse_args()

    if args.command == 'scan':
        asyncio.run(scan_command(args))
    elif args.command == 'report':
        print("Report generation from existing scan - not yet implemented")
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
