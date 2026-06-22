"""
Report Generator
Generates professional scan reports in multiple formats.
"""

import json
import base64
from pathlib import Path
from datetime import datetime
from typing import Optional
import logging

from jinja2 import Template
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots

logger = logging.getLogger(__name__)


class ReportGenerator:
    """
    Generates comprehensive security scan reports.

    Supported formats:
    - HTML (interactive, with charts)
    - PDF (via HTML + print)
    - SARIF (standard format)
    - JSON (machine-readable)
    - Markdown (for GitHub/GitLab)
    """

    def __init__(self):
        self.templates_dir = Path(__file__).parent.parent / 'templates'
        self.assets_dir = Path(__file__).parent.parent / 'assets'

    def generate(self, scan_result, output_format: str = 'html',
                 output_path: str = None) -> str:
        """Generate report in specified format."""
        format_generators = {
            'html': self._generate_html,
            'sarif': self._generate_sarif,
            'json': self._generate_json,
            'markdown': self._generate_markdown,
        }

        generator = format_generators.get(output_format.lower())
        if not generator:
            raise ValueError(f"Unsupported format: {output_format}")

        content = generator(scan_result)

        if output_path:
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(content)
            logger.info("Report saved to %s", output_path)

        return content

    def _generate_html(self, result) -> str:
        """Generate interactive HTML report."""
        # Create severity pie chart
        severity_data = result.statistics['severity_distribution']
        colors = {'CRITICAL': '#DC3545', 'HIGH': '#FD7E14', 'MEDIUM': '#FFC107',
                  'LOW': '#28A745', 'INFO': '#17A2B8'}

        fig = go.Figure(data=[go.Pie(
            labels=list(severity_data.keys()),
            values=list(severity_data.values()),
            marker_colors=[colors.get(k, '#6C757D') for k in severity_data.keys()],
            hole=0.4
        )])
        fig.update_layout(
            title="Vulnerability Severity Distribution",
            showlegend=True,
            width=500,
            height=400
        )
        severity_chart = fig.to_html(full_html=False, include_plotlyjs='cdn')

        # Build findings table HTML
        findings_rows = ""
        for f in result.findings:
            severity_badge = self._severity_badge(f.severity)
            patch_status = "✅ Validated" if f.patch_validated else "⚠️ Unvalidated"
            if not f.ai_patch:
                patch_status = "❌ No Patch"

            findings_rows += f"""
            <tr>
                <td><code>{f.id[:8]}</code></td>
                <td>{severity_badge}</td>
                <td>{f.rule_name}</td>
                <td><code>{f.file_path.split('/')[-1]}:{f.line_start}</code></td>
                <td>{f.cwe_id or 'N/A'}</td>
                <td>{patch_status}</td>
            </tr>
            <tr class="finding-detail" id="detail-{f.id[:8]}">
                <td colspan="6">
                    <div class="detail-content">
                        <p><strong>Scanner:</strong> {f.scanner}</p>
                        <p><strong>Message:</strong> {f.message}</p>
                        <pre class="code-block"><code>{f.code_snippet}</code></pre>
                        {f'<div class="ai-analysis"><h4>🔍 AI Analysis</h4><div>{self._markdown_to_html(f.ai_analysis)}</div></div>' if f.ai_analysis else ''}
                        {f'<div class="ai-patch"><h4>🔧 AI Generated Patch</h4><pre><code>{f.ai_patch}</code></pre></div>' if f.ai_patch else ''}
                    </div>
                </td>
            </tr>
            """

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VulnHealer Report - {result.target_path.split('/')[-1]}</title>
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
    <style>
        :root {{
            --bg: #0d1117;
            --fg: #c9d1d9;
            --card-bg: #161b22;
            --border: #30363d;
            --critical: #f85149;
            --high: #fb8500;
            --medium: #f0883e;
            --low: #3fb950;
            --info: #58a6ff;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg);
            color: var(--fg);
            margin: 0;
            padding: 20px;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}
        header {{
            text-align: center;
            padding: 40px 0;
            border-bottom: 1px solid var(--border);
            margin-bottom: 30px;
        }}
        .logo {{
            font-size: 3em;
            margin-bottom: 10px;
        }}
        h1 {{
            margin: 0;
            color: #fff;
        }}
        .meta {{
            color: #8b949e;
            margin-top: 10px;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .stat-card {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
            text-align: center;
        }}
        .stat-value {{
            font-size: 2.5em;
            font-weight: bold;
            margin: 10px 0;
        }}
        .stat-label {{
            color: #8b949e;
            font-size: 0.9em;
        }}
        .severity-CRITICAL {{ color: var(--critical); }}
        .severity-HIGH {{ color: var(--high); }}
        .severity-MEDIUM {{ color: var(--medium); }}
        .severity-LOW {{ color: var(--low); }}
        .severity-INFO {{ color: var(--info); }}
        .chart-container {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 30px;
        }}
        .findings-table {{
            width: 100%;
            border-collapse: collapse;
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 12px;
            overflow: hidden;
        }}
        .findings-table th {{
            background: #21262d;
            padding: 12px;
            text-align: left;
            font-weight: 600;
        }}
        .findings-table td {{
            padding: 12px;
            border-top: 1px solid var(--border);
        }}
        .findings-table tr:hover {{
            background: rgba(88, 166, 255, 0.05);
        }}
        .badge {{
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 600;
        }}
        .badge-critical {{ background: rgba(248, 81, 73, 0.2); color: var(--critical); }}
        .badge-high {{ background: rgba(251, 133, 0, 0.2); color: var(--high); }}
        .badge-medium {{ background: rgba(240, 136, 62, 0.2); color: var(--medium); }}
        .badge-low {{ background: rgba(63, 185, 80, 0.2); color: var(--low); }}
        .badge-info {{ background: rgba(88, 166, 255, 0.2); color: var(--info); }}
        .code-block {{
            background: #0d1117;
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 15px;
            overflow-x: auto;
            font-family: 'SF Mono', Monaco, monospace;
            font-size: 0.9em;
            margin: 10px 0;
        }}
        .finding-detail {{
            display: none;
        }}
        .finding-detail.active {{
            display: table-row;
        }}
        .detail-content {{
            padding: 20px;
            background: #0d1117;
        }}
        .ai-analysis {{
            border-left: 3px solid var(--info);
            padding-left: 15px;
            margin: 15px 0;
        }}
        .ai-patch {{
            border-left: 3px solid var(--low);
            padding-left: 15px;
            margin: 15px 0;
        }}
        .clickable {{
            cursor: pointer;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo">🛡️</div>
            <h1>VulnHealer Security Report</h1>
            <div class="meta">
                Target: <code>{result.target_path}</code> |
                Scanned: {result.scan_timestamp} |
                Duration: {result.duration_seconds:.1f}s
            </div>
        </header>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">Total Findings</div>
                <div class="stat-value">{result.statistics['total_findings']}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Critical / High</div>
                <div class="stat-value severity-CRITICAL">
                    {result.statistics['severity_distribution'].get('CRITICAL', 0) +
                     result.statistics['severity_distribution'].get('HIGH', 0)}
                </div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Validated Patches</div>
                <div class="stat-value severity-LOW">
                    {result.statistics.get('validated_patches', 0)}
                </div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Patch Success Rate</div>
                <div class="stat-value">
                    {result.statistics.get('patch_success_rate', 0) * 100:.0f}%
                </div>
            </div>
        </div>

        <div class="chart-container">
            {severity_chart}
        </div>

        <table class="findings-table">
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Severity</th>
                    <th>Rule</th>
                    <th>Location</th>
                    <th>CWE</th>
                    <th>Patch Status</th>
                </tr>
            </thead>
            <tbody>
                {findings_rows}
            </tbody>
        </table>
    </div>

    <script>
        document.querySelectorAll('.findings-table tbody tr:not(.finding-detail)').forEach(row => {{
            row.addEventListener('click', () => {{
                const detail = row.nextElementSibling;
                if (detail && detail.classList.contains('finding-detail')) {{
                    detail.classList.toggle('active');
                }}
            }});
        }});
    </script>
</body>
</html>"""

        return html

    def _generate_sarif(self, result) -> str:
        """Generate SARIF format report."""
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "VulnHealer",
                        "version": "2.0.0",
                        "informationUri": "https://vulnhealer.dev"
                    }
                },
                "results": []
            }]
        }

        for f in result.findings:
            sarif_result = {
                "ruleId": f.rule_id or f.rule_name,
                "message": {"text": f.message},
                "level": f.severity.lower() if f.severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] else "note",
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.file_path},
                        "region": {
                            "startLine": f.line_start,
                            "endLine": f.line_end,
                            "startColumn": f.column_start,
                            "endColumn": f.column_end
                        }
                    }
                }],
                "properties": {
                    "confidence": f.confidence,
                    "cwe": f.cwe_id,
                    "scanner": f.scanner,
                    "aiPatch": f.ai_patch,
                    "patchValidated": f.patch_validated
                }
            }
            sarif["runs"][0]["results"].append(sarif_result)

        return json.dumps(sarif, indent=2)

    def _generate_json(self, result) -> str:
        """Generate JSON report."""
        return result.to_json()

    def _generate_markdown(self, result) -> str:
        """Generate Markdown report for GitHub/GitLab."""
        md = f"""# 🔒 VulnHealer Security Scan Report

## Scan Summary

| Metric | Value |
|--------|-------|
| **Target** | `{result.target_path}` |
| **Scan Time** | {result.scan_timestamp} |
| **Duration** | {result.duration_seconds:.1f}s |
| **Total Findings** | {result.statistics['total_findings']} |
| **Validated Patches** | {result.statistics.get('validated_patches', 0)} |

## Severity Distribution

| Severity | Count |
|----------|-------|
"""
        for sev, count in result.statistics['severity_distribution'].items():
            icon = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢', 'INFO': '🔵'}.get(sev, '⚪')
            md += f"| {icon} {sev} | {count} |\n"

        md += "\n## Findings\n\n"

        for f in result.findings:
            md += f"""### {f.rule_name}

- **Severity**: `{f.severity}`
- **Location**: `{f.file_path}:{f.line_start}`
- **CWE**: {f.cwe_id or 'N/A'}
- **Scanner**: {f.scanner}

**Vulnerable Code**:
```
{f.code_snippet}
```

{f'**AI Analysis**: {f.ai_analysis[:500]}...' if f.ai_analysis else ''}

{f'**AI Patch**: \n```\n' + f.ai_patch + '\n```' if f.ai_patch else ''}

---
"""

        return md

    def _severity_badge(self, severity: str) -> str:
        """Generate severity badge HTML."""
        classes = {
            'CRITICAL': 'badge-critical',
            'HIGH': 'badge-high',
            'MEDIUM': 'badge-medium',
            'LOW': 'badge-low',
            'INFO': 'badge-info'
        }
        return f'<span class="badge {classes.get(severity, '')}">{severity}</span>'

    def _markdown_to_html(self, text: str) -> str:
        """Basic markdown to HTML conversion."""
        import re
        # Bold
        text = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', text)
        # Headers
        text = re.sub(r'^### (.+)$', r'<h3>\1</h3>', text, flags=re.MULTILINE)
        text = re.sub(r'^## (.+)$', r'<h2>\1</h2>', text, flags=re.MULTILINE)
        # Code blocks
        text = re.sub(r'`([^`]+)`', r'<code>\1</code>', text)
        # Line breaks
        text = text.replace('\n', '<br>')
        return text
