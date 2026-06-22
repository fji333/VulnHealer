"""
VulnHealer Streamlit UI
Professional web interface for AI-powered static code analysis.
"""

import os
import sys
import json
import tempfile
from pathlib import Path
from datetime import datetime
from typing import Optional

import streamlit as st
from streamlit_ace import st_ace

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.engine import VulnHealerEngine, ScanResult
from utils.report_generator import ReportGenerator

# Page configuration
st.set_page_config(
    page_title="VulnHealer | AI-Powered SAST & Auto-Patch",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 3em;
        font-weight: bold;
        background: linear-gradient(45deg, #00C9FF, #92FE9D);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0.2em;
    }
    .sub-header {
        color: #8b949e;
        font-size: 1.2em;
        margin-bottom: 2em;
    }
    .stat-card {
        background: #161b22;
        border: 1px solid #30363d;
        border-radius: 12px;
        padding: 20px;
        text-align: center;
    }
    .stat-value {
        font-size: 2em;
        font-weight: bold;
        color: #c9d1d9;
    }
    .stat-label {
        color: #8b949e;
        font-size: 0.9em;
    }
    .severity-critical { color: #f85149; }
    .severity-high { color: #fb8500; }
    .severity-medium { color: #f0883e; }
    .severity-low { color: #3fb950; }
    .severity-info { color: #58a6ff; }
    .finding-card {
        background: #161b22;
        border: 1px solid #30363d;
        border-radius: 12px;
        padding: 20px;
        margin-bottom: 15px;
    }
    .code-block {
        background: #0d1117;
        border: 1px solid #30363d;
        border-radius: 8px;
        padding: 15px;
        font-family: 'SF Mono', Monaco, monospace;
        font-size: 0.85em;
        overflow-x: auto;
    }
    .patch-block {
        background: rgba(63, 185, 80, 0.1);
        border: 1px solid #3fb950;
        border-radius: 8px;
        padding: 15px;
        font-family: 'SF Mono', Monaco, monospace;
        font-size: 0.85em;
    }
    .analysis-block {
        background: rgba(88, 166, 255, 0.1);
        border: 1px solid #58a6ff;
        border-radius: 8px;
        padding: 15px;
    }
</style>
""", unsafe_allow_html=True)


def init_session_state():
    """Initialize session state variables."""
    if 'scan_result' not in st.session_state:
        st.session_state.scan_result = None
    if 'scan_history' not in st.session_state:
        st.session_state.scan_history = []
    if 'api_keys' not in st.session_state:
        st.session_state.api_keys = {
            'openai': os.getenv('OPENAI_API_KEY', ''),
            'deepseek': os.getenv('DEEPSEEK_API_KEY', ''),
            'anthropic': os.getenv('ANTHROPIC_API_KEY', ''),
            'ollama_url': os.getenv('OLLAMA_BASE_URL', 'http://localhost:11434')
        }


def sidebar():
    """Render sidebar."""
    with st.sidebar:
        st.markdown("# 🛡️ VulnHealer")
        st.markdown("*AI-Powered SAST & Auto-Patch Engine*")
        st.markdown("---")

        # API Configuration
        st.markdown("### 🔑 API Configuration")

        with st.expander("LLM Providers", expanded=False):
            st.session_state.api_keys['openai'] = st.text_input(
                "OpenAI API Key",
                value=st.session_state.api_keys['openai'],
                type="password"
            )
            st.session_state.api_keys['deepseek'] = st.text_input(
                "DeepSeek API Key",
                value=st.session_state.api_keys['deepseek'],
                type="password"
            )
            st.session_state.api_keys['anthropic'] = st.text_input(
                "Anthropic API Key",
                value=st.session_state.api_keys['anthropic'],
                type="password"
            )
            st.session_state.api_keys['ollama_url'] = st.text_input(
                "Ollama Base URL",
                value=st.session_state.api_keys['ollama_url']
            )

        # Scan Configuration
        st.markdown("### ⚙️ Scan Configuration")
        with st.expander("Scanner Settings", expanded=False):
            enable_semgrep = st.checkbox("Enable Semgrep", value=True, key="enable_semgrep")
            enable_bandit = st.checkbox("Enable Bandit", value=True, key="enable_bandit")
            enable_secret = st.checkbox("Enable Secret Scanner", value=True, key="enable_secret")
            enable_config_audit = st.checkbox("Enable Config Auditor", value=True, key="enable_config_audit")
            enable_fp_filter = st.checkbox("Enable FP Filter", value=True, key="enable_fp_filter")
            enable_patch_validation = st.checkbox("Enable Patch Validation", value=True, key="enable_patch_validation")

        # About
        st.markdown("---")
        st.markdown("### 📖 About")
        st.markdown("""
        **VulnHealer v2.0**

        Features:
        - Multi-scanner fusion (Semgrep + Bandit)
        - LLM-powered analysis & patch generation
        - False-positive filtering
        - Patch validation
        - SARIF/HTML/Markdown export

        [GitHub](https://github.com/yourusername/vulnhealer)
        """)


def render_header():
    """Render main header."""
    st.markdown('<div class="main-header">🛡️ VulnHealer</div>', unsafe_allow_html=True)
    st.markdown('<div class="sub-header">AI-Enhanced Static Application Security Testing & Automated Remediation</div>', unsafe_allow_html=True)


def render_code_input() -> str:
    """Render code input section."""
    st.markdown("### 📁 Upload or Paste Code")

    tab1, tab2, tab3 = st.tabs(["✏️ Editor", "📤 Upload", "🔗 GitHub URL"])

    code = ""

    with tab1:
        languages = ["python", "javascript", "typescript", "java", "c_cpp", "go", "ruby", "php"]
        selected_lang = st.selectbox("Language", languages, index=0)

        code = st_ace(
            placeholder="Paste your code here...",
            language=selected_lang,
            theme="monokai",
            height=400,
            key="code_editor",
            auto_update=True
        )

    with tab2:
        uploaded_file = st.file_uploader(
            "Upload source file or zip",
            type=['py', 'js', 'ts', 'java', 'c', 'cpp', 'go', 'rb', 'php', 'zip', 'tar.gz'],
            key="file_uploader"
        )
        if uploaded_file:
            if uploaded_file.name.endswith(('.zip', '.tar.gz')):
                # Handle archive upload
                import zipfile
                import io
                if uploaded_file.name.endswith('.zip'):
                    with zipfile.ZipFile(io.BytesIO(uploaded_file.read())) as z:
                        # Extract to temp directory
                        extract_path = tempfile.mkdtemp()
                        z.extractall(extract_path)
                        st.success(f"Extracted {len(z.namelist())} files to temp directory")
                        return extract_path
            else:
                code = uploaded_file.read().decode('utf-8', errors='replace')
                st.code(code, language=uploaded_file.name.split('.')[-1])

    with tab3:
        github_url = st.text_input("GitHub Repository URL", placeholder="https://github.com/user/repo")
        if github_url and st.button("Clone & Scan"):
            with st.spinner("Cloning repository..."):
                import subprocess
                clone_path = tempfile.mkdtemp()
                result = subprocess.run(
                    ['git', 'clone', '--depth', '1', github_url, clone_path],
                    capture_output=True,
                    text=True
                )
                if result.returncode == 0:
                    st.success("Repository cloned successfully!")
                    return clone_path
                else:
                    st.error(f"Clone failed: {result.stderr}")

    return code


def render_scan_button(code_or_path) -> bool:
    """Render scan button and trigger scan."""
    col1, col2, col3 = st.columns([1, 1, 4])

    with col1:
        scan_clicked = st.button("🔍 Scan for Vulnerabilities", type="primary", use_container_width=True)

    with col2:
        clear_clicked = st.button("🗑️ Clear Results", use_container_width=True)

    if clear_clicked:
        st.session_state.scan_result = None
        st.rerun()

    return scan_clicked


def run_scan(code_or_path: str) -> Optional[ScanResult]:
    """Execute scan pipeline."""
    with st.spinner("🔄 Initializing VulnHealer Engine..."):
        config = {
            'scanners': {
                'semgrep': {'enabled': st.session_state.get('enable_semgrep', True)},
                'bandit': {'enabled': st.session_state.get('enable_bandit', True)},
                'secret': {'enabled': st.session_state.get('enable_secret', True)},
                'config_audit': {'enabled': st.session_state.get('enable_config_audit', True)}
            },
            'llm': {
                'openai_api_key': st.session_state.api_keys['openai'],
                'deepseek_api_key': st.session_state.api_keys['deepseek'],
                'anthropic_api_key': st.session_state.api_keys['anthropic'],
                'default_provider': 'deepseek'
            },
            'context_lines_before': 5,
            'context_lines_after': 5,
            'enable_fp_filter': True,
            'enable_patch_validation': True,
            'max_concurrent_llm': 5
        }

        engine = VulnHealerEngine(config)

    # Create temp file for code
    if isinstance(code_or_path, str) and code_or_path.strip():
        if os.path.exists(code_or_path):
            target_path = code_or_path
        else:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
                f.write(code_or_path)
                target_path = f.name
    else:
        st.warning("Please provide code to scan")
        return None

    with st.spinner("🔍 Scanning... This may take a few minutes for LLM analysis."):
        import asyncio
        result = asyncio.run(engine.scan(target_path))

    st.session_state.scan_result = result
    st.session_state.scan_history.append({
        'timestamp': datetime.now().isoformat(),
        'target': target_path,
        'findings_count': len(result.findings)
    })

    return result


def render_stats(result: ScanResult):
    """Render scan statistics."""
    st.markdown("---")
    st.markdown("### 📊 Scan Summary")

    cols = st.columns(4)
    stats = result.statistics

    with cols[0]:
        st.markdown(f"""
        <div class="stat-card">
            <div class="stat-label">Total Findings</div>
            <div class="stat-value">{stats['total_findings']}</div>
        </div>
        """, unsafe_allow_html=True)

    with cols[1]:
        critical_high = stats['severity_distribution'].get('CRITICAL', 0) + \
                       stats['severity_distribution'].get('HIGH', 0)
        st.markdown(f"""
        <div class="stat-card">
            <div class="stat-label">Critical / High</div>
            <div class="stat-value severity-critical">{critical_high}</div>
        </div>
        """, unsafe_allow_html=True)

    with cols[2]:
        validated = stats.get('validated_patches', 0)
        st.markdown(f"""
        <div class="stat-card">
            <div class="stat-label">Validated Patches</div>
            <div class="stat-value severity-low">{validated}</div>
        </div>
        """, unsafe_allow_html=True)

    with cols[3]:
        success_rate = stats.get('patch_success_rate', 0) * 100
        st.markdown(f"""
        <div class="stat-card">
            <div class="stat-label">Patch Success Rate</div>
            <div class="stat-value">{success_rate:.0f}%</div>
        </div>
        """, unsafe_allow_html=True)


def render_findings(result: ScanResult):
    """Render vulnerability findings with AI analysis and patches."""
    st.markdown("---")
    st.markdown("### 🔍 Vulnerability Findings")

    if not result.findings:
        st.success("✅ No vulnerabilities found! Your code looks clean.")
        return

    # Filter options
    col1, col2, col3 = st.columns([2, 2, 2])
    with col1:
        severity_filter = st.multiselect(
            "Filter by Severity",
            ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'],
            default=['CRITICAL', 'HIGH', 'MEDIUM']
        )
    with col2:
        scanner_filter = st.multiselect(
            "Filter by Scanner",
            list(set(f.scanner for f in result.findings)),
            default=[]
        )
    with col3:
        show_fp = st.checkbox("Show Filtered (FP)", value=False)

    # Apply filters
    filtered = result.findings
    if severity_filter:
        filtered = [f for f in filtered if f.severity in severity_filter]
    if scanner_filter:
        filtered = [f for f in filtered if f.scanner in scanner_filter]
    if not show_fp:
        filtered = [f for f in filtered if not f.is_false_positive]

    st.write(f"Showing {len(filtered)} of {len(result.findings)} findings")

    # Render each finding
    for i, finding in enumerate(filtered):
        with st.expander(
            f"{finding.severity} | {finding.rule_name} | {finding.file_path.split('/')[-1]}:{finding.line_start}",
            expanded=(finding.severity in ['CRITICAL', 'HIGH'])
        ):
            cols = st.columns([1, 1])

            with cols[0]:
                st.markdown("**Vulnerable Code:**")
                st.code(finding.code_snippet, language="python")

            with cols[1]:
                if finding.ai_patch:
                    st.markdown("**🔧 AI Generated Patch:**")
                    st.markdown(f'<div class="patch-block"><pre><code>{finding.ai_patch}</code></pre></div>', unsafe_allow_html=True)
                    if finding.patch_validated:
                        st.success("✅ Patch validated (syntax correct)")
                    else:
                        st.warning("⚠️ Patch not validated - review before applying")
                else:
                    st.info("No patch generated")

            # AI Analysis
            if finding.ai_analysis:
                st.markdown("**🔍 AI Security Analysis:**")
                st.markdown(f'<div class="analysis-block">{finding.ai_analysis}</div>', unsafe_allow_html=True)

            # Metadata
            meta_cols = st.columns(4)
            with meta_cols[0]:
                st.metric("Confidence", f"{finding.confidence:.0%}")
            with meta_cols[1]:
                st.metric("Scanner", finding.scanner)
            with meta_cols[2]:
                st.metric("CWE", finding.cwe_id or "N/A")
            with meta_cols[3]:
                st.metric("FP Probability", f"{finding.fp_confidence:.0%}")


def render_export(result: ScanResult):
    """Render report export section."""
    st.markdown("---")
    st.markdown("### 📥 Export Report")

    col1, col2, col3, col4 = st.columns(4)

    report_gen = ReportGenerator()

    with col1:
        if st.button("📄 HTML Report", use_container_width=True):
            with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as f:
                report_path = f.name
            report_gen.generate(result, 'html', report_path)
            with open(report_path, 'rb') as f:
                st.download_button(
                    "Download HTML",
                    f.read(),
                    file_name=f"vulnhealer_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html",
                    mime="text/html",
                    use_container_width=True
                )

    with col2:
        if st.button("📋 Markdown", use_container_width=True):
            md_content = report_gen.generate(result, 'markdown')
            st.download_button(
                "Download Markdown",
                md_content,
                file_name=f"vulnhealer_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
                mime="text/markdown",
                use_container_width=True
            )

    with col3:
        if st.button("🔍 SARIF", use_container_width=True):
            sarif_content = report_gen.generate(result, 'sarif')
            st.download_button(
                "Download SARIF",
                sarif_content,
                file_name=f"vulnhealer_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.sarif",
                mime="application/json",
                use_container_width=True
            )

    with col4:
        json_content = result.to_json()
        st.download_button(
            "Download JSON",
            json_content,
            file_name=f"vulnhealer_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json",
            use_container_width=True
        )


def main():
    """Main Streamlit app."""
    init_session_state()
    sidebar()
    render_header()

    # Code input
    code_or_path = render_code_input()

    # Scan button
    scan_clicked = render_scan_button(code_or_path)

    if scan_clicked and (code_or_path or (isinstance(code_or_path, str) and code_or_path.strip())):
        result = run_scan(code_or_path)
    else:
        result = st.session_state.scan_result

    # Display results
    if result:
        render_stats(result)
        render_findings(result)
        render_export(result)

    # Scan history
    if st.session_state.scan_history:
        st.markdown("---")
        st.markdown("### 📜 Scan History")
        for entry in reversed(st.session_state.scan_history[-5:]):
            st.write(f"🕐 {entry['timestamp']} - {entry['findings_count']} findings")


if __name__ == "__main__":
    main()
