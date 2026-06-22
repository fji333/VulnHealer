"""
VulnHealer - AI-Powered SAST & Auto-Patch Engine
==================================================

A production-grade, AI-enhanced static application security testing (SAST) tool
that combines multi-scanner fusion, LLM-powered vulnerability analysis,
and automated patch generation with validation.

Features:
- Multi-scanner fusion (Semgrep + Bandit + extensible)
- Multi-LLM support (OpenAI, DeepSeek, Anthropic, Ollama local)
- Intelligent false-positive filtering with ML
- Automated secure patch generation and validation
- Professional web UI (Streamlit)
- SARIF/HTML/Markdown/JSON report export
- CI/CD integration ready

Usage:
    streamlit run ui/streamlit_app.py

    # Or use CLI:
    python -m vulnhealer.cli scan /path/to/code --output report.html

Author: VulnHealer Team
Version: 2.0.0
License: MIT
"""

__version__ = "2.0.0"
__author__ = "VulnHealer Team"

from core.engine import VulnHealerEngine, VulnerabilityFinding, ScanResult

__all__ = [
    'VulnHealerEngine',
    'VulnerabilityFinding',
    'ScanResult',
    '__version__'
]
