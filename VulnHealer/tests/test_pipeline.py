"""
Test VulnHealer Core Pipeline
Quick integration test to verify the engine works end-to-end.
Run: python tests/test_pipeline.py
"""

import asyncio
import tempfile
import os
from pathlib import Path

# Add project root to path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.engine import VulnHealerEngine


TEST_VULNERABLE_CODE = '''
import os
import pickle
import sqlite3
from flask import Flask, request

app = Flask(__name__)

# SQL Injection vulnerability
def get_user(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchall()

# XSS vulnerability
@app.route('/greet')
def greet():
    name = request.args.get('name', 'Guest')
    return f"<h1>Hello, {name}!</h1>"

# Command injection
def run_command(cmd):
    os.system(cmd)

# Unsafe deserialization
def load_data(data):
    return pickle.loads(data)

# Hardcoded password
API_KEY = "sk-1234567890abcdef"

if __name__ == '__main__':
    app.run(debug=True)
'''


def test_basic_pipeline():
    """Test the complete pipeline with sample vulnerable code."""
    print("🧪 VulnHealer Pipeline Test")
    print("=" * 50)

    # Create temp file with vulnerable code
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(TEST_VULNERABLE_CODE)
        temp_path = f.name

    print(f"📄 Created test file: {temp_path}")

    # Configure engine
    config = {
        'scanners': {
            'semgrep': {'enabled': True},
            'bandit': {'enabled': True}
        },
        'llm': {
            'openai_api_key': os.getenv('OPENAI_API_KEY', ''),
            'deepseek_api_key': os.getenv('DEEPSEEK_API_KEY', ''),
            'anthropic_api_key': os.getenv('ANTHROPIC_API_KEY', ''),
            'default_provider': 'deepseek'
        },
        'context_lines_before': 3,
        'context_lines_after': 3,
        'enable_fp_filter': True,
        'enable_patch_validation': True,
        'max_concurrent_llm': 3
    }

    # Check if any API key is available
    has_key = any([
        config['llm']['openai_api_key'],
        config['llm']['deepseek_api_key'],
        config['llm']['anthropic_api_key']
    ])

    if not has_key:
        print("⚠️  No LLM API keys found. Set OPENAI_API_KEY, DEEPSEEK_API_KEY, or ANTHROPIC_API_KEY")
        print("   Scan will still work but AI analysis will be skipped.")
        print("   Or install Ollama for free local LLM: https://ollama.ai")
        print()

    try:
        engine = VulnHealerEngine(config)

        print("🔍 Running scan...")
        result = asyncio.run(engine.scan(temp_path))

        print("\n" + "=" * 50)
        print("✅ SCAN COMPLETE")
        print("=" * 50)

        print(f"\n📊 Statistics:")
        print(f"   Total findings: {result.statistics['total_findings']}")
        print(f"   Critical: {result.statistics['severity_distribution'].get('CRITICAL', 0)}")
        print(f"   High: {result.statistics['severity_distribution'].get('HIGH', 0)}")
        print(f"   Medium: {result.statistics['severity_distribution'].get('MEDIUM', 0)}")
        print(f"   Low: {result.statistics['severity_distribution'].get('LOW', 0)}")
        print(f"   Duration: {result.duration_seconds:.1f}s")

        if result.findings:
            print(f"\n🔍 Top Findings:")
            for i, f in enumerate(result.findings[:5], 1):
                print(f"   {i}. [{f.severity}] {f.rule_name} at {f.file_path}:{f.line_start}")
                if f.ai_patch:
                    print(f"      🩹 AI Patch: {'Available' if f.ai_patch else 'Not generated'}")
                if f.patch_validated:
                    print(f"      ✅ Patch validated")

        # Generate test report
        report_path = tempfile.mktemp(suffix='.html')
        engine.generate_report(result, 'html', report_path)
        print(f"\n📄 HTML report saved to: {report_path}")

        # Cleanup
        os.unlink(temp_path)

        print("\n🎉 Test completed successfully!")
        return True

    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == '__main__':
    success = test_basic_pipeline()
    sys.exit(0 if success else 1)
