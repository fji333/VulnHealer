"""
Code Context Extractor
Extracts surrounding code context for vulnerability findings.
Uses tree-sitter for language-aware context extraction.
"""

from pathlib import Path
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)


class CodeContextExtractor:
    """
    Extracts code context around vulnerability locations.

    Features:
    - Line-based context (before/after)
    - Function-level context
    - Class-level context
    - Import context (for Python)
    """

    def __init__(self, context_lines: int = 5, context_lines_after: int = 5):
        self.context_lines = context_lines
        self.context_lines_after = context_lines_after

    def extract(self, file_path: str, line_start: int, line_end: int) -> Dict[str, str]:
        """
        Extract context around vulnerability location.

        Args:
            file_path: Path to source file
            line_start: Start line (1-indexed)
            line_end: End line (1-indexed)

        Returns:
            Dict with 'before', 'after', 'function', 'imports' keys
        """
        path = Path(file_path)
        if not path.exists():
            return {'before': '', 'after': '', 'function': '', 'imports': ''}

        try:
            with open(path, 'r', encoding='utf-8', errors='replace') as f:
                lines = f.readlines()
        except Exception as e:
            logger.warning(f"Failed to read {file_path}: {e}")
            return {'before': '', 'after': '', 'function': '', 'imports': ''}

        # Convert to 0-indexed
        start_idx = max(0, line_start - 1)
        end_idx = min(len(lines), line_end)

        # Line-based context
        before_start = max(0, start_idx - self.context_lines)
        after_end = min(len(lines), end_idx + self.context_lines_after)

        before = ''.join(lines[before_start:start_idx])
        after = ''.join(lines[end_idx:after_end])

        # Function-level context (best effort)
        function_context = self._extract_function_context(lines, start_idx)

        # Import context for Python
        imports = self._extract_imports(lines) if path.suffix == '.py' else ''

        return {
            'before': before,
            'after': after,
            'function': function_context,
            'imports': imports
        }

    def _extract_function_context(self, lines: list, target_line: int) -> str:
        """Extract the containing function/method (best effort)."""
        # Find function start (look for 'def ' or 'class ' going backwards)
        func_start = -1
        indent_level = None

        for i in range(target_line, -1, -1):
            line = lines[i]
            stripped = line.lstrip()

            if stripped.startswith('def ') or stripped.startswith('class '):
                func_start = i
                indent_level = len(line) - len(stripped)
                break

        if func_start == -1:
            return ''

        # Find function end (next line at same or lower indent, or end of file)
        func_end = len(lines)
        for i in range(target_line + 1, len(lines)):
            line = lines[i]
            if line.strip() and not line.strip().startswith('#'):
                current_indent = len(line) - len(line.lstrip())
                if current_indent <= indent_level and i > func_start + 1:
                    func_end = i
                    break

        return ''.join(lines[func_start:func_end])

    def _extract_imports(self, lines: list) -> str:
        """Extract import statements from Python file."""
        imports = []
        for line in lines:
            stripped = line.strip()
            if stripped.startswith(('import ', 'from ')) and not stripped.startswith('#'):
                imports.append(line)
            # Stop at first non-import, non-comment, non-empty line
            elif stripped and not stripped.startswith('#') and not stripped.startswith('"""') and not stripped.startswith("'''"):
                if imports:  # Only break if we've found some imports
                    break
        return ''.join(imports)

    def extract_call_graph(self, file_path: str, function_name: str) -> Dict[str, Any]:
        """Extract simple call graph information (future enhancement)."""
        # Placeholder for future tree-sitter based analysis
        return {'callers': [], 'callees': [], 'taint_sources': []}
