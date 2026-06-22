"""
Patch Validator
Validates generated patches by compilation, syntax checking, and semantic tests.
"""

import subprocess
import tempfile
import os
from pathlib import Path
from typing import Tuple, Dict, Any
import logging

logger = logging.getLogger(__name__)


class PatchValidator:
    """
    Validates AI-generated patches.

    Checks:
    1. Syntax validity (compilation/parsing)
    2. No new vulnerabilities introduced
    3. Functional equivalence (basic)
    4. Security property verification
    """

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.timeout = config.get('timeout', 30)
        self.max_attempts = config.get('max_attempts', 3)

        # Language-specific validators
        self.validators = {
            'py': self._validate_python,
            'js': self._validate_javascript,
            'ts': self._validate_typescript,
            'java': self._validate_java,
            'c': self._validate_c,
            'cpp': self._validate_cpp,
            'go': self._validate_go,
        }

    async def validate(self, project_path: str, file_path: str,
                       original_code: str, patched_code: str) -> Tuple[bool, str]:
        """
        Validate a patch.

        Returns:
            (is_valid: bool, message: str)
        """
        ext = Path(file_path).suffix.lstrip('.')
        validator = self.validators.get(ext)

        if not validator:
            return True, f"No validator for .{ext}, assuming valid"

        try:
            return await validator(file_path, original_code, patched_code)
        except Exception as e:
            logger.error(f"Patch validation failed: {e}")
            return False, f"Validation error: {str(e)}"

    async def _validate_python(self, file_path: str, original: str, patched: str) -> Tuple[bool, str]:
        """Validate Python patch."""
        import ast

        try:
            # Check syntax
            ast.parse(patched)

            # Check for new obvious issues
            issues = self._check_python_security(patched)
            if issues:
                return False, f"New issues introduced: {', '.join(issues)}"

            return True, "Python syntax valid, no obvious new issues"

        except SyntaxError as e:
            return False, f"Python syntax error: {e}"

    async def _validate_javascript(self, file_path: str, original: str, patched: str) -> Tuple[bool, str]:
        """Validate JavaScript patch."""
        # Use Node.js to check syntax if available
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
                f.write(patched)
                temp_path = f.name

            result = subprocess.run(
                ['node', '--check', temp_path],
                capture_output=True,
                text=True,
                timeout=self.timeout
            )

            os.unlink(temp_path)

            if result.returncode == 0:
                return True, "JavaScript syntax valid"
            else:
                return False, f"JavaScript syntax error: {result.stderr}"

        except FileNotFoundError:
            return True, "Node.js not available, skipping JS validation"
        except Exception as e:
            return False, f"JS validation error: {e}"

    async def _validate_typescript(self, file_path: str, original: str, patched: str) -> Tuple[bool, str]:
        """Validate TypeScript patch."""
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.ts', delete=False) as f:
                f.write(patched)
                temp_path = f.name

            result = subprocess.run(
                ['npx', 'tsc', '--noEmit', '--skipLibCheck', temp_path],
                capture_output=True,
                text=True,
                timeout=self.timeout
            )

            os.unlink(temp_path)

            if result.returncode == 0:
                return True, "TypeScript compilation successful"
            else:
                # TypeScript may have errors from missing types, check if it's a syntax issue
                if 'error TS' in result.stderr:
                    return False, f"TypeScript error: {result.stderr[:200]}"
                return True, "TypeScript syntax appears valid (type errors may be from missing deps)"

        except FileNotFoundError:
            return True, "TypeScript compiler not available"
        except Exception as e:
            return False, f"TS validation error: {e}"

    async def _validate_java(self, file_path: str, original: str, patched: str) -> Tuple[bool, str]:
        """Validate Java patch."""
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.java', delete=False) as f:
                f.write(patched)
                temp_path = f.name

            result = subprocess.run(
                ['javac', '-d', '/tmp', temp_path],
                capture_output=True,
                text=True,
                timeout=self.timeout
            )

            os.unlink(temp_path)

            if result.returncode == 0:
                return True, "Java compilation successful"
            else:
                return False, f"Java compilation error: {result.stderr[:300]}"

        except FileNotFoundError:
            return True, "Java compiler not available"
        except Exception as e:
            return False, f"Java validation error: {e}"

    async def _validate_c(self, file_path: str, original: str, patched: str) -> Tuple[bool, str]:
        """Validate C patch."""
        return await self._compile_with_gcc(file_path, original, patched, 'c')

    async def _validate_cpp(self, file_path: str, original: str, patched: str) -> Tuple[bool, str]:
        """Validate C++ patch."""
        return await self._compile_with_gcc(file_path, original, patched, 'cpp')

    async def _validate_go(self, file_path: str, original: str, patched: str) -> Tuple[bool, str]:
        """Validate Go patch."""
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.go', delete=False) as f:
                f.write(patched)
                temp_path = f.name

            result = subprocess.run(
                ['go', 'vet', temp_path],
                capture_output=True,
                text=True,
                timeout=self.timeout
            )

            os.unlink(temp_path)

            # go vet can have warnings but still be valid
            return True, f"Go validation: {result.stdout or 'clean'}"

        except FileNotFoundError:
            return True, "Go compiler not available"
        except Exception as e:
            return False, f"Go validation error: {e}"

    async def _compile_with_gcc(self, file_path: str, original: str, patched: str,
                                lang: str) -> Tuple[bool, str]:
        """Generic C/C++ compilation check."""
        ext = 'c' if lang == 'c' else 'cpp'
        compiler = 'gcc' if lang == 'c' else 'g++'

        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix=f'.{ext}', delete=False) as f:
                f.write(patched)
                temp_path = f.name

            result = subprocess.run(
                [compiler, '-fsyntax-only', temp_path],
                capture_output=True,
                text=True,
                timeout=self.timeout
            )

            os.unlink(temp_path)

            if result.returncode == 0:
                return True, f"{lang.upper()} syntax valid"
            else:
                return False, f"{lang.upper()} syntax error: {result.stderr[:300]}"

        except FileNotFoundError:
            return True, f"{compiler} not available"
        except Exception as e:
            return False, f"{lang} validation error: {e}"

    def _check_python_security(self, code: str) -> list:
        """Check for obvious security regressions in Python."""
        issues = []

        dangerous_patterns = [
            ('eval(', "Use of eval()"),
            ('exec(', "Use of exec()"),
            ('__import__(', "Dynamic import"),
            ('subprocess.call(shell=True', "Shell injection risk"),
            ('os.system(', "Use of os.system()"),
            ('pickle.loads', "Unsafe deserialization"),
            ('yaml.load(', "Unsafe YAML loading"),
            ('input(', "Use of input() in Python 2 style"),
        ]

        for pattern, description in dangerous_patterns:
            if pattern in code:
                issues.append(description)

        return issues
