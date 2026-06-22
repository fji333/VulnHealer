"""
Incremental Scanner
Git-diff based scanner — only scans changed files to speed up CI/CD pipelines.
"""

import subprocess
from pathlib import Path
from typing import List, Dict, Any
import logging

logger = logging.getLogger(__name__)


class IncrementalScanner:
    """
    Git-aware incremental scanner.

    Only scans:
    - Modified files (vs base branch)
    - New files
    - Skips deleted/untracked files

    Typical CI usage: compare against main branch.
    """

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.base_ref = self.config.get("base_ref", "main")
        self.include_staged = self.config.get("include_staged", True)

    def get_changed_files(self, repo_path: str, base_ref: str = None) -> List[str]:
        """
        Return list of changed file paths relative to base_ref.

        Args:
            repo_path: Root of the git repository
            base_ref: Base branch/commit to compare against (default: self.base_ref)

        Returns:
            List of absolute file paths for changed files that still exist
        """
        base = base_ref or self.base_ref
        changed = []

        try:
            # Files changed vs base branch (added + modified only)
            r = subprocess.run(
                ["git", "diff", "--name-only", "--diff-filter=AM", base, "HEAD"],
                capture_output=True, text=True, cwd=repo_path
            )
            if r.returncode == 0:
                changed += r.stdout.strip().splitlines()

            # Also include staged changes not yet committed
            if self.include_staged:
                r2 = subprocess.run(
                    ["git", "diff", "--name-only", "--diff-filter=AM", "--cached"],
                    capture_output=True, text=True, cwd=repo_path
                )
                if r2.returncode == 0:
                    changed += r2.stdout.strip().splitlines()

        except FileNotFoundError:
            logger.warning("git not found, falling back to full scan")
            return []

        # Deduplicate and resolve to absolute paths that exist
        root = Path(repo_path)
        seen = set()
        result = []
        for f in changed:
            abs_path = (root / f).resolve()
            if abs_path not in seen and abs_path.exists():
                seen.add(abs_path)
                result.append(str(abs_path))

        return result

    def get_commit_diff_stats(self, repo_path: str, base_ref: str = None) -> Dict[str, Any]:
        """Return stats about what changed."""
        base = base_ref or self.base_ref
        try:
            r = subprocess.run(
                ["git", "diff", "--stat", base, "HEAD"],
                capture_output=True, text=True, cwd=repo_path
            )
            # Count changed files
            files_changed = [f for f in self.get_changed_files(repo_path, base)]
            return {
                "base_ref": base,
                "files_changed": len(files_changed),
                "changed_files": files_changed,
                "diff_stat": r.stdout.strip()
            }
        except Exception as e:
            return {"error": str(e), "files_changed": 0, "changed_files": []}

    def is_git_repo(self, path: str) -> bool:
        """Check if path is inside a git repository."""
        try:
            r = subprocess.run(
                ["git", "rev-parse", "--is-inside-work-tree"],
                capture_output=True, text=True, cwd=path
            )
            return r.returncode == 0
        except:
            return False
