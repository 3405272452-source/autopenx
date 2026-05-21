"""Temporary file lifecycle management for attack chain execution.

Tracks files/directories created during CTF operations and guarantees
cleanup via atexit hooks, context managers, and explicit cleanup calls.
Only preserved results (reports, flag records) survive cleanup.
"""
from __future__ import annotations

import atexit
import logging
import shutil
from contextlib import contextmanager
from pathlib import Path
from typing import Dict, List, Optional, Set, Union

log = logging.getLogger("autopnex.ctf.workspace_cleaner")

StrPath = Union[str, Path]


class WorkspaceCleaner:
    """Track and clean up temporary files/directories created during attack chain."""

    def __init__(self, base_dir: StrPath = "ctf_workspace", auto_clean: bool = True):
        self._base_dir = Path(base_dir).resolve()
        self._tracked_files: Set[Path] = set()
        self._tracked_dirs: Set[Path] = set()
        self._preserved: Set[Path] = set()
        self._auto_clean = auto_clean
        self._cleaned = False

        if auto_clean:
            atexit.register(self.cleanup)

    # ------------------------------------------------------------------
    # Tracking API
    # ------------------------------------------------------------------

    def track_file(self, path: StrPath) -> Path:
        """Register a temporary file for later cleanup."""
        p = Path(path).resolve()
        self._tracked_files.add(p)
        return p

    def track_dir(self, path: StrPath) -> Path:
        """Register a temporary directory for cleanup (including all children)."""
        p = Path(path).resolve()
        self._tracked_dirs.add(p)
        return p

    def preserve(self, path: StrPath) -> Path:
        """Mark a file/directory to be preserved during cleanup."""
        p = Path(path).resolve()
        self._preserved.add(p)
        return p

    def is_tracked(self, path: StrPath) -> bool:
        p = Path(path).resolve()
        return p in self._tracked_files or p in self._tracked_dirs

    # ------------------------------------------------------------------
    # Cleanup API
    # ------------------------------------------------------------------

    def cleanup(self, force: bool = False) -> dict:
        """Execute cleanup: delete all tracked temp files and directories.

        Returns dict with keys: files_deleted, dirs_deleted, errors, preserved, skipped.
        """
        if self._cleaned and not force:
            return {"already_cleaned": True, "files_deleted": 0, "dirs_deleted": 0, "errors": [], "preserved": []}

        stats: Dict[str, object] = {
            "files_deleted": 0,
            "dirs_deleted": 0,
            "errors": [],
            "preserved": [],
            "skipped": 0,
        }

        # Delete tracked files (respect preserved)
        for f in sorted(self._tracked_files):
            if any(f == p or str(f).startswith(str(p) + "\\") for p in self._preserved):
                stats["preserved"].append(str(f))
                continue
            try:
                if f.exists():
                    f.unlink()
                    stats["files_deleted"] = int(stats["files_deleted"]) + 1
            except OSError as e:
                stats["errors"].append(f"{f}: {e}")

        # Delete tracked directories (deepest first)
        sorted_dirs = sorted(self._tracked_dirs, key=lambda p: len(p.parts), reverse=True)
        for d in sorted_dirs:
            if any(d == p or str(d).startswith(str(p) + "\\") for p in self._preserved):
                stats["preserved"].append(str(d))
                continue
            try:
                if d.exists():
                    shutil.rmtree(d, ignore_errors=True)
                    stats["dirs_deleted"] = int(stats["dirs_deleted"]) + 1
            except OSError as e:
                stats["errors"].append(f"{d}: {e}")

        # Remove base_dir if empty
        try:
            if self._base_dir.exists() and not any(self._base_dir.iterdir()):
                self._base_dir.rmdir()
        except OSError:
            pass

        self._cleaned = True
        self._tracked_files.clear()
        self._tracked_dirs.clear()
        log.info("Cleanup: %d files, %d dirs removed, %d errors",
                 stats["files_deleted"], stats["dirs_deleted"], len(stats["errors"]))
        return stats

    def cleanup_on_success(self) -> dict:
        """Cleanup after successful task completion."""
        return self.cleanup()

    def cleanup_on_failure(self) -> dict:
        """Cleanup after failed task (same behavior, avoids disk pileup)."""
        return self.cleanup()

    # ------------------------------------------------------------------
    # Context Manager
    # ------------------------------------------------------------------

    @contextmanager
    def managed_workspace(self):
        """Context manager: auto-cleanup on exit (success or failure).

        Usage:
            with cleaner.managed_workspace() as ws:
                # ... attack chain work in ws ...
            # All tracked files auto-cleaned
        """
        self._base_dir.mkdir(parents=True, exist_ok=True)
        self.track_dir(self._base_dir)
        try:
            yield self._base_dir
        finally:
            self.cleanup()

    # ------------------------------------------------------------------
    # Convenience methods
    # ------------------------------------------------------------------

    def create_temp_file(self, name: str, content: bytes = b"") -> Path:
        """Create and track a temporary file under base_dir."""
        self._base_dir.mkdir(parents=True, exist_ok=True)
        p = self._base_dir / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(content)
        self.track_file(p)
        return p

    def create_temp_dir(self, name: str) -> Path:
        """Create and track a temporary subdirectory under base_dir."""
        self._base_dir.mkdir(parents=True, exist_ok=True)
        d = self._base_dir / name
        d.mkdir(parents=True, exist_ok=True)
        self.track_dir(d)
        return d

    def write_temp(self, name: str, content: bytes) -> Path:
        """Write content to a tracked temp file (alias for create_temp_file)."""
        return self.create_temp_file(name, content)

    @property
    def base_dir(self) -> Path:
        return self._base_dir

    @property
    def tracked_count(self) -> int:
        return len(self._tracked_files) + len(self._tracked_dirs)

    @property
    def preserved_count(self) -> int:
        return len(self._preserved)

    # ------------------------------------------------------------------
    # Bulk cleanup: scan for common redundant patterns
    # ------------------------------------------------------------------

    PATTERNS_TO_CLEAN = [
        "*.phar", "*.phar.gz", "phar_builder*.php",
        "payload_*.txt", "payload_*.bin", "payload_*.ser",
        "shell_*.php", "shell_*.phtml", "shell_*.gif",
        "exploit_tmp_*.py", "test_tmp_*.py",
        "*.pyc", "__pycache__",
    ]

    def scan_clean(self, root: Optional[StrPath] = None, dry_run: bool = False) -> dict:
        """Scan for and remove common redundant files from a directory.

        This is the 'one-click cleanup' entry point for removing leftover
        exploit artifacts, temp scripts, and intermediate files.
        """
        scan_root = Path(root) if root else self._base_dir
        if not scan_root.exists():
            return {"error": f"Path does not exist: {scan_root}", "removed": []}

        removed: List[str] = []
        failed: List[str] = []

        # 1. Pattern-based cleanup
        for pattern in self.PATTERNS_TO_CLEAN:
            for matched in scan_root.rglob(pattern):
                try:
                    if not dry_run:
                        if matched.is_dir():
                            shutil.rmtree(matched, ignore_errors=True)
                        else:
                            matched.unlink()
                    removed.append(str(matched))
                except OSError as e:
                    failed.append(f"{matched}: {e}")

        # 2. Empty directories
        for dirpath in sorted(scan_root.rglob("*"), key=lambda p: len(p.parts), reverse=True):
            if dirpath.is_dir():
                try:
                    if not any(dirpath.iterdir()):
                        if not dry_run:
                            dirpath.rmdir()
                        removed.append(str(dirpath))
                except OSError:
                    pass

        log.info("Scan-clean %s: %d removed, %d failed", "dry-run" if dry_run else "live", len(removed), len(failed))
        return {"root": str(scan_root), "dry_run": dry_run, "removed": removed, "failed": failed, "count": len(removed)}


# ---------------------------------------------------------------------------
# Global singleton for atexit safety
# ---------------------------------------------------------------------------

_global_cleaner: Optional[WorkspaceCleaner] = None


def get_global_cleaner(base_dir: StrPath = "ctf_workspace") -> WorkspaceCleaner:
    """Get or create a global WorkspaceCleaner singleton for module-level use."""
    global _global_cleaner
    if _global_cleaner is None:
        _global_cleaner = WorkspaceCleaner(base_dir=base_dir, auto_clean=True)
    return _global_cleaner


def one_click_cleanup(root: StrPath, dry_run: bool = False) -> dict:
    """Standalone one-click cleanup: scan and remove redundant scripts/artifacts.

    Callable from CLI or as a library entry point. Scans the given root
    directory for common temp files (phar, payload, shell, *.pyc, etc.)
    and removes them.

    Args:
        root: Directory to scan for redundant files.
        dry_run: If True, only report what would be removed.

    Returns:
        dict with 'removed' list, 'failed' list, and 'count'.
    """
    cleaner = WorkspaceCleaner(base_dir=root, auto_clean=False)
    return cleaner.scan_clean(root=root, dry_run=dry_run)


# ---------------------------------------------------------------------------
# Standalone CLI entry point
#   python -m autopnex.ctf.workspace_cleaner [--dry-run] [root_dir]
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    dry = "--dry-run" in sys.argv or "--dry" in sys.argv
    root_arg = next((a for a in sys.argv[1:] if not a.startswith("--")), "ctf_workspace")
    print(f"One-Click Cleanup: scanning {root_arg} {'(dry-run)' if dry else ''}")
    result = one_click_cleanup(root_arg, dry_run=dry)
    if result.get("error"):
        print(f"Error: {result['error']}")
        sys.exit(1)
    print(f"{'Would remove' if dry else 'Removed'} {result['count']} files/directories:")
    for item in result.get("removed", []):
        print(f"  {'[DRY]' if dry else '[DEL]'} {item}")
    for item in result.get("failed", []):
        print(f"  [FAIL] {item}")
