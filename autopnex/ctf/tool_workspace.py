"""Controlled workspace for CTF agent-created tools and scripts."""
from __future__ import annotations

import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import requests


_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9_.-]+")
_PACKAGE_RE = re.compile(r"^[A-Za-z0-9_.-]+([<>=!~]=?[A-Za-z0-9_.+*-]+)?$")


class CTFToolWorkspace:
    """A bounded filesystem area for scripts, downloads, and Python packages."""

    def __init__(self, root: str | Path = "ctf_workspace", *, timeout: int = 120) -> None:
        self.root = Path(root).resolve()
        self.scripts_dir = self.root / "scripts"
        self.downloads_dir = self.root / "downloads"
        self.packages_dir = self.root / "python_packages"
        self.timeout = timeout
        for path in (self.root, self.scripts_dir, self.downloads_dir, self.packages_dir):
            path.mkdir(parents=True, exist_ok=True)

    def write_script(self, name: str, content: str, *, language: str = "python") -> Dict[str, Any]:
        suffix = _language_suffix(language)
        safe_name = _safe_filename(name, default=f"tool{suffix}")
        if not safe_name.endswith(suffix):
            safe_name += suffix
        path = self._ensure_inside(self.scripts_dir / safe_name)
        path.write_text(content or "", encoding="utf-8")
        return {"success": True, "path": str(path), "bytes": path.stat().st_size, "language": language}

    def run_script(
        self,
        path: str,
        *,
        args: Optional[list[str]] = None,
        language: str = "python",
        timeout: Optional[int] = None,
    ) -> Dict[str, Any]:
        script_path = self._ensure_inside(Path(path))
        if not script_path.exists():
            return {"success": False, "error": f"script_not_found:{script_path}"}
        command = _interpreter(language) + [str(script_path), *(args or [])]
        env = os.environ.copy()
        env["PYTHONPATH"] = str(self.packages_dir) + os.pathsep + env.get("PYTHONPATH", "")
        start = time.perf_counter()
        try:
            proc = subprocess.run(
                command,
                cwd=str(self.root),
                env=env,
                text=True,
                capture_output=True,
                timeout=min(int(timeout or self.timeout), 300),
                check=False,
            )
        except Exception as exc:  # noqa: BLE001
            return {"success": False, "error": f"{exc.__class__.__name__}: {exc}"}
        return {
            "success": proc.returncode == 0,
            "exit_code": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "duration_ms": int((time.perf_counter() - start) * 1000),
        }

    def install_python_package(self, package: str, *, timeout: int = 180) -> Dict[str, Any]:
        package = (package or "").strip()
        if not _PACKAGE_RE.match(package):
            return {"success": False, "error": "invalid_package_name"}
        command = [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--target",
            str(self.packages_dir),
            package,
        ]
        start = time.perf_counter()
        try:
            proc = subprocess.run(
                command,
                cwd=str(self.root),
                text=True,
                capture_output=True,
                timeout=min(timeout, 300),
                check=False,
            )
        except Exception as exc:  # noqa: BLE001
            return {"success": False, "error": f"{exc.__class__.__name__}: {exc}"}
        return {
            "success": proc.returncode == 0,
            "package": package,
            "target": str(self.packages_dir),
            "stdout": proc.stdout[-4000:],
            "stderr": proc.stderr[-4000:],
            "exit_code": proc.returncode,
            "duration_ms": int((time.perf_counter() - start) * 1000),
        }

    def download_url(self, url: str, *, filename: str = "", timeout: int = 60) -> Dict[str, Any]:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            return {"success": False, "error": "unsupported_url_scheme"}
        safe_name = _safe_filename(filename or Path(parsed.path).name or "download.bin", default="download.bin")
        dest = self._ensure_inside(self.downloads_dir / safe_name)
        try:
            with requests.get(url, timeout=min(timeout, 120), stream=True) as resp:
                resp.raise_for_status()
                total = 0
                with dest.open("wb") as fh:
                    for chunk in resp.iter_content(chunk_size=64 * 1024):
                        if not chunk:
                            continue
                        total += len(chunk)
                        if total > 50 * 1024 * 1024:
                            return {"success": False, "error": "download_too_large"}
                        fh.write(chunk)
        except Exception as exc:  # noqa: BLE001
            return {"success": False, "error": f"{exc.__class__.__name__}: {exc}"}
        return {"success": True, "path": str(dest), "bytes": dest.stat().st_size, "url": url}

    def _ensure_inside(self, path: Path) -> Path:
        resolved = path.resolve()
        if self.root != resolved and self.root not in resolved.parents:
            raise ValueError(f"path_outside_ctf_workspace:{resolved}")
        return resolved


def _safe_filename(name: str, *, default: str) -> str:
    cleaned = _SAFE_NAME_RE.sub("_", Path(name or default).name).strip("._")
    return cleaned or default


def _language_suffix(language: str) -> str:
    return {
        "python": ".py",
        "python3": ".py",
        "bash": ".sh",
        "sh": ".sh",
        "node": ".js",
        "nodejs": ".js",
    }.get(language.lower(), ".txt")


def _interpreter(language: str) -> list[str]:
    lang = language.lower()
    if lang in {"python", "python3"}:
        return [sys.executable]
    if lang in {"node", "nodejs"}:
        return ["node"]
    if lang in {"bash", "sh"}:
        return [lang]
    raise ValueError(f"unsupported_language:{language}")
