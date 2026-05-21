"""Source code leak detection and automatic download for CTF challenges.

Covers backup files, Git/SVN/Docker leaks, composer/package configs,
and framework fingerprinting to guide further exploitation steps.
"""
from __future__ import annotations

import io
import logging
import re
import gzip
import zlib
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set, Tuple

if TYPE_CHECKING:
    from .workspace_cleaner import WorkspaceCleaner
from urllib.parse import urljoin, urlsplit

import requests

log = logging.getLogger("autopnex.ctf.source_leak_scanner")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BACKUP_PATHS: List[str] = [
    "/www.zip", "/www.tar.gz", "/www.rar", "/web.zip", "/src.zip", "/source.zip",
    "/backup.zip", "/backup.tar.gz", "/site.zip", "/html.zip", "/app.zip",
    "/code.zip", "/dist.zip", "/website.zip", "/public.zip", "/db.sql",
    "/backup.sql", "/dump.sql", "/database.sql",
]

GIT_LEAK_PATHS: List[str] = [
    "/.git/HEAD", "/.git/config", "/.git/index", "/.git/description",
    "/.git/refs/heads/master", "/.git/refs/heads/main",
    "/.git/logs/HEAD", "/.git/COMMIT_EDITMSG",
]

GIT_OBJECT_PATHS: List[str] = [
    "/.git/objects/info/packs",
    "/.git/packed-refs",
]

SVN_LEAK_PATHS: List[str] = [
    "/.svn/entries", "/.svn/wc.db", "/.svn/format",
]

OTHER_LEAK_PATHS: List[str] = [
    "/.DS_Store", "/composer.json", "/package.json", "/.env",
    "/WEB-INF/web.xml", "/.gitignore",
    "/Dockerfile", "/docker-compose.yml", "/.dockerignore",
    "/robots.txt", "/sitemap.xml",
    "/phpinfo.php", "/info.php", "/test.php", "/debug.php",
]

# Framework fingerprints: (file_path, signature_regex)
FRAMEWORK_FINGERPRINTS: List[Tuple[str, str, str]] = [
    ("Laravel", "artisan", r"laravel/framework"),
    ("Laravel", "composer.json", r"laravel/framework"),
    ("Laravel", "app/Http/Kernel.php", r"class\s+Kernel"),
    ("ThinkPHP", "think", r""),
    ("ThinkPHP", "thinkphp/", r""),
    ("ThinkPHP", "application/index/controller", r""),
    ("Yii", "yii", r""),
    ("Yii", "config/web.php", r"yiisoft/yii2"),
    ("Yii", "composer.json", r"yiisoft/yii2"),
    ("Laminas", "laminas/", r""),
    ("Laminas", "module/", r""),
    ("Laminas", "config/autoload/", r""),
    ("Laminas", "composer.json", r"laminas/"),
    ("Symfony", "symfony/", r""),
    ("Symfony", "bin/console", r""),
    ("Symfony", "composer.json", r"symfony/"),
    ("CodeIgniter", "system/core/", r""),
    ("CodeIgniter", "application/controllers/", r""),
    ("CakePHP", "src/Controller/", r""),
    ("CakePHP", "config/app.php", r""),
    ("WordPress", "wp-content/", r""),
    ("WordPress", "wp-config.php", r""),
    ("Slim", "composer.json", r"slim/slim"),
    ("Phalcon", "composer.json", r"phalcon/devtools"),
]

PHP_EXTRA_EXTENSIONS: Set[str] = {
    ".php", ".php5", ".php7", ".phtml", ".pht", ".phps", ".php3", ".php4",
    ".inc", ".shtml", ".module",
}

GIT_OBJECT_TYPE_MAP: Dict[int, str] = {
    1: "commit", 2: "tree", 3: "blob", 4: "tag",
}

HTTP_TIMEOUT = 12


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class LeakResult:
    leak_type: str
    url: str
    local_path: str = ""
    files: List[str] = field(default_factory=list)
    framework: str = ""
    framework_confidence: float = 0.0
    analysis: str = ""
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "leak_type": self.leak_type,
            "url": self.url,
            "local_path": self.local_path,
            "file_count": len(self.files),
            "files": self.files[:50],
            "framework": self.framework,
            "framework_confidence": self.framework_confidence,
            "analysis": self.analysis,
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# SourceLeakScanner
# ---------------------------------------------------------------------------

class SourceLeakScanner:
    """Scan target URL for source code leaks and identify framework."""

    def __init__(self, session: requests.Session, work_dir: str = "", cleaner: "Optional[WorkspaceCleaner]" = None):
        self._session = session
        self._work_dir = Path(work_dir) if work_dir else Path("ctf_workspace")
        self._work_dir.mkdir(parents=True, exist_ok=True)
        self._cleaner = cleaner

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan_all(self, target_url: str) -> List[LeakResult]:
        """Run all leak probes against a target URL. Returns list of LeakResults."""
        results: List[LeakResult] = []

        results.extend(self.probe_backup_files(target_url))
        results.extend(self.probe_git_leak(target_url))
        results.extend(self.probe_svn_leak(target_url))
        results.extend(self.probe_other_leaks(target_url))

        framework = self.detect_framework(target_url)
        if framework:
            for r in results:
                if not r.framework:
                    r.framework = framework
                    r.framework_confidence = 0.8

        return results or [self._empty_result(target_url)]

    def probe_backup_files(self, target_url: str) -> List[LeakResult]:
        """Probe common backup archive paths. Download and save if found."""
        base = target_url.rstrip("/")
        results: List[LeakResult] = []
        for path in BACKUP_PATHS:
            url = base + path
            try:
                r = self._session.get(url, timeout=HTTP_TIMEOUT, allow_redirects=True)
                if r.status_code == 200 and len(r.content) > 1024:
                    result = self._save_leak(base, path, r.content, "backup")
                    results.append(result)
            except requests.RequestException:
                continue
        return results

    def probe_git_leak(self, target_url: str) -> List[LeakResult]:
        """Detect and attempt to recover .git directory leak."""
        base = target_url.rstrip("/")
        results: List[LeakResult] = []

        # Step 1: Check if /.git/HEAD exists
        head_url = base + "/.git/HEAD"
        try:
            r = self._session.get(head_url, timeout=HTTP_TIMEOUT, allow_redirects=True)
        except requests.RequestException:
            return results

        is_git_leak = (r.status_code == 200 and hasattr(r.content, '__contains__') and b"ref:" in r.content) or (
            hasattr(r.content, '__getitem__') and b"ref:" in r.content[:200] if r.content else False
        )

        if not is_git_leak:
            return results

        leak_dir = self._work_dir / "leaks" / urlsplit(base).netloc / "git_leak"
        leak_dir.mkdir(parents=True, exist_ok=True)
        if self._cleaner:
            self._cleaner.track_dir(leak_dir)

        files_grabbed: List[str] = []

        # Step 2: Download key git files
        git_files = GIT_LEAK_PATHS + GIT_OBJECT_PATHS
        for git_path in git_files:
            try:
                r = self._session.get(base + git_path, timeout=HTTP_TIMEOUT, allow_redirects=True)
                if r.status_code == 200 and r.content:
                    rel = git_path.replace("/.git/", "")
                    dest = leak_dir / rel.replace("/", "_")
                    dest.write_bytes(r.content)
                    files_grabbed.append(git_path)
            except requests.RequestException:
                continue

        # Step 3: Try to enumerate git objects from index
        try:
            index_url = base + "/.git/index"
            r = self._session.get(index_url, timeout=HTTP_TIMEOUT)
            if r.status_code == 200 and len(r.content) > 12:
                objects = _parse_git_index(r.content)
                for sha1, _path in objects:
                    obj_url = base + f"/.git/objects/{sha1[:2]}/{sha1[2:]}"
                    try:
                        orr = self._session.get(obj_url, timeout=HTTP_TIMEOUT)
                        if orr.status_code == 200:
                            obj_dir = leak_dir / "objects" / sha1[:2]
                            obj_dir.mkdir(parents=True, exist_ok=True)
                            (obj_dir / sha1[2:]).write_bytes(orr.content)
                            files_grabbed.append(f"/.git/objects/{sha1[:2]}/{sha1[2:]}")
                    except requests.RequestException:
                        continue
        except Exception:
            pass

        # Step 4: Try pack files
        try:
            pack_url = base + "/.git/objects/info/packs"
            r = self._session.get(pack_url, timeout=HTTP_TIMEOUT)
            if r.status_code == 200:
                for p_line in r.text.splitlines():
                    if p_line.startswith("P pack-"):
                        pack_name = p_line.split(" ")[1].strip()
                        idx_url = base + f"/.git/objects/pack/{pack_name}.idx"
                        pack_data_url = base + f"/.git/objects/pack/{pack_name}.pack"
                        for purl in [idx_url, pack_data_url]:
                            try:
                                pr = self._session.get(purl, timeout=HTTP_TIMEOUT)
                                if pr.status_code == 200:
                                    dest_file = leak_dir / purl.rsplit("/", 1)[1]
                                    dest_file.write_bytes(pr.content)
                                    files_grabbed.append(purl.replace(base, ""))
                            except requests.RequestException:
                                continue
        except Exception:
            pass

        result = LeakResult(
            leak_type="git_leak",
            url=base,
            local_path=str(leak_dir),
            files=files_grabbed,
            analysis=f"Git leak found: {len(files_grabbed)} files recovered. Use 'git checkout .' in {leak_dir} to restore working tree.",
        )
        results.append(result)

        # Step 5: Check for common source files
        source_paths = [
            "/index.php", "/index.html", "/composer.json", "/app.php", "/config.php",
            "/router.php", "/bootstrap.php", "/server.php",
            "/src/index.php", "/public/index.php", "/web/index.php",
        ]
        for src_path in source_paths:
            try:
                r = self._session.get(base + src_path, timeout=HTTP_TIMEOUT, allow_redirects=True)
                if r.status_code == 200 and r.content:
                    dest = leak_dir / src_path.strip("/").replace("/", "_")
                    dest.write_bytes(r.content)
                    files_grabbed.append(src_path)
            except requests.RequestException:
                continue

        result.analysis = f"Git leak: {len(files_grabbed)} files saved to {leak_dir}"

        # Step 6: Attempt git source recovery (Phase 9)
        recovered = recover_git_source(leak_dir)
        if recovered:
            files_grabbed.extend(recovered)
            result.files = files_grabbed
            result.analysis += f"; {len(recovered)} source files recovered"

        return results

    def probe_svn_leak(self, target_url: str) -> List[LeakResult]:
        """Detect Subversion (.svn) repository leak."""
        base = target_url.rstrip("/")
        results: List[LeakResult] = []

        for svn_path in SVN_LEAK_PATHS:
            url = base + svn_path
            try:
                r = self._session.get(url, timeout=HTTP_TIMEOUT, allow_redirects=True)
                if r.status_code == 200 and len(r.content) > 10:
                    leak_dir = self._work_dir / "leaks" / urlsplit(base).netloc / "svn_leak"
                    leak_dir.mkdir(parents=True, exist_ok=True)
                    if self._cleaner:
                        self._cleaner.track_dir(leak_dir)
                    dest = leak_dir / svn_path.strip("/").replace("/", "_")
                    dest.write_bytes(r.content)

                    result = LeakResult(
                        leak_type="svn_leak",
                        url=url,
                        local_path=str(leak_dir),
                        files=[svn_path],
                        analysis=f"SVN leak detected: {svn_path} accessible",
                    )
                    results.append(result)
            except requests.RequestException:
                continue

        if results and (self._work_dir / "leaks" / urlsplit(base).netloc / "svn_leak" / ".svn_entries").exists():
            try:
                entries_path = self._work_dir / "leaks" / urlsplit(base).netloc / "svn_leak" / ".svn_entries"
                content = entries_path.read_text(errors="replace")
                file_matches = re.findall(r'name="([^"]+)"', content)
                for fname in file_matches[:20]:
                    try:
                        fr = self._session.get(base + f"/{fname}", timeout=HTTP_TIMEOUT)
                        if fr.status_code == 200:
                            (self._work_dir / "leaks" / urlsplit(base).netloc / "svn_leak" / fname).write_bytes(fr.content)
                    except requests.RequestException:
                        continue
            except Exception:
                pass

        return results

    def probe_other_leaks(self, target_url: str) -> List[LeakResult]:
        """Probe config, debug, and other info-leak paths."""
        base = target_url.rstrip("/")
        results: List[LeakResult] = []
        for path in OTHER_LEAK_PATHS:
            url = base + path
            try:
                r = self._session.get(url, timeout=HTTP_TIMEOUT, allow_redirects=True)
                if r.status_code == 200 and len(r.content) > 10:
                    results.append(LeakResult(
                        leak_type="config_leak",
                        url=url,
                        files=[path],
                        analysis=f"Config file accessible: {path}",
                    ))
            except requests.RequestException:
                continue

        # Probe PHP extra extensions
        for base_index in ["/index", "/admin", "/flag", "/config", "/test", "/login", "/api/index"]:
            for ext in PHP_EXTRA_EXTENSIONS:
                url = base + base_index + ext
                try:
                    r = self._session.get(url, timeout=HTTP_TIMEOUT, allow_redirects=True)
                    if r.status_code == 200 and len(r.content) > 50 and b"<?php" not in r.content:
                        results.append(LeakResult(
                            leak_type="php_endpoint",
                            url=url,
                            files=[base_index + ext],
                            analysis=f"PHP endpoint with non-standard extension: {ext}",
                        ))
                except requests.RequestException:
                    continue

        return results

    def detect_framework(self, target_url: str) -> str:
        """Identify PHP framework by probing known paths and analyzing responses."""
        base = target_url.rstrip("/")
        scores: Dict[str, int] = {}

        for fw_name, fw_path, fw_regex in FRAMEWORK_FINGERPRINTS:
            url = base + "/" + fw_path.lstrip("/")
            try:
                r = self._session.get(url, timeout=HTTP_TIMEOUT, allow_redirects=True)
                if r.status_code == 200 and r.content:
                    if fw_regex:
                        if re.search(fw_regex.encode(), r.content) or re.search(fw_regex, r.text):
                            scores[fw_name] = scores.get(fw_name, 0) + 1
                    else:
                        scores[fw_name] = scores.get(fw_name, 0) + 0.5
            except requests.RequestException:
                continue

        if scores:
            return max(scores, key=lambda k: scores[k])

        # Secondary: check HTML meta/comments
        try:
            r = self._session.get(base + "/", timeout=HTTP_TIMEOUT)
            body = r.text.lower() if r.status_code == 200 else ""
            if "wp-content" in body:
                return "WordPress"
            if "thinkphp" in body:
                return "ThinkPHP"
            if "laravel" in body:
                return "Laravel"
        except requests.RequestException:
            pass

        return "Raw PHP"

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _save_leak(self, base_url: str, path: str, data: bytes, prefix: str) -> LeakResult:
        leak_dir = self._work_dir / "leaks" / urlsplit(base_url).netloc / prefix
        leak_dir.mkdir(parents=True, exist_ok=True)
        fname = path.strip("/").replace("/", "_") or "archive"
        dest = leak_dir / fname
        dest.write_bytes(data)

        # Track for cleanup
        if self._cleaner:
            self._cleaner.track_file(dest)
            self._cleaner.track_dir(leak_dir)

        archive_files = _list_archive_files(data, dest.suffix.lstrip("."))
        return LeakResult(
            leak_type=f"{prefix}_leak",
            url=base_url + path,
            local_path=str(dest),
            files=archive_files,
            analysis=f"Archive {path}: {len(archive_files)} files extracted to {leak_dir}",
        )

    def _empty_result(self, url: str) -> LeakResult:
        return LeakResult(leak_type="none", url=url)


# ---------------------------------------------------------------------------
# Git index parsing
# ---------------------------------------------------------------------------

def _parse_git_index(data: bytes) -> List[Tuple[str, str]]:
    """Parse git index file to extract object SHA1 hashes and file paths."""
    results: List[Tuple[str, str]] = []
    try:
        if len(data) < 12:
            return results
        sig = data[:4]
        if sig != b"DIRC":
            return results
        version = struct.unpack(">I", data[4:8])[0]
        entry_count = struct.unpack(">I", data[8:12])[0]
        offset = 12
        for _ in range(min(entry_count, 200)):
            if offset + 62 > len(data):
                break
            ctime_s = struct.unpack(">I", data[offset:offset + 4])[0]
            ctime_ns = struct.unpack(">I", data[offset + 4:offset + 8])[0]
            mtime_s = struct.unpack(">I", data[offset + 8:offset + 12])[0]
            mtime_ns = struct.unpack(">I", data[offset + 12:offset + 16])[0]
            dev = struct.unpack(">I", data[offset + 16:offset + 20])[0]
            ino = struct.unpack(">I", data[offset + 20:offset + 24])[0]
            mode = struct.unpack(">I", data[offset + 24:offset + 28])[0]
            uid = struct.unpack(">I", data[offset + 28:offset + 32])[0]
            gid = struct.unpack(">I", data[offset + 32:offset + 36])[0]
            size = struct.unpack(">I", data[offset + 36:offset + 40])[0]
            sha1_hex = data[offset + 40:offset + 60].hex()
            flags = struct.unpack(">H", data[offset + 60:offset + 62])[0]
            offset += 62
            if version >= 3:
                offset += 2
            # Read path
            null_pos = data.find(b"\x00", offset)
            if null_pos == -1:
                break
            path = data[offset:null_pos].decode("utf-8", errors="replace")
            results.append((sha1_hex, path))
            offset = null_pos + 1
            # Padding to 8-byte boundary
            while offset < len(data) and data[offset] == 0 and offset % 8 != 0:
                offset += 1
    except Exception:
        pass
    return results


# ---------------------------------------------------------------------------
# Archive file listing
# ---------------------------------------------------------------------------

def _list_archive_files(data: bytes, suffix: str) -> List[str]:
    """List files inside a zip/tar.gz/rar archive."""
    files: List[str] = []
    try:
        if suffix in ("zip", "rar"):
            import zipfile
            if zipfile.is_zipfile(io.BytesIO(data)):
                with zipfile.ZipFile(io.BytesIO(data)) as zf:
                    for info in zf.infolist():
                        if not info.is_dir():
                            files.append(info.filename)
        elif "tar" in suffix:
            import tarfile
            with tarfile.open(fileobj=io.BytesIO(data)) as tf:
                for member in tf.getmembers():
                    if member.isfile():
                        files.append(member.name)
    except Exception:
        pass
    return files


# ---------------------------------------------------------------------------
# Git object parsing
# ---------------------------------------------------------------------------

def parse_git_blob(raw: bytes) -> Optional[bytes]:
    """Extract file content from a raw git blob object. Returns decoded content or None."""
    try:
        data = zlib.decompress(raw)
        null_idx = data.find(b"\x00")
        if null_idx == -1:
            data = zlib.decompress(raw, -15)
            null_idx = data.find(b"\x00")
        if null_idx == -1:
            return data
        type_str = data[:null_idx].decode("ascii", errors="replace")
        if "blob" in type_str:
            return data[null_idx + 1:]
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Git source recovery — Phase 9
# ---------------------------------------------------------------------------

def recover_git_source(leak_dir: Path) -> List[str]:
    """Attempt to recover PHP source files from a downloaded .git directory.

    Strategy A: Use local git (if available in PATH) to checkout.
    Strategy B: Pure Python — parse HEAD, resolve ref, walk tree, extract blobs.

    Returns list of recovered file paths.
    """
    recovered: List[str] = []

    # Strategy A: git checkout
    try:
        import subprocess
        result = subprocess.run(
            ["git", "checkout", "--", "."],
            cwd=str(leak_dir),
            capture_output=True,
            timeout=30,
        )
        if result.returncode == 0:
            for f in leak_dir.rglob("*.php"):
                recovered.append(str(f))
            for f in leak_dir.rglob("*.inc"):
                recovered.append(str(f))
            if recovered:
                log.info("Git checkout recovered %d PHP files", len(recovered))
                return recovered
    except Exception:
        pass

    # Strategy B: Pure Python git recovery
    try:
        recovered = _pure_python_git_recover(leak_dir)
        if recovered:
            log.info("Pure Python git recovery: %d files", len(recovered))
    except Exception as e:
        log.debug("Pure Python git recovery failed: %s", e)

    return recovered


def _pure_python_git_recover(leak_dir: Path) -> List[str]:
    """Pure Python git repository recovery: HEAD -> ref -> commit -> tree -> blobs."""
    recovered: List[str] = []

    # 1. Read HEAD to get current ref
    head_path = leak_dir / "HEAD"
    if not head_path.exists():
        head_path = leak_dir / "HEAD_refs_heads_master"
    if not head_path.exists():
        for candidate in ["HEAD_refs_heads_main", "HEAD"]:
            for f in leak_dir.iterdir():
                if f.is_file() and candidate in f.name:
                    head_path = f
                    break

    if not head_path.exists():
        return recovered

    head_content = head_path.read_bytes().strip()
    ref = head_content.decode("ascii", errors="replace")

    # 2. Resolve ref to commit SHA
    if ref.startswith("ref: "):
        ref_path_part = ref[5:].strip()  # e.g. "refs/heads/master"
        ref_file = leak_dir / ref_path_part.replace("/", "_")
        if ref_file.exists():
            sha = ref_file.read_bytes().strip().decode("ascii", errors="replace")[:40]
        else:
            return recovered
    else:
        sha = ref[:40]

    # Also check packed-refs
    if not sha:
        packed = leak_dir / "refs_heads_master"
        if not packed.exists():
            packed = leak_dir / "packed-refs"
        if not packed.exists():
            for f in leak_dir.iterdir():
                if f.is_file() and "packed" in f.name.lower():
                    packed = f
                    break
        if packed.exists():
            for line in packed.read_bytes().split(b"\n"):
                if b"refs/heads" in line:
                    sha = line[:40].decode("ascii", errors="replace").strip()
                    break

    if not sha or len(sha) < 40:
        return recovered

    # 3. Read commit object to get tree SHA
    commit_data = _read_git_object_file(leak_dir, sha)
    if not commit_data:
        return recovered

    commit_text = commit_data.decode("ascii", errors="replace")
    tree_sha: Optional[str] = None
    for line in commit_text.split("\n"):
        if line.startswith("tree "):
            tree_sha = line[5:].strip()[:40]
            break

    if not tree_sha:
        return recovered

    # 4. Walk tree and extract blobs
    _walk_git_tree(leak_dir, tree_sha, leak_dir, recovered)

    return recovered


def _read_git_object_file(leak_dir: Path, sha: str) -> Optional[bytes]:
    """Read and decompress a loose git object by SHA."""
    sha = sha.strip()[:40]
    # Loose object path: objects/XX/YYYYYYYY...
    obj_path = leak_dir / "objects" / sha[:2] / sha[2:]
    if not obj_path.exists():
        # Try alternate locations (downloaded files may have flat naming)
        alt_path = leak_dir / (sha[:2] + "_" + sha[2:])
        if alt_path.exists():
            obj_path = alt_path
    if not obj_path.exists():
        # Try the objects/{sha[:2]}_{sha[2:]} naming from downloads
        for candidate in leak_dir.iterdir():
            if candidate.is_file() and sha[:2] in candidate.name and sha[2:12] in candidate.name:
                obj_path = candidate
                break

    if not obj_path.exists():
        return None

    try:
        raw = obj_path.read_bytes()
        return zlib.decompress(raw)
    except Exception:
        return None


def _parse_git_object(data: bytes) -> Tuple[Optional[str], Optional[bytes]]:
    """Parse a git object header. Returns (type, content)."""
    try:
        null_idx = data.find(b"\x00")
        if null_idx == -1:
            return None, None
        header = data[:null_idx].decode("ascii", errors="replace")
        # header format: "blob 1234" or "tree 567" or "commit 890"
        parts = header.split(" ", 1)
        obj_type = parts[0] if parts else ""
        return obj_type, data[null_idx + 1:]
    except Exception:
        return None, None


def _walk_git_tree(leak_dir: Path, tree_sha: str, output_root: Path, recovered: List[str]):
    """Recursively walk a git tree object and extract all blobs."""
    data = _read_git_object_file(leak_dir, tree_sha)
    if not data:
        return

    obj_type, body = _parse_git_object(data)
    if obj_type != "tree":
        return
    if not body:
        return

    pos = 0
    while pos < len(body):
        # Each entry: <mode> <name>\x00<20-byte SHA1>
        space_idx = body.find(b" ", pos)
        if space_idx == -1:
            break
        null_idx = body.find(b"\x00", space_idx)
        if null_idx == -1:
            break

        mode = body[pos:space_idx].decode("ascii", errors="replace")
        name = body[space_idx + 1:null_idx].decode("utf-8", errors="replace")
        sha = body[null_idx + 1:null_idx + 21].hex()

        pos = null_idx + 21

        if mode == "40000":
            # Sub-tree
            subdir = output_root / name
            subdir.mkdir(parents=True, exist_ok=True)
            _walk_git_tree(leak_dir, sha, subdir, recovered)
        elif mode in ("100644", "100755", "120000"):
            # Blob (regular file, executable, symlink)
            blob_data = _read_git_object_file(leak_dir, sha)
            if blob_data:
                _, content = _parse_git_object(blob_data)
                if content is not None:
                    file_path = output_root / name
                    file_path.write_bytes(content)
                    recovered.append(str(file_path))
