from __future__ import annotations

import platform
import shutil
from pathlib import Path
from typing import Any, Dict, List

from config.settings import settings
from ..base import BaseTool, ToolResult


class CTFToolManagerTool(BaseTool):
    category = "ctf_web"
    required_capability = "passive"

    @property
    def name(self) -> str:
        return "ctf_tool_manager"

    @property
    def description(self) -> str:
        return (
            "Plan acquisition and use of missing CTF helper tools when the agent decides a task needs external support. "
            "Covers common web, pwn, reverse, forensics, crypto, android, stego, and network tooling, and returns the next core tool "
            "to call such as download_tool_url, install_python_package, write_tool_script, or run_tool_script."
        )

    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "needed_tool": {"type": "string", "description": "Tool/library needed, e.g. jadx, binwalk, exiftool, z3, sqlmap."},
                "task": {"type": "string", "description": "Why the tool is needed."},
                "challenge_type": {"type": "string", "description": "Optional CTF category: web/pwn/reverse/forensics/crypto/misc/android."},
                "prefer_python": {"type": "boolean", "description": "Prefer pip-installable Python packages when possible."},
                "local_search_paths": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional explicit local directories to search before downloading.",
                },
            },
            "required": ["needed_tool"],
        }

    def _run(self, **kwargs: Any) -> ToolResult:
        needed_tool = str(kwargs.get("needed_tool") or "").strip().lower()
        task = str(kwargs.get("task") or "CTF solve task").strip()
        challenge_type = str(kwargs.get("challenge_type") or "").strip().lower()
        prefer_python = bool(kwargs.get("prefer_python", False))
        local_search_paths = [str(item) for item in (kwargs.get("local_search_paths") or []) if str(item).strip()]
        system = platform.system().lower()
        catalog = _catalog(system)
        entry = _match_tool(needed_tool, catalog)
        if entry is None:
            entry = _generic_entry(needed_tool, task, prefer_python)
        actions = list(entry["actions"])
        existing_artifacts = _find_existing_artifacts(entry, local_search_paths)
        installed = _installed_state(entry, existing_artifacts)
        if existing_artifacts:
            actions = [_use_existing_action(existing_artifacts[0]), *actions]
        next_core_tool = _next_core_tool(actions, installed)
        action_summary = [
            f"当前判断：解题过程需要额外工具 `{needed_tool}` 来完成 `{task}`。",
            f"工具状态：{installed['summary']}。",
            f"下一步：调用 `{next_core_tool}`，优先复用 existing_artifacts；没有本机可用脚本/工具时再按 actions 下载或安装。",
        ]
        parsed = {
            "needed_tool": needed_tool,
            "task": task,
            "challenge_type": challenge_type,
            "matched_tool": entry["name"],
            "aliases": entry.get("aliases", []),
            "installed": installed,
            "existing_artifacts": existing_artifacts,
            "next_core_tool": next_core_tool,
            "actions": actions,
            "verify_commands": entry.get("verify_commands", []),
            "usage_examples": entry.get("usage_examples", []),
            "chinese_action_summary": action_summary,
        }
        raw = "\n\n".join([
            "中文行动摘要:\n" + "\n".join(f"- {item}" for item in action_summary),
            "工具补全动作:\n" + "\n".join(_format_action(item) for item in actions),
            "验证命令:\n" + "\n".join(f"- {item}" for item in entry.get("verify_commands", [])),
            "用法示例:\n" + "\n".join(f"- {item}" for item in entry.get("usage_examples", [])),
        ])
        return ToolResult(True, self.name, "已生成通用 CTF 工具补全计划。", raw_output=raw, parsed_data=parsed)


def _catalog(system: str) -> List[Dict[str, Any]]:
    windows = "windows" in system
    return [
        _download_tool("jadx", ["apk", "android", "dex", "jadx-gui"], "https://github.com/skylot/jadx/releases/latest", "jadx --version", "jadx -d out app.apk"),
        _download_tool("apktool", ["apktool.jar", "android resources", "smali"], "https://bitbucket.org/iBotPeaches/apktool/downloads/", "apktool --version", "apktool d app.apk -o out"),
        _download_tool("binwalk", ["firmware", "extract firmware"], "https://github.com/ReFirmLabs/binwalk", "binwalk --version", "binwalk -e firmware.bin"),
        _download_tool("exiftool", ["metadata", "exif", "image metadata"], "https://exiftool.org/", "exiftool -ver", "exiftool suspicious.jpg"),
        _download_tool("steghide", ["stego", "jpg hidden", "wav hidden"], "https://github.com/StefanoDeVuono/steghide", "steghide --version", "steghide info image.jpg"),
        _download_tool("zsteg", ["png stego", "lsb"], "https://github.com/zed-0xff/zsteg", "zsteg --version", "zsteg image.png"),
        _download_tool("sqlmap", ["sqli", "sql injection"], "https://github.com/sqlmapproject/sqlmap/archive/refs/heads/master.zip", "python sqlmap.py --version", "python sqlmap.py -u <url> --batch"),
        _download_tool("nuclei", ["template scan", "cve scan"], "https://github.com/projectdiscovery/nuclei/releases/latest", "nuclei -version", "nuclei -u <url>"),
        _download_tool("ffmpeg", ["audio", "video", "frames"], "https://ffmpeg.org/download.html", "ffmpeg -version", "ffmpeg -i input.wav output.png"),
        _download_tool("tshark", ["pcap", "wireshark cli"], "https://www.wireshark.org/download.html", "tshark -v", "tshark -r capture.pcap -Y http"),
        _download_tool("hashcat", ["hash cracking", "password cracking"], "https://hashcat.net/hashcat/", "hashcat --version", "hashcat -m <mode> hash.txt wordlist.txt"),
        _download_tool("john", ["john the ripper", "zip2john", "ssh2john"], "https://www.openwall.com/john/", "john --list=formats", "john hash.txt --wordlist=rockyou.txt"),
        _pip_tool("z3", ["z3-solver", "constraints", "smt"], "z3-solver", "python -c \"import z3; print(z3.get_version_string())\"", "write Python solve script importing z3"),
        _pip_tool("pwntools", ["pwn", "remote exploit", "elf rop"], "pwntools", "python -c \"import pwn; print(pwn.version)\"", "write exploit.py using pwn.remote/process"),
        _pip_tool("pycryptodome", ["crypto", "aes", "rsa", "number"], "pycryptodome", "python -c \"import Crypto; print('ok')\"", "write Python crypto solver importing Crypto.Util.number"),
        _pip_tool("opencv", ["cv2", "image processing", "qr"], "opencv-python", "python -c \"import cv2; print(cv2.__version__)\"", "write Python image analysis script importing cv2"),
        _pip_tool("pillow", ["pil", "image", "pixels"], "pillow", "python -c \"from PIL import Image; print('ok')\"", "write Python image script importing PIL.Image"),
        _pip_tool("scapy", ["packet", "pcap", "network"], "scapy", "python -c \"import scapy.all as s; print('ok')\"", "write Python packet parser using scapy"),
        _pip_tool("angr", ["symbolic execution", "reverse", "binary solve"], "angr", "python -c \"import angr; print(angr.__version__)\"", "write angr solve script"),
        _download_tool("ngrok", ["tcp tunnel", "public exposure"], "https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-windows-amd64.zip" if windows else "https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-linux-amd64.tgz", "ngrok version", "ngrok tcp 3306"),
        _download_tool("chisel", ["reverse tunnel", "tcp tunnel"], "https://github.com/jpillora/chisel/releases/latest", "chisel --version", "chisel client <vps>:8000 R:3306:127.0.0.1:3306"),
    ]


def _download_tool(name: str, aliases: List[str], url: str, verify: str, usage: str) -> Dict[str, Any]:
    return {
        "name": name,
        "aliases": aliases,
        "actions": [{"kind": "download", "tool": "download_tool_url", "url": url, "filename": _filename_from_url_or_name(url, name)}],
        "verify_commands": [verify],
        "usage_examples": [usage],
    }


def _pip_tool(name: str, aliases: List[str], package: str, verify: str, usage: str) -> Dict[str, Any]:
    return {
        "name": name,
        "aliases": aliases,
        "actions": [{"kind": "pip", "tool": "install_python_package", "package": package}],
        "verify_commands": [verify],
        "usage_examples": [usage],
    }


def _match_tool(needed_tool: str, catalog: List[Dict[str, Any]]) -> Dict[str, Any] | None:
    words = {needed_tool, *needed_tool.replace("_", " ").replace("-", " ").split()}
    for entry in catalog:
        haystack = {entry["name"], *entry.get("aliases", [])}
        if any(word and any(word in item.lower() for item in haystack) for word in words):
            return entry
    return None


def _generic_entry(needed_tool: str, task: str, prefer_python: bool) -> Dict[str, Any]:
    if prefer_python:
        return _pip_tool(needed_tool, [task], needed_tool, f"python -c \"import {needed_tool.replace('-', '_')}; print('ok')\"", f"write script using {needed_tool}")
    return {
        "name": needed_tool or "unknown_tool",
        "aliases": [task],
        "actions": [
            {"kind": "research", "tool": "ctf_knowledge_search", "query": f"{needed_tool} install CTF usage"},
            {"kind": "download", "tool": "download_tool_url", "url": "<official-release-url>", "filename": f"{needed_tool or 'tool'}.bin"},
        ],
        "verify_commands": [f"{needed_tool} --help"],
        "usage_examples": [f"Run {needed_tool} against the challenge artifact after download/extraction."],
    }


def _installed_state(entry: Dict[str, Any], existing_artifacts: List[Dict[str, Any]]) -> Dict[str, Any]:
    if existing_artifacts:
        first = existing_artifacts[0]
        return {
            "installed": True,
            "path": first["path"],
            "source": first["source"],
            "summary": f"已找到本机可复用脚本/工具: {first['path']}",
        }
    name = entry.get("name", "")
    binary = shutil.which(name)
    if binary:
        return {"installed": True, "path": binary, "source": "PATH", "summary": f"已在 PATH 中找到 {name}: {binary}"}
    return {"installed": False, "path": "", "source": "", "summary": f"未在 PATH/CTF workspace 中找到 {name}，需要按计划补齐"}


def _next_core_tool(actions: List[Dict[str, Any]], installed: Dict[str, Any]) -> str:
    if installed.get("installed"):
        return "run_tool_script"
    for action in actions:
        tool = action.get("tool")
        if tool:
            return str(tool)
    return "write_tool_script"


def _format_action(action: Dict[str, Any]) -> str:
    if action.get("kind") == "use_existing":
        return f"- use_existing: {action.get('path')}"
    if action.get("kind") == "pip":
        return f"- install_python_package: {action.get('package')}"
    if action.get("kind") == "download":
        return f"- download_tool_url: {action.get('url')} -> {action.get('filename')}"
    if action.get("kind") == "research":
        return f"- ctf_knowledge_search: {action.get('query')}"
    return "- " + str(action)


def _filename_from_url_or_name(url: str, name: str) -> str:
    tail = url.rstrip("/").rsplit("/", 1)[-1]
    if "." in tail and "latest" not in tail:
        return tail
    return name + ".download"


def _find_existing_artifacts(entry: Dict[str, Any], local_search_paths: List[str]) -> List[Dict[str, Any]]:
    runtime = settings.effective()
    workspace = Path(runtime.ctf_workspace_dir).resolve()
    roots = [
        workspace / "scripts",
        workspace / "downloads",
        workspace / "python_packages",
    ]
    for item in local_search_paths:
        path = Path(item).expanduser()
        if path.exists():
            roots.append(path.resolve())
    needles = _artifact_needles(entry)
    suffixes = {".py", ".ps1", ".bat", ".cmd", ".exe", ".sh", ".jar", ".js", ".pl", ".rb", ".download", ".zip", ".tgz", ".gz"}
    found: List[Dict[str, Any]] = []
    for root in roots:
        if not root.exists() or not root.is_dir():
            continue
        for path in _iter_candidate_files(root):
            lower_name = path.name.lower()
            if path.suffix.lower() not in suffixes and not any(needle in lower_name for needle in needles):
                continue
            if any(needle in lower_name for needle in needles):
                found.append({
                    "path": str(path),
                    "name": path.name,
                    "source": str(root),
                    "kind": _artifact_kind(path),
                })
                if len(found) >= 10:
                    return found
    return found


def _artifact_needles(entry: Dict[str, Any]) -> List[str]:
    raw = [entry.get("name", ""), *entry.get("aliases", [])]
    needles = []
    for item in raw:
        value = str(item).lower().replace("_", "-").strip()
        if value:
            needles.append(value)
            needles.extend(part for part in value.replace("-", " ").split() if len(part) >= 3)
    return sorted(set(needles), key=len, reverse=True)


def _iter_candidate_files(root: Path) -> List[Path]:
    try:
        paths = [item for item in root.rglob("*") if item.is_file()]
    except OSError:
        return []
    return sorted(paths, key=lambda item: (len(item.parts), str(item)))[:300]


def _artifact_kind(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix in {".py", ".ps1", ".bat", ".cmd", ".sh", ".js", ".pl", ".rb"}:
        return "script"
    if suffix in {".exe", ".jar"}:
        return "binary"
    return "download"


def _use_existing_action(artifact: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "kind": "use_existing",
        "tool": "run_tool_script" if artifact.get("kind") == "script" else "write_tool_script",
        "path": artifact["path"],
        "artifact_kind": artifact.get("kind", ""),
    }
