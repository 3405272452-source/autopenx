"""CTF Tool Router - unified tool execution gateway.

Centralises dispatch for builtin tools, registry tools, workspace actions,
and future MCP/CLI bridges.
"""
from __future__ import annotations

import logging
import re
import traceback
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import requests

from config.settings import RuntimeConfig
from ..tools.base import ToolRegistry
from .flag_engine import FlagEngine
from .tool_workspace import CTFToolWorkspace

log = logging.getLogger("autopnex.ctf.tool_router")

# ---------------------------------------------------------------------------
# Tool definitions for DeepSeek function calling
# ---------------------------------------------------------------------------

TOOL_DEFINITIONS: List[Dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "http_request",
            "description": (
                "Make an HTTP request to a URL. Use for interacting with CTF web "
                "challenges - fetching pages, submitting forms, testing injections, "
                "uploading files. Supports multipart file upload via 'files' parameter."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Full URL to request.",
                    },
                    "method": {
                        "type": "string",
                        "enum": ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"],
                        "description": "HTTP method. Default: GET.",
                    },
                    "headers": {
                        "type": "object",
                        "description": "Optional HTTP headers as key-value pairs.",
                    },
                    "data": {
                        "type": "string",
                        "description": "Request body for POST/PUT (form data or raw body).",
                    },
                    "form": {
                        "type": "object",
                        "description": "Structured HTML form fields for application/x-www-form-urlencoded.",
                    },
                    "files": {
                        "type": "object",
                        "description": (
                            "Multipart file upload. Keys are form field names, values are objects "
                            "with {filename, content, content_type}. Example: "
                            "{\"uploaded\": {\"filename\": \"shell.php\", \"content\": \"<?php system($_GET['cmd']); ?>\", \"content_type\": \"image/jpeg\"}}"
                        ),
                    },
                    "params": {
                        "type": "object",
                        "description": "URL query parameters as key-value pairs.",
                    },
                    "allow_redirects": {
                        "type": "boolean",
                        "description": "Whether to follow HTTP redirects. Default: true.",
                    },
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_python",
            "description": (
                "Execute Python code in a sandboxed subprocess. Use for crypto "
                "computations, decoding, scripting exploits, mathematical operations. "
                "Has access to standard library and common crypto packages."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "code": {
                        "type": "string",
                        "description": "Python source code to execute. Use print() for output.",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Max execution time in seconds (default: 30, max: 120).",
                    },
                },
                "required": ["code"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "decode_data",
            "description": (
                "Decode encoded data. Supports base64, base32, hex, rot13, url, "
                "morse, binary. Use 'auto' to auto-detect encoding."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "data": {
                        "type": "string",
                        "description": "The encoded data string to decode.",
                    },
                    "encoding": {
                        "type": "string",
                        "enum": ["base64", "base32", "hex", "rot13", "url", "morse", "binary", "auto"],
                        "description": "Encoding type. Use 'auto' for auto-detection.",
                    },
                },
                "required": ["data"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "scan_flag",
            "description": (
                "Scan text for CTF flag patterns. Checks for flag{...}, CTF{...}, "
                "and other common formats. Also tries decoding before scanning."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "text": {
                        "type": "string",
                        "description": "Text content to scan for flags.",
                    },
                },
                "required": ["text"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "file_analyze",
            "description": (
                "Analyze a file - detect type, extract strings, find embedded data. "
                "Useful for misc/forensics challenges with uploaded files."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to the file to analyze.",
                    },
                },
                "required": ["file_path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "ctf_knowledge_search",
            "description": "Search built-in and learned CTF solve knowledge for relevant patterns, payloads, tools, blockers, and past attempts.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Keywords such as 'php phar file_exists __set PDO'."},
                    "challenge_type": {"type": "string", "description": "Optional CTF category like web, pwn, crypto, misc, reverse."},
                    "limit": {"type": "integer", "description": "Maximum results. Default: 8."},
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "write_tool_script",
            "description": "Write a helper script into the controlled CTF workspace for later execution. Use for exploit builders, parsers, brute-force scripts, and decoders.",
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Script filename, e.g. solve_rsa.py."},
                    "content": {"type": "string", "description": "Full script source code."},
                    "language": {"type": "string", "enum": ["python", "python3", "bash", "sh", "node"], "description": "Script language. Default: python."},
                },
                "required": ["name", "content"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_tool_script",
            "description": "Run a script previously written inside the controlled CTF workspace.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Path returned by write_tool_script."},
                    "args": {"type": "array", "items": {"type": "string"}, "description": "Optional command-line arguments."},
                    "language": {"type": "string", "enum": ["python", "python3", "bash", "sh", "node"], "description": "Script language. Default: python."},
                    "timeout": {"type": "integer", "description": "Timeout in seconds, capped at 300."},
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "install_python_package",
            "description": "Install a Python package into the controlled CTF workspace using pip --target. Use only when a solve script needs a missing package.",
            "parameters": {
                "type": "object",
                "properties": {
                    "package": {"type": "string", "description": "Package spec, e.g. z3-solver or pycryptodome."}
                },
                "required": ["package"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "download_tool_url",
            "description": "Download a helper file into the controlled CTF workspace. Use for public scripts, challenge helper artifacts, and missing CTF tooling such as tunnel clients when needed.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "HTTP/HTTPS URL to download."},
                    "filename": {"type": "string", "description": "Optional safe local filename."},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "recon_scan",
            "description": "Scan target for attack surface: robots.txt, sitemap, links, forms, JS APIs.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target base URL to scan."},
                    "depth": {"type": "integer", "description": "Crawl depth (default: 1)."},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "repl_execute",
            "description": (
                "Execute Python code in a persistent REPL that maintains variable "
                "state between calls. Use for multi-step exploits where you need to "
                "keep session/cookies/variables alive."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "code": {
                        "type": "string",
                        "description": "Python code to execute in the persistent REPL.",
                    },
                },
                "required": ["code"],
            },
        },
    },
]

CORE_TOOL_NAMES = {
    "http_request",
    "run_python",
    "decode_data",
    "scan_flag",
    "file_analyze",
    "ctf_knowledge_search",
    "write_tool_script",
    "run_tool_script",
    "install_python_package",
    "download_tool_url",
    "recon_scan",
    "repl_execute",
}

DEFAULT_CTF_TOOL_NAMES = {
    "ssti_detect",
    "lfi_detect",
    "unserialize_detect",
    "flag_reader",
    "phar_pdo_chain",
    "ctf_mysql_helper",
    "ctf_tunnel_helper",
    "ctf_tool_manager",
}


# ---------------------------------------------------------------------------
# Builtin tool executors
# ---------------------------------------------------------------------------

def _exec_http_request(args: Dict[str, Any], session: Optional[requests.Session] = None) -> Dict[str, Any]:
    """Execute an HTTP request and return status, headers, body."""
    url = args.get("url", "")
    method = args.get("method", "GET").upper()
    headers = args.get("headers") or {}
    data = args.get("data")
    form = args.get("form")
    params = args.get("params")
    files = args.get("files")  # multipart file upload support
    allow_redirects = bool(args.get("allow_redirects", True))

    if not url:
        return {"error": "url is required"}

    try:
        req_headers = {"User-Agent": "AutoPenX-CTF/1.0"}
        req_headers.update(headers)

        client = session or requests
        request_data = form if isinstance(form, dict) and form else data

        # Build files dict for multipart upload
        # Format: {"field_name": ("filename", content_bytes, "content_type")}
        files_dict = None
        if files and isinstance(files, dict):
            files_dict = {}
            for field_name, file_spec in files.items():
                if isinstance(file_spec, dict):
                    fname = file_spec.get("filename", "file.txt")
                    content = file_spec.get("content", "").encode("utf-8")
                    ctype = file_spec.get("content_type", "application/octet-stream")
                    files_dict[field_name] = (fname, content, ctype)
                elif isinstance(file_spec, str):
                    files_dict[field_name] = (field_name, file_spec.encode("utf-8"), "text/plain")
            # When uploading files, don't pass data as it conflicts
            if files_dict:
                request_data = None

        resp = client.request(
            method=method,
            url=url,
            headers=req_headers,
            data=request_data,
            params=params,
            files=files_dict,
            timeout=30,
            allow_redirects=allow_redirects,
            verify=False,
        )

        body = resp.text
        if len(body) > 10000:
            body = body[:10000] + f"\n... [truncated, total {len(resp.text)} chars]"

        return {
            "status_code": resp.status_code,
            "headers": dict(resp.headers),
            "body": body,
            "url": str(resp.url),
            "location": resp.headers.get("Location", ""),
            "history": [
                {
                    "status_code": item.status_code,
                    "url": str(item.url),
                    "location": item.headers.get("Location", ""),
                }
                for item in resp.history
            ],
            "cookies": dict(getattr(resp, "cookies", {}) or {}),
            "session_cookies": dict(session.cookies) if session is not None else {},
        }
    except requests.Timeout:
        return {"error": "Request timed out after 30s"}
    except requests.ConnectionError as e:
        return {"error": f"Connection failed: {e}"}
    except Exception as e:
        return {"error": f"HTTP request failed: {e}"}


def _exec_run_python(args: Dict[str, Any]) -> Dict[str, Any]:
    """Execute Python code via script_execute."""
    from ..tools.ctf_crypto.script_execute import script_execute

    code = args.get("code", "")
    timeout = min(int(args.get("timeout", 30)), 120)

    if not code.strip():
        return {"error": "No code provided", "stdout": "", "stderr": "", "exit_code": -1}

    result = script_execute(code, timeout=timeout)
    return {
        "stdout": result["stdout"],
        "stderr": result["stderr"],
        "exit_code": result["exit_code"],
        "success": result["success"],
    }


def _exec_decode_data(args: Dict[str, Any]) -> Dict[str, Any]:
    """Decode encoded data via encoding_decode."""
    from ..tools.ctf_crypto.encoding_decode import encoding_decode

    data = args.get("data", "")
    encoding = args.get("encoding", "auto")

    if not data:
        return {"error": "No data provided", "decoded": "", "encoding_detected": ""}

    result = encoding_decode(data, encoding=encoding)
    return {
        "decoded": result.get("decoded", ""),
        "encoding_detected": result.get("encoding", ""),
        "confidence": result.get("confidence", 0.0),
    }


def _exec_scan_flag(args: Dict[str, Any], flag_engine: FlagEngine) -> Dict[str, Any]:
    """Scan text for flag patterns."""
    text = args.get("text", "")
    if not text:
        return {"found": False, "candidates": []}

    candidates = flag_engine.scan(text)
    decoded_candidates = flag_engine.decode_and_scan(text)
    all_candidates = candidates + decoded_candidates

    seen = set()
    unique = []
    for c in all_candidates:
        if c.value not in seen:
            seen.add(c.value)
            unique.append({"value": c.value, "confidence": c.confidence, "encoding": c.encoding})

    return {
        "found": len(unique) > 0,
        "candidates": unique[:10],
    }


def _exec_file_analyze(args: Dict[str, Any]) -> Dict[str, Any]:
    """Analyze a file - type detection, string extraction."""
    from .source_analyzer import analyze_attachment

    file_path = args.get("file_path", "")
    if not file_path:
        return {"error": "file_path is required"}

    path = Path(file_path)
    if not path.exists():
        return {"error": f"File not found: {file_path}"}

    try:
        data = path.read_bytes()
        file_type = _detect_magic(data[:16])

        strings_found = re.findall(rb"[\x20-\x7e]{4,}", data)
        strings_list = [s.decode("ascii") for s in strings_found[:50]]

        embedded = []
        if b"PK\x03\x04" in data[1:]:
            embedded.append("ZIP archive detected inside file")
        if b"\x89PNG" in data[1:]:
            embedded.append("PNG image detected inside file")
        if b"%PDF" in data[1:]:
            embedded.append("PDF detected inside file")

        result = {
            "file_type": file_type,
            "size_bytes": len(data),
            "strings": strings_list,
            "embedded": embedded,
        }
        if file_type == "ZIP archive":
            analysis = analyze_attachment(path)
            result["source_analysis"] = analysis.to_dict()
            result["source_summary"] = analysis.to_prompt_context(max_findings=20)
        return result
    except Exception as e:
        return {"error": f"File analysis failed: {e}"}


def _detect_magic(header: bytes) -> str:
    """Detect file type from magic bytes."""
    if header[:8] == b"\x89PNG\r\n\x1a\n":
        return "PNG image"
    if header[:3] == b"\xff\xd8\xff":
        return "JPEG image"
    if header[:4] == b"GIF8":
        return "GIF image"
    if header[:4] == b"PK\x03\x04":
        return "ZIP archive"
    if header[:4] == b"%PDF":
        return "PDF document"
    if header[:4] == b"\x7fELF":
        return "ELF binary"
    if header[:2] == b"MZ":
        return "PE executable"
    if header[:4] == b"Rar!":
        return "RAR archive"
    return "unknown"


# ---------------------------------------------------------------------------
# ToolRouter
# ---------------------------------------------------------------------------

class ToolRouter:
    """Unified gateway for executing CTF tools."""

    def __init__(
        self,
        runtime_config: RuntimeConfig,
        flag_engine: FlagEngine,
        tool_workspace: CTFToolWorkspace,
        knowledge_base: Any,
        session: requests.Session,
        challenge_type: Optional[str] = None,
        enabled_tools: Optional[Set[str]] = None,
    ):
        self.runtime_config = runtime_config
        self.flag_engine = flag_engine
        self.tool_workspace = tool_workspace
        self.knowledge_base = knowledge_base
        self.session = session
        self.challenge_type = challenge_type
        self.enabled_tools = enabled_tools or CORE_TOOL_NAMES.copy()

    # -- schema exposure ---------------------------------------------------

    def definitions(self) -> List[Dict[str, Any]]:
        """Return tool definitions for LLM function calling."""
        selected = self.enabled_tools
        tool_defs = [
            tool
            for tool in TOOL_DEFINITIONS
            if tool.get("function", {}).get("name") in selected
        ]
        registry_defs = ToolRegistry.openai_schemas(
            categories=["ctf_web"],
            runtime_config=self.runtime_config,
        )
        for schema in registry_defs:
            name = schema.get("function", {}).get("name")
            if name in selected:
                tool_defs.append(schema)
        return tool_defs

    @staticmethod
    def normalise_registry_args(name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """Normalise registry tool argument names."""
        normalised = dict(args or {})
        if name in {"ssti_detect", "lfi_detect", "unserialize_detect"}:
            if "param" not in normalised and "parameter" in normalised:
                normalised["param"] = normalised["parameter"]
            if "param" not in normalised and "params" in normalised and isinstance(normalised["params"], dict):
                normalised["param"] = next(iter(normalised["params"]), "")
        if name == "flag_reader":
            if "lfi_param" not in normalised and "param" in normalised:
                normalised["lfi_param"] = normalised["param"]
        return normalised

    # -- execution ---------------------------------------------------------

    def execute(self, name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatch tool execution. Returns result dict."""
        if name not in self.enabled_tools:
            return {"error": f"Tool disabled by enabled_tools: {name}"}
        try:
            if name == "http_request":
                return _exec_http_request(args, session=self.session)
            elif name == "ctf_knowledge_search":
                return {
                    "results": self.knowledge_base.search_knowledge(
                        args.get("query", ""),
                        challenge_type=args.get("challenge_type") or self.challenge_type or "",
                        limit=int(args.get("limit") or 8),
                    )
                }
            elif name == "write_tool_script":
                if not self.runtime_config.ctf_auto_tooling_enabled:
                    return {"error": "ctf_auto_tooling_disabled"}
                return self.tool_workspace.write_script(
                    args.get("name", "tool.py"),
                    args.get("content", ""),
                    language=args.get("language", "python"),
                )
            elif name == "run_tool_script":
                if not self.runtime_config.ctf_auto_tooling_enabled:
                    return {"error": "ctf_auto_tooling_disabled"}
                return self.tool_workspace.run_script(
                    args.get("path", ""),
                    args=args.get("args") or [],
                    language=args.get("language", "python"),
                    timeout=args.get("timeout"),
                )
            elif name == "install_python_package":
                if not (self.runtime_config.ctf_auto_tooling_enabled and self.runtime_config.ctf_tool_install_enabled):
                    return {"error": "ctf_tool_install_disabled"}
                return self.tool_workspace.install_python_package(args.get("package", ""))
            elif name == "download_tool_url":
                if not self.runtime_config.ctf_auto_tooling_enabled:
                    return {"error": "ctf_auto_tooling_disabled"}
                return self.tool_workspace.download_url(args.get("url", ""), filename=args.get("filename", ""))
            elif name == "run_python":
                return _exec_run_python(args)
            elif name == "decode_data":
                return _exec_decode_data(args)
            elif name == "scan_flag":
                return _exec_scan_flag(args, self.flag_engine)
            elif name == "file_analyze":
                return _exec_file_analyze(args)
            elif name == "recon_scan":
                from .recon_module import ReconModule
                url = args.get("url", "")
                if not url:
                    return {"error": "url is required"}
                recon = ReconModule(session=self.session, base_url=url)
                surface = recon.scan()
                return surface.to_dict()
            elif name == "repl_execute":
                from ..tools.ctf_web.python_repl import PersistentREPL
                if not hasattr(self, "_repl"):
                    self._repl = PersistentREPL()
                code = args.get("code", "")
                if not code.strip():
                    return {"error": "No code provided", "success": False, "stdout": "", "stderr": "", "variables": []}
                return self._repl.execute(code)
            elif ToolRegistry.get(name):
                registry_args = self.normalise_registry_args(name, args)
                result = ToolRegistry.execute(name, registry_args, runtime_config=self.runtime_config)
                return result.to_dict()
            else:
                return {"error": f"Unknown tool: {name}"}
        except Exception as e:
            log.error("Tool %s execution failed: %s", name, traceback.format_exc())
            return {"error": f"Tool execution failed: {e}"}
