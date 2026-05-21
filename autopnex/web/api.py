"""FastAPI application exposing AutoPenX as a web service with a simple UI."""
from __future__ import annotations

import asyncio
import importlib
import json
import os
import queue
import shutil
import threading
import time
import time as _time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from config.settings import settings
from ..policy import PolicyError, apply_scan_policy, create_approval
from ..tools._http import TargetScopeError, ensure_target_allowed
from ..tools.base import ToolRegistry

from .. import tools as _tools  # noqa: F401  (load tools)
from .runner import manager, event_to_sse


STATIC_DIR = Path(__file__).parent / "static"


app = FastAPI(title="AutoPenX", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    target: str
    mock: bool = False
    max_iter: Optional[int] = None
    scan_mode: Optional[str] = None
    allow_external_tools: Optional[bool] = None
    allow_local_targets: Optional[bool] = None
    exploit_enabled: Optional[bool] = None
    approval_token: Optional[str] = None
    login_endpoint: Optional[str] = None
    login_credentials: Optional[str] = None
    login_username_field: Optional[str] = None
    login_password_field: Optional[str] = None


class SettingsUpdateRequest(BaseModel):
    api_key: Optional[str] = None
    clear_api_key: bool = False
    deepseek_base_url: Optional[str] = None
    deepseek_model: Optional[str] = None
    burp_proxy_url: Optional[str] = None
    scan_mode: Optional[str] = None
    allow_external_tools: Optional[bool] = None
    allow_local_targets: Optional[bool] = None
    exploit_enabled: Optional[bool] = None


class ApprovalRequest(BaseModel):
    target: str
    scopes: list[str]
    ttl_seconds: Optional[int] = None


def _settings_payload():
    settings.reload()
    runtime = settings.snapshot()
    return {
        **runtime.to_client_dict(),
        "capabilities": ToolRegistry.capabilities(runtime),
    }


@app.get("/", response_class=HTMLResponse)
async def index() -> HTMLResponse:
    html_file = STATIC_DIR / "index.html"
    return HTMLResponse(html_file.read_text(encoding="utf-8"))


@app.get("/api/health")
async def health():
    payload = _settings_payload()
    return {
        "status": "ok",
        "llm_configured": payload["has_api_key"],
        "model": payload["deepseek_model"],
        "allow_external_tools": payload["allow_external_tools"],
        "capabilities": payload["capabilities"],
        "scan_mode": payload["scan_mode"],
        "allow_local_targets": payload["allow_local_targets"],
        "exploit_enabled": payload["exploit_enabled"],
    }


@app.get("/api/settings")
async def get_settings():
    return _settings_payload()


@app.put("/api/settings")
async def update_settings(req: SettingsUpdateRequest):
    if req.deepseek_base_url is not None and not req.deepseek_base_url.strip():
        raise HTTPException(400, "deepseek_base_url cannot be empty")
    if req.deepseek_model is not None and not req.deepseek_model.strip():
        raise HTTPException(400, "deepseek_model cannot be empty")
    settings.save_ui_settings(
        api_key=req.api_key,
        clear_api_key=req.clear_api_key,
        base_url=req.deepseek_base_url,
        model=req.deepseek_model,
        burp_proxy_url=req.burp_proxy_url,
        scan_mode=req.scan_mode,
        allow_external_tools=req.allow_external_tools,
        allow_local_targets=req.allow_local_targets,
        exploit_enabled=req.exploit_enabled,
    )
    return _settings_payload()


@app.post("/api/approvals")
async def create_scan_approval(req: ApprovalRequest):
    ttl = req.ttl_seconds or settings.approval_ttl_seconds
    try:
        approval = create_approval(req.target, req.scopes, ttl)
    except PolicyError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {
        "token": approval.token,
        "scopes": list(approval.scopes),
        "target": approval.target,
        "expires_at": approval.expires_at,
    }


@app.post("/api/scan")
async def start_scan(req: ScanRequest):
    if not req.target:
        raise HTTPException(400, "target is required")
    base_runtime = settings.snapshot()
    try:
        runtime = apply_scan_policy(
            base_runtime,
            target=req.target,
            scan_mode=req.scan_mode,
            allow_external_tools=req.allow_external_tools,
            allow_local_targets=req.allow_local_targets,
            exploit_enabled=req.exploit_enabled,
            approval_token=req.approval_token,
        )
    except PolicyError as exc:
        raise HTTPException(403, str(exc)) from exc
    try:
        ensure_target_allowed(req.target, runtime_config=runtime)
    except TargetScopeError as exc:
        raise HTTPException(403, str(exc)) from exc
    # Apply login overrides from request
    login_overrides = {}
    if req.login_endpoint:
        login_overrides["login_endpoint"] = req.login_endpoint
    if req.login_credentials:
        login_overrides["login_credentials"] = req.login_credentials
    if req.login_username_field:
        login_overrides["login_username_field"] = req.login_username_field
    if req.login_password_field:
        login_overrides["login_password_field"] = req.login_password_field
    if login_overrides:
        runtime = settings.snapshot(
            scan_mode=runtime.scan_mode,
            allow_external_tools=runtime.allow_external_tools,
            allow_local_targets=runtime.allow_local_targets,
            exploit_enabled=runtime.exploit_enabled,
            **login_overrides,
        )
    job = manager.start(req.target, mock=req.mock, max_iter=req.max_iter, runtime_config=runtime)
    return {"job_id": job.id, "status": job.status}


@app.get("/api/jobs")
async def list_jobs():
    return {"jobs": manager.list()}


@app.get("/api/jobs/{job_id}")
async def job_status(job_id: str):
    job = manager.get(job_id)
    if not job:
        raise HTTPException(404, "job not found")
    return {
        "id": job.id,
        "target": job.target,
        "status": job.status,
        "mock": job.mock,
        "mode": job.orchestrator_mode or ("mock" if job.mock or not job.runtime_config.has_llm else "llm"),
        "created_at": job.created_at,
        "findings_count": len(job.findings.findings) if job.findings else 0,
        "findings": [f.to_dict() for f in job.findings.sorted_findings()] if job.findings else [],
        "evidence_artifacts": [artifact.to_dict() for artifact in job.findings.evidence_artifacts] if job.findings else [],
        "phase_tasks": {phase: [task.to_dict() for task in tasks] for phase, tasks in job.findings.phase_tasks.items()}
        if job.findings
        else {},
        "error": job.error,
        "markdown_path": job.markdown_path,
        "html_path": job.html_path,
        "history_tail": list(job.history)[-120:],
        "runtime_config": {
            **job.runtime_config.to_client_dict(),
            "capabilities": ToolRegistry.capabilities(job.runtime_config),
        },
    }


@app.get("/api/jobs/{job_id}/events")
async def job_events(job_id: str, request: Request):
    job = manager.get(job_id)
    if not job:
        raise HTTPException(404, "job not found")

    last_id = 0
    raw = request.headers.get("Last-Event-ID", "0")
    try:
        last_id = int(raw)
    except (ValueError, TypeError):
        last_id = 0

    async def stream():
        for ev in list(job.history):
            if ev.get("seq", 0) <= last_id:
                continue
            try:
                yield event_to_sse(ev)
            except (TypeError, ValueError) as exc:
                yield event_to_sse(
                    {"event": "sse_serialize_error", "error": f"{exc.__class__.__name__}: {exc}"}
                )
        idle_count = 0
        while True:
            if job.status in ("done", "error") and job.events.empty():
                break
            try:
                ev = job.events.get_nowait()
            except queue.Empty:
                idle_count += 1
                if idle_count >= 60:  # ~15s without events → send keepalive
                    yield ": keepalive\n\n"
                    idle_count = 0
                await asyncio.sleep(0.25)
                continue
            idle_count = 0
            try:
                yield event_to_sse(ev)
            except (TypeError, ValueError) as exc:
                yield event_to_sse(
                    {"event": "sse_serialize_error", "error": f"{exc.__class__.__name__}: {exc}"}
                )
        try:
            yield event_to_sse({"event": "stream_close", "status": job.status})
        except (TypeError, ValueError) as exc:
            yield event_to_sse(
                {"event": "sse_serialize_error", "error": f"{exc.__class__.__name__}: {exc}"}
            )

    return StreamingResponse(stream(), media_type="text/event-stream")


@app.get("/api/jobs/{job_id}/report")
async def job_report_markdown(job_id: str):
    job = manager.get(job_id)
    if not job or not job.markdown_path:
        raise HTTPException(404, "report not ready")
    return FileResponse(job.markdown_path, media_type="text/markdown", filename=f"{job_id}.md")


@app.get("/api/jobs/{job_id}/report.html")
async def job_report_html(job_id: str):
    job = manager.get(job_id)
    if not job or not job.html_path:
        raise HTTPException(404, "report not ready")
    return FileResponse(job.html_path, media_type="text/html")


# ---------------------------------------------------------------------------
# CTF Mode Endpoints
# ---------------------------------------------------------------------------

UPLOAD_BASE = Path(__file__).parent.parent.parent / "uploads"

# Magic bytes signatures for file type detection
_MAGIC_SIGNATURES: List[tuple] = [
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
    (b"%PDF", "application/pdf"),
    (b"PK\x03\x04", "application/zip"),
    (b"\x1f\x8b", "application/gzip"),
    (b"Rar!\x1a\x07", "application/rar"),
    (b"\x7fELF", "application/x-elf"),
    (b"MZ", "application/x-dosexec"),
    (b"\xd0\xcf\x11\xe0", "application/x-pcap"),
    (b"\xa1\xb2\xc3\xd4", "application/x-pcap"),
    (b"\xd4\xc3\xb2\xa1", "application/x-pcap"),
    (b"\x0a\x0d\x0d\x0a", "application/x-pcapng"),
    (b"\xca\xfe\xba\xbe", "application/java-archive"),
    (b"SQLite format", "application/x-sqlite3"),
]


def _detect_file_type_magic(content: bytes) -> str:
    """Detect file type using magic bytes (first 8 bytes)."""
    header = content[:8]
    for sig, ftype in _MAGIC_SIGNATURES:
        if header.startswith(sig):
            return ftype
    # Heuristic: check if content looks like text
    try:
        content[:512].decode("utf-8")
        return "text/plain"
    except (UnicodeDecodeError, ValueError):
        pass
    return "application/octet-stream"


# CTF tool definitions
# "builtin": True means the tool is part of AutoPenX (always available)
# "check": CLI command name for shutil.which() or Python module for importlib
CTF_TOOLS: List[Dict[str, Any]] = [
    # Core ReAct tools
    {"name": "http_request", "category": "Core", "description": "HTTP 请求与会话保持", "builtin": True},
    {"name": "run_python", "category": "Core", "description": "临时 Python 脚本执行", "builtin": True},
    {"name": "decode_data", "category": "Core", "description": "编码解码与自动识别", "builtin": True},
    {"name": "scan_flag", "category": "Core", "description": "Flag 格式扫描", "builtin": True},
    {"name": "file_analyze", "category": "Core", "description": "文件类型与字符串分析", "builtin": True},
    {"name": "ctf_knowledge_search", "category": "Core", "description": "检索内置与已学习解题经验", "builtin": True},
    {"name": "write_tool_script", "category": "Core", "description": "在受控工作区写入自定义脚本", "builtin": True},
    {"name": "run_tool_script", "category": "Core", "description": "运行受控工作区脚本", "builtin": True},
    {"name": "install_python_package", "category": "Core", "description": "安装 Python 包到 CTF 工作区", "builtin": True},
    {"name": "download_tool_url", "category": "Core", "description": "下载辅助工具到 CTF 工作区", "builtin": True},
    # Web (all built-in)
    {"name": "ssti_detect", "category": "Web", "description": "SSTI 模板注入检测", "builtin": True},
    {"name": "lfi_detect", "category": "Web", "description": "本地文件包含检测", "builtin": True},
    {"name": "unserialize_detect", "category": "Web", "description": "反序列化漏洞检测", "builtin": True},
    {"name": "flag_reader", "category": "Web", "description": "Flag 文件读取", "builtin": True},
    {"name": "phar_pdo_chain", "category": "Web", "description": "Phar + PDO FETCH_CLASS 对象链辅助", "builtin": True},
    {"name": "ctf_mysql_helper", "category": "Web", "description": "公网 MySQL 辅助方案生成", "builtin": True},
    {"name": "ctf_tunnel_helper", "category": "Web", "description": "非 Docker 公网暴露与隧道方案生成", "builtin": True},
    {"name": "ctf_tool_manager", "category": "Core", "description": "通用 CTF 外部工具下载/安装规划", "builtin": True},
    # Pwn
    {"name": "checksec", "category": "Pwn", "description": "二进制安全检查 (内置ELF解析)", "builtin": True},
    {"name": "rop_chain", "category": "Pwn", "description": "ROP 链构造", "check": "ROPgadget"},
    {"name": "format_string", "category": "Pwn", "description": "格式化字符串利用", "builtin": True},
    {"name": "remote_interact", "category": "Pwn", "description": "远程 TCP 交互", "builtin": True},
    # Crypto (all built-in)
    {"name": "rsa_attack", "category": "Crypto", "description": "RSA 攻击 (小e/Fermat/Wiener)", "builtin": True},
    {"name": "classical_cipher", "category": "Crypto", "description": "古典密码破解 (Caesar/Vigenere)", "builtin": True},
    {"name": "encoding_decode", "category": "Crypto", "description": "编码解码 (Base64/Hex/Morse)", "builtin": True},
    {"name": "script_execute", "category": "Crypto", "description": "Python 脚本执行引擎", "builtin": True},
    # Misc
    {"name": "file_analyze", "category": "Misc", "description": "文件类型分析 (内置magic)", "builtin": True},
    {"name": "stego_analyze", "category": "Misc", "description": "隐写分析", "check": "steghide"},
    {"name": "traffic_analyze", "category": "Misc", "description": "流量分析", "check": "tshark"},
    {"name": "archive_analyze", "category": "Misc", "description": "压缩包分析 (内置ZIP解析)", "builtin": True},
    # Reverse
    {"name": "decompile", "category": "Reverse", "description": "反编译 (需Ghidra/objdump)", "check": "objdump"},
    {"name": "strings_extract", "category": "Reverse", "description": "字符串提取 (内置)", "builtin": True},
    {"name": "dynamic_analyze", "category": "Reverse", "description": "动态分析 (ltrace/strace)", "check": "ltrace"},
    {"name": "constraint_solve", "category": "Reverse", "description": "约束求解 (z3)", "check": "z3", "is_python": True},
]


def _check_tool_available(tool_def: Dict[str, Any]) -> bool:
    """Check if a tool is available."""
    # Built-in tools are always available
    if tool_def.get("builtin"):
        return True
    check = tool_def.get("check", "")
    if not check:
        return True
    if tool_def.get("is_python"):
        try:
            importlib.import_module(check)
            return True
        except (ImportError, ModuleNotFoundError):
            return False
    # Check system PATH + external_tools directory
    ext_tools_dir = Path(__file__).parent.parent.parent / "external_tools"
    search_path = os.environ.get("PATH", "")
    if ext_tools_dir.exists():
        search_path = str(ext_tools_dir) + os.pathsep + search_path
    return shutil.which(check, path=search_path) is not None


class CTFSolveRequest(BaseModel):
    target: str
    challenge_type: Optional[str] = None
    flag_format: Optional[str] = r"flag\{[^}]+\}"
    files: List[str] = []
    enabled_tools: List[str] = []
    max_attempts: int = 10
    timeout: int = 600
    thinking_mode: bool = True
    scan_mode: Optional[str] = None
    allow_external_tools: Optional[bool] = None
    allow_local_targets: Optional[bool] = None
    exploit_enabled: Optional[bool] = None
    approval_token: Optional[str] = None


@app.post("/api/ctf/upload")
async def ctf_upload(file: UploadFile = File(...)):
    """Accept a CTF challenge file upload and detect type via magic bytes."""
    if not file.filename:
        raise HTTPException(400, "filename is required")

    upload_dir = UPLOAD_BASE
    upload_dir.mkdir(parents=True, exist_ok=True)

    safe_name = Path(file.filename).name
    if not safe_name:
        raise HTTPException(400, "invalid filename")
    dest = upload_dir / safe_name
    content = await file.read()
    dest.write_bytes(content)

    file_type = _detect_file_type_magic(content)
    source_analysis = None
    if file_type in {"application/zip", "text/plain"} or file.filename.lower().endswith((".zip", ".php", ".html", ".txt")):
        try:
            from ..ctf.source_analyzer import analyze_attachment

            analysis = analyze_attachment(dest)
            source_analysis = analysis.to_dict()
        except Exception as exc:  # noqa: BLE001
            source_analysis = {"errors": [f"{exc.__class__.__name__}: {exc}"]}

    return {
        "filename": file.filename,
        "size": len(content),
        "file_type": file_type,
        "path": str(dest),
        "source_analysis": source_analysis,
    }


@app.get("/api/ctf/tools")
async def ctf_tools():
    """Return list of CTF tools with availability status."""
    tools = []
    for tool_def in CTF_TOOLS:
        available = _check_tool_available(tool_def)
        tools.append({
            "name": tool_def["name"],
            "category": tool_def["category"],
            "description": tool_def["description"],
            "available": available,
        })
    return {"tools": tools}


@app.post("/api/ctf/solve")
async def ctf_solve(req: CTFSolveRequest):
    """Run CTF ReAct agent to solve a challenge via LLM-driven tool calling."""
    if not req.target:
        raise HTTPException(400, "target is required")

    try:
        from ..ctf.react_agent import CTFReActAgent

        base_runtime = settings.snapshot()
        runtime = apply_scan_policy(
            base_runtime,
            target=req.target,
            scan_mode=req.scan_mode,
            allow_external_tools=req.allow_external_tools,
            allow_local_targets=req.allow_local_targets,
            exploit_enabled=req.exploit_enabled,
            approval_token=req.approval_token,
        )
        ensure_target_allowed(req.target, runtime_config=runtime)

        agent = CTFReActAgent(
            target=req.target,
            challenge_type=req.challenge_type,
            flag_format=req.flag_format or r"flag\{[^}]+\}",
            max_iterations=req.max_attempts,
            timeout=req.timeout,
            thinking=req.thinking_mode,
            enabled_tools=req.enabled_tools,
            runtime_config=runtime,
            knowledge_base_path=str(Path(__file__).parent.parent.parent / "ctf_knowledge.json"),
            multi_agent=True,  # Hybrid: deterministic routes first, then LLM ReAct fallback
        )

        # Add uploaded files
        for fpath in req.files:
            agent.add_file(fpath)

        result = await agent.solve()
        return result

    except asyncio.TimeoutError:
        return {
            "success": False,
            "flag": None,
            "reasoning": "",
            "steps": [],
            "iterations": 0,
            "duration_ms": req.timeout * 1000,
            "error": "timeout",
        }
    except (PolicyError, TargetScopeError) as exc:
        raise HTTPException(403, str(exc)) from exc
    except Exception as exc:
        return {
            "success": False,
            "flag": None,
            "reasoning": "",
            "steps": [],
            "iterations": 0,
            "duration_ms": 0,
            "error": str(exc),
        }


@app.post("/api/ctf/solve/events")
async def ctf_solve_events(req: CTFSolveRequest):
    """Stream CTF solve progress as Server-Sent Events."""
    if not req.target:
        raise HTTPException(400, "target is required")

    events: "queue.Queue[Dict[str, Any]]" = queue.Queue()
    seq = {"value": 0}

    def push(event: Dict[str, Any]) -> None:
        seq["value"] += 1
        events.put({"seq": seq["value"], "ts": time.time(), **event})

    def worker() -> None:
        try:
            from ..ctf.react_agent import CTFReActAgent

            base_runtime = settings.snapshot()
            runtime = apply_scan_policy(
                base_runtime,
                target=req.target,
                scan_mode=req.scan_mode,
                allow_external_tools=req.allow_external_tools,
                allow_local_targets=req.allow_local_targets,
                exploit_enabled=req.exploit_enabled,
                approval_token=req.approval_token,
            )
            ensure_target_allowed(req.target, runtime_config=runtime)
            agent = CTFReActAgent(
                target=req.target,
                challenge_type=req.challenge_type,
                flag_format=req.flag_format or r"flag\{[^}]+\}",
                max_iterations=req.max_attempts,
                timeout=req.timeout,
                thinking=req.thinking_mode,
                enabled_tools=req.enabled_tools,
                runtime_config=runtime,
                progress_callback=push,
                knowledge_base_path=str(Path(__file__).parent.parent.parent / "ctf_knowledge.json"),
                multi_agent=True,  # Hybrid: deterministic routes first, then LLM ReAct fallback
            )
            for fpath in req.files:
                agent.add_file(fpath)
            result = asyncio.run(agent.solve())
            push({"event": "ctf_complete", "result": result})
        except Exception as exc:  # noqa: BLE001
            push({"event": "ctf_error", "error": f"{exc.__class__.__name__}: {exc}"})
        finally:
            push({"event": "ctf_stream_end"})

    threading.Thread(target=worker, daemon=True, name=f"ctf-solve-{uuid.uuid4().hex[:8]}").start()

    async def stream():
        while True:
            try:
                event = events.get_nowait()
            except queue.Empty:
                await asyncio.sleep(0.25)
                continue
            yield event_to_sse(event)
            if event.get("event") == "ctf_stream_end":
                break

    return StreamingResponse(stream(), media_type="text/event-stream")


# ---------------------------------------------------------------------------
# Browser Login Helper
# ---------------------------------------------------------------------------


class BrowserLoginRequest(BaseModel):
    target_url: str
    wait_timeout: int = 300


@app.post("/api/browser-login")
async def browser_login_endpoint(req: BrowserLoginRequest):
    """Open a headed browser for manual login and capture session cookies.

    This is a long-running endpoint - the user needs time to log in manually.
    Default timeout is 300 seconds (5 minutes).
    """
    if not req.target_url:
        raise HTTPException(400, "target_url is required")

    try:
        from ..tools.browser.login_helper import browser_login
    except ImportError as exc:
        raise HTTPException(500, f"Failed to import browser login helper: {exc}")

    result = await browser_login(req.target_url, req.wait_timeout)

    if not result.get("success"):
        return {
            "success": False,
            "error": result.get("error", "Login failed"),
            "cookies": [],
            "session_cookie": "",
            "all_headers": {},
        }

    return {
        "success": True,
        "cookies": result.get("cookies", []),
        "session_cookie": result.get("session_cookie", ""),
        "all_headers": result.get("all_headers", {}),
        "cookie_count": result.get("cookie_count", 0),
        "elapsed_seconds": result.get("elapsed_seconds", 0),
    }


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
