from __future__ import annotations

import html
import re
from typing import Any, Dict, List, Optional

from .flag_engine import FlagEngine


def normalise_flag_format(flag_format: str) -> str:
    raw = (flag_format or "").strip()
    if not raw or raw in {"flag{...}", r"flag\{...\}"}:
        return r"[A-Za-z0-9_]+\{[^}]+\}"
    if raw == "flag":
        return r"[A-Za-z0-9_]+\{[^}]+\}"
    try:
        re.compile(raw)
        return raw
    except re.error:
        return r"[A-Za-z0-9_]+\{[^}]+\}"


def compact_for_llm(text: str, limit: int = 8000) -> str:
    if len(text) <= limit:
        return text
    marker = f"\n... [truncated middle, total {len(text)} chars] ...\n"
    head_len = max(1000, (limit - len(marker)) // 2)
    tail_len = max(1000, limit - len(marker) - head_len)
    return text[:head_len] + marker + text[-tail_len:]


def normalised_text_variants(text: str) -> List[str]:
    stripped = re.sub(r"<[^>]+>", "", text)
    unescaped = html.unescape(text).replace("\xa0", " ")
    stripped_unescaped = html.unescape(stripped).replace("\xa0", " ")
    variants = [text, unescaped, stripped, stripped_unescaped]
    unique: List[str] = []
    seen = set()
    for variant in variants:
        if variant not in seen:
            seen.add(variant)
            unique.append(variant)
    return unique


def check_flag_in_text(text: str, *, flag_engine: FlagEngine, flag_format: str) -> Optional[str]:
    marker_match = re.search(r"FLAG_FOUND:\s*(\S+)", text)
    if marker_match:
        candidate = marker_match.group(1)
        if re.search(flag_format, candidate):
            return candidate
    candidates = []
    for variant in normalised_text_variants(text):
        candidates.extend(flag_engine.scan(variant))
    if not candidates:
        return None
    candidates.sort(key=lambda item: item.confidence, reverse=True)
    best = candidates[0]
    if best.confidence >= 0.8:
        return best.value
    return None


def diagnose_tool_result(tool_name: str, tool_args: Dict[str, Any], tool_result: Dict[str, Any]) -> str:
    hints: List[str] = []
    if "error" in tool_result and tool_result.get("error"):
        hints.append(f"工具报错: {tool_result.get('error')}")
    status = tool_result.get("status_code")
    if isinstance(status, int):
        if status == 404:
            hints.append("HTTP 404: 路径不存在；回到源码/首页/JS 中找真实路由，或枚举相邻路径。")
        elif status in {401, 403}:
            hints.append(f"HTTP {status}: 存在认证/权限限制；优先检查 cookie、Host/Header、登录流程或越权路径。")
        elif status >= 500:
            hints.append(f"HTTP {status}: 服务端异常；保留该 payload，尝试缩小输入并利用报错信息定位 sink。")
        elif status in {301, 302, 303, 307, 308}:
            hints.append(f"HTTP {status}: 检查 Location 和 session cookie；表单流程建议 allow_redirects=false。")
    body = str(tool_result.get("body") or tool_result.get("stdout") or "")
    if not body.strip() and not hints:
        hints.append("响应为空: 尝试查看状态码/响应头，换 GET/POST、参数名或保持 session。")
    stderr = str(tool_result.get("stderr") or "")
    if stderr.strip():
        hints.append("脚本 stderr 非空: 先修脚本语法/依赖/编码问题，再复用该思路。")
    if tool_name == "http_request" and tool_args.get("method", "GET").upper() == "GET" and "form" in body.lower():
        hints.append("页面含表单: 下一步应提取 action/method/input 名称并提交表单。")
    if not hints:
        return ""
    return "工具结果诊断:\n" + "\n".join(f"- {item}" for item in hints[:5])


def extract_blockers(steps: List[Dict[str, Any]], result: Dict[str, Any]) -> List[str]:
    blockers: List[str] = []
    if result.get("error"):
        blockers.append(str(result["error"]))
    for step in steps:
        preview = str(step.get("result_preview", ""))
        for marker in ("missing_public_mysql_host", "requires_external_mysql", "php binary not found", "timeout"):
            if marker in preview and marker not in blockers:
                blockers.append(marker)
    return blockers[:10]


def extract_lessons(steps: List[Dict[str, Any]], result: Dict[str, Any]) -> List[str]:
    lessons: List[str] = []
    tools = [step.get("tool") for step in steps if step.get("tool")]
    if tools:
        lessons.append("Tools used: " + " -> ".join(tools[:12]))
    blockers = extract_blockers(steps, result)
    if blockers:
        lessons.append("Blockers: " + "; ".join(blockers))
    if result.get("success"):
        lessons.append("Successful strategy: " + " -> ".join(tools[:12]))
    return lessons[:10]


def extract_crypto_hints(text: str) -> Optional[str]:
    """Scan text for base64, hex, and JWT patterns and return a hint string."""
    import base64
    import json

    hints: List[str] = []

    # Base64
    b64_pattern = re.compile(r'[A-Za-z0-9+/]{40,}={0,2}')
    seen_b64 = set()
    for m in b64_pattern.finditer(text):
        token = m.group()
        if token in seen_b64:
            continue
        seen_b64.add(token)
        try:
            decoded = base64.b64decode(token).decode("utf-8", errors="ignore")
            if decoded and all(32 <= ord(c) < 127 for c in decoded[:30]):
                hints.append(f"base64: {token[:50]} -> {decoded[:80]!r}")
        except Exception:
            pass
        if len(seen_b64) >= 5:
            break

    # Hex
    hex_pattern = re.compile(r'\b[0-9a-fA-F]{32,}\b')
    seen_hex = set()
    for m in hex_pattern.finditer(text):
        token = m.group()
        if token in seen_hex:
            continue
        seen_hex.add(token)
        try:
            decoded = bytes.fromhex(token).decode("utf-8", errors="ignore")
            if decoded and all(32 <= ord(c) < 127 for c in decoded[:30]):
                hints.append(f"hex: {token[:50]} -> {decoded[:80]!r}")
        except Exception:
            pass
        if len(seen_hex) >= 5:
            break

    # JWT
    jwt_pattern = re.compile(r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*')
    seen_jwt = set()
    for m in jwt_pattern.finditer(text):
        token = m.group()
        if token in seen_jwt:
            continue
        seen_jwt.add(token)
        try:
            parts = token.split(".")
            if len(parts) == 3:
                header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
                payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
                payload_str = json.dumps(payload, ensure_ascii=False, default=str)[:200]
                hints.append(f"JWT: header={header} payload={payload_str}")
        except Exception:
            pass
        if len(seen_jwt) >= 3:
            break

    if hints:
        return "Crypto/encoding hints detected:\n" + "\n".join(hints[:8])
    return None
