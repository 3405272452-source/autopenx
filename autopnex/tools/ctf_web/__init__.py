"""CTF web exploitation tools package.

Provides SSTI detection, LFI/RFI detection, PHP unserialize detection,
and flag file reading tools for CTF web challenges.
"""
from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional

from autopnex.tools.base import ToolRegistry
from .ssti_detect import SSTIDetectTool
from .lfi_detect import LFIDetectTool
from .unserialize_detect import UnserializeDetectTool
from .flag_reader import FlagReaderTool
from .phar_pdo_chain import PharPDOChainTool
from .ctf_mysql_helper import CTFMySQLHelperTool
from .ctf_tunnel_helper import CTFTunnelHelperTool
from .ctf_tool_manager import CTFToolManagerTool

ToolRegistry.register(SSTIDetectTool)
ToolRegistry.register(LFIDetectTool)
ToolRegistry.register(UnserializeDetectTool)
ToolRegistry.register(FlagReaderTool)
ToolRegistry.register(PharPDOChainTool)
ToolRegistry.register(CTFMySQLHelperTool)
ToolRegistry.register(CTFTunnelHelperTool)
ToolRegistry.register(CTFToolManagerTool)


# ---------------------------------------------------------------------------
# Async convenience wrappers
# ---------------------------------------------------------------------------

async def ssti_detect(url: str, param: str, engine: str = "auto") -> dict:
    """Detect SSTI vulnerabilities asynchronously.

    Args:
        url: Target URL to test.
        param: Query/form parameter name to inject into.
        engine: Template engine hint ('auto' to test all).

    Returns:
        Dict with keys: vulnerable, engine, payload, response.
    """
    tool = SSTIDetectTool()
    result = await asyncio.to_thread(tool._run, url=url, param=param)
    pd = result.parsed_data
    return {
        "vulnerable": pd.get("vulnerable", False),
        "engine": pd.get("engine", ""),
        "payload": pd.get("payload", ""),
        "response": result.raw_output,
    }


async def lfi_detect(url: str, param: str, depth: int = 5) -> dict:
    """Detect LFI/RFI vulnerabilities asynchronously.

    Args:
        url: Target URL to test.
        param: Query/form parameter name to inject file paths into.
        depth: Maximum directory traversal depth.

    Returns:
        Dict with keys: vulnerable, payload, content, technique.
    """
    tool = LFIDetectTool()
    result = await asyncio.to_thread(tool._run, url=url, param=param)
    pd = result.parsed_data
    return {
        "vulnerable": pd.get("vulnerable", False),
        "payload": pd.get("payload", ""),
        "content": pd.get("file_content_excerpt", ""),
        "technique": pd.get("payload_type", ""),
    }


async def unserialize_detect(url: str, param: str) -> dict:
    """Detect PHP unserialize vulnerabilities asynchronously.

    Args:
        url: Target URL to test.
        param: Parameter name to inject serialized payloads into.

    Returns:
        Dict with keys: vulnerable, payload, response.
    """
    tool = UnserializeDetectTool()
    result = await asyncio.to_thread(tool._run, url=url, param=param)
    pd = result.parsed_data
    return {
        "vulnerable": pd.get("vulnerable", False),
        "payload": pd.get("indicators", [""])[0] if pd.get("indicators") else "",
        "response": result.raw_output,
    }


async def flag_reader(url: str, paths: Optional[List[str]] = None) -> dict:
    """Read flag files from a target web application asynchronously.

    Args:
        url: Target base URL of the web application.
        paths: Optional list of custom flag paths to try.

    Returns:
        Dict with keys: found, flag, path, method.
    """
    tool = FlagReaderTool()
    result = await asyncio.to_thread(tool._run, url=url)
    pd = result.parsed_data
    return {
        "found": pd.get("found", False),
        "flag": pd.get("flag", ""),
        "path": pd.get("path", ""),
        "method": pd.get("method", ""),
    }


# ---------------------------------------------------------------------------
# CTF_WEB_TOOLS registry mapping tool names to async functions
# ---------------------------------------------------------------------------

CTF_WEB_TOOLS: Dict[str, Any] = {
    "ssti_detect": ssti_detect,
    "lfi_detect": lfi_detect,
    "unserialize_detect": unserialize_detect,
    "flag_reader": flag_reader,
}


__all__ = [
    "SSTIDetectTool",
    "LFIDetectTool",
    "UnserializeDetectTool",
    "FlagReaderTool",
    "PharPDOChainTool",
    "CTFMySQLHelperTool",
    "CTFTunnelHelperTool",
    "CTFToolManagerTool",
    "ssti_detect",
    "lfi_detect",
    "unserialize_detect",
    "flag_reader",
    "CTF_WEB_TOOLS",
]
