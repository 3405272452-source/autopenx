"""Async directory brute-forcing against a web root using a small built-in wordlist.

Includes SPA / catch-all false-positive mitigation via baseline fingerprinting.
"""
from __future__ import annotations

import asyncio
import hashlib
import uuid
from typing import Any, Dict, List, Optional

import aiohttp

from ..base import BaseTool, ToolResult, register
from .._http import normalise_target
from config.settings import settings
from ...knowledge_base.wordlists import COMMON_DIRS


@register
class DirBusterTool(BaseTool):
    category = "scan"

    @property
    def name(self) -> str:
        return "dir_buster"

    @property
    def description(self) -> str:
        return "Async directory / file brute-forcer against a web root using a small built-in wordlist."

    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "extra_paths": {"type": "array", "items": {"type": "string"}},
                "concurrency": {"type": "integer", "description": "Parallel requests (default 20)."},
            },
            "required": ["target"],
        }

    def _run(self, **kwargs: Any) -> ToolResult:
        target = normalise_target(kwargs.get("target", ""))
        if not target:
            return ToolResult(False, self.name, "target required", error="missing_target")
        extra: List[str] = kwargs.get("extra_paths") or []
        concurrency = int(kwargs.get("concurrency") or 20)
        wordlist = list(dict.fromkeys(COMMON_DIRS + extra))

        # Import global session cookies for authenticated scanning
        from .._http import get_session_cookies
        extra_cookies = get_session_cookies()

        hits = asyncio.run(_run_scan(target, wordlist, concurrency, cookies=extra_cookies))
        summary = f"{len(hits)} interesting paths out of {len(wordlist)} probed."
        raw = "\n".join(f"{h['status']} {h['url']} ({h['size']}B)" for h in hits)
        return ToolResult(
            True,
            self.name,
            summary,
            parsed_data={"hits": hits, "probed": len(wordlist)},
            raw_output=raw,
        )


async def _probe_baseline(session: aiohttp.ClientSession, base: str) -> Optional[str]:
    """Fetch a random nonexistent path; return SHA-256 of body if server returns 200."""
    canary = f"/__autopenx_canary_{uuid.uuid4().hex[:8]}"
    url = f"{base}/{canary}"
    try:
        async with session.get(url, allow_redirects=False, timeout=settings.http_timeout) as resp:
            if resp.status != 200:
                return None
            body = await resp.content.read(8192)
            return hashlib.sha256(body).hexdigest()
    except Exception:  # noqa: BLE001
        return None


async def _fetch(
    session: aiohttp.ClientSession,
    url: str,
    baseline_hash: Optional[str],
) -> Optional[Dict[str, Any]]:
    try:
        async with session.get(url, allow_redirects=False, timeout=settings.http_timeout) as resp:
            body = await resp.content.read(8192)
            size = int(resp.headers.get("content-length") or len(body or b""))
            if resp.status in (200, 204, 301, 302, 401, 403):
                text = body.decode("utf-8", errors="replace").lower() if body else ""
                if resp.status == 200 and ("not found" in text and size < 400):
                    return None
                if resp.status == 200 and baseline_hash:
                    if hashlib.sha256(body).hexdigest() == baseline_hash:
                        return None
                    ct = resp.headers.get("content-type", "").lower()
                    if "text/html" in ct and ("<!doctype" in text or "<html" in text):
                        return None
                return {"url": url, "status": resp.status, "size": size}
    except Exception:  # noqa: BLE001
        return None
    return None


async def _run_scan(base: str, wordlist: List[str], concurrency: int, cookies: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
    sem = asyncio.Semaphore(concurrency)
    connector = aiohttp.TCPConnector(ssl=False, limit=concurrency * 2)
    headers = {"User-Agent": settings.user_agent}
    cookie_jar = aiohttp.CookieJar()
    results: List[Dict[str, Any]] = []

    async with aiohttp.ClientSession(connector=connector, headers=headers, cookie_jar=cookie_jar) as session:
        # Inject authenticated cookies
        if cookies:
            for name, value in cookies.items():
                session.cookie_jar.update_cookies({name: value})
        baseline_hash = await _probe_baseline(session, base)

        async def _bounded(path: str):
            async with sem:
                url = f"{base}/{path.lstrip('/')}"
                return await _fetch(session, url, baseline_hash)

        gathered = await asyncio.gather(*[_bounded(p) for p in wordlist])
        for g in gathered:
            if g:
                results.append(g)
    return results
