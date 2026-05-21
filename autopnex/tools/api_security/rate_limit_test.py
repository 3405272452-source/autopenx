"""Rate limiting, timing attack, and race condition tester.

Inspired by Shannon's shannon-rate-limit tool. Tests for missing rate limits,
user enumeration via timing differences, and race conditions.
"""
from __future__ import annotations

import asyncio
import statistics
import time
from typing import Any, Dict, List

from ..base import BaseTool, ToolResult, register
from .._http import normalise_target, request


@register
class RateLimitTestTool(BaseTool):
    category = "vuln"

    @property
    def name(self) -> str:
        return "rate_limit_test"

    @property
    def description(self) -> str:
        return (
            "Test rate limiting, timing attacks, and race conditions. "
            "Modes: 'burst' (rapid requests to detect rate limits), "
            "'timing' (response time comparison for user enumeration), "
            "'race' (concurrent requests for race conditions like coupon redemption)."
        )

    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target URL to test.",
                },
                "action": {
                    "type": "string",
                    "enum": ["burst", "timing", "race"],
                    "description": "Test type: burst, timing, or race.",
                },
                "requests_count": {
                    "type": "number",
                    "description": "Number of requests for burst test (default: 50).",
                },
                "concurrent": {
                    "type": "number",
                    "description": "Concurrent requests for race test (default: 10).",
                },
                "method": {
                    "type": "string",
                    "enum": ["GET", "POST"],
                    "description": "HTTP method (default: GET).",
                },
                "body": {
                    "type": "string",
                    "description": "Request body for POST requests.",
                },
                "headers": {
                    "type": "string",
                    "description": "JSON string of additional headers.",
                },
                "valid_input": {
                    "type": "string",
                    "description": "For timing test: request body with valid credentials.",
                },
                "invalid_input": {
                    "type": "string",
                    "description": "For timing test: request body with invalid credentials.",
                },
            },
            "required": ["target", "action"],
        }

    def _run(self, **kwargs: Any) -> ToolResult:
        target = normalise_target(kwargs.get("target", ""))
        action = kwargs.get("action", "burst")

        if not target:
            return ToolResult(False, self.name, "target required", error="missing_args")

        if action == "burst":
            return self._burst_test(kwargs)
        elif action == "timing":
            return self._timing_test(kwargs)
        elif action == "race":
            return self._race_test(kwargs)
        else:
            return ToolResult(False, self.name, f"Unknown action: {action}", error="invalid_action")

    def _burst_test(self, kwargs: Dict) -> ToolResult:
        target = normalise_target(kwargs.get("target", ""))
        count = int(kwargs.get("requests_count", 50))
        method = (kwargs.get("method") or "GET").upper()
        body = kwargs.get("body")
        headers = self._parse_headers(kwargs.get("headers"))

        responses: List[Dict[str, Any]] = []
        blocked_count = 0
        success_count = 0

        for i in range(count):
            resp, err, elapsed = request(
                method, target,
                data=body if method == "POST" else None,
                headers=headers,
            )
            if resp is None:
                responses.append({"index": i, "error": err})
                continue

            is_blocked = resp.status_code in (429, 403, 503)
            if is_blocked:
                blocked_count += 1

            if resp.status_code == 200:
                success_count += 1

            responses.append({
                "index": i,
                "status": resp.status_code,
                "elapsed_ms": int(elapsed * 1000),
                "blocked": is_blocked,
            })

        has_rate_limit = blocked_count > 0
        summary = (
            f"Burst test: {success_count}/{count} succeeded, "
            f"{blocked_count} blocked (rate limit {'detected' if has_rate_limit else 'NOT detected'})"
        )

        return ToolResult(
            success=True,
            tool=self.name,
            summary=summary,
            parsed_data={
                "action": "burst",
                "target": target,
                "total_requests": count,
                "success_count": success_count,
                "blocked_count": blocked_count,
                "rate_limit_detected": has_rate_limit,
                "rate_limit_threshold": count - blocked_count if has_rate_limit else None,
                "severity": "MEDIUM" if not has_rate_limit else "INFO",
            },
        )

    def _timing_test(self, kwargs: Dict) -> ToolResult:
        target = normalise_target(kwargs.get("target", ""))
        valid_input = kwargs.get("valid_input", "")
        invalid_input = kwargs.get("invalid_input", "")
        method = (kwargs.get("method") or "POST").upper()
        iterations = 10

        if not valid_input or not invalid_input:
            return ToolResult(False, self.name, "valid_input and invalid_input required for timing test", error="missing_args")

        import json
        try:
            valid_data = json.loads(valid_input) if valid_input.startswith("{") else valid_input
            invalid_data = json.loads(invalid_input) if invalid_input.startswith("{") else invalid_input
        except json.JSONDecodeError:
            valid_data = valid_input
            invalid_data = invalid_input

        valid_times: List[float] = []
        invalid_times: List[float] = []

        for _ in range(iterations):
            _, _, elapsed_v = request(method, target, data=valid_data)
            valid_times.append(elapsed_v * 1000)

            _, _, elapsed_i = request(method, target, data=invalid_data)
            invalid_times.append(elapsed_i * 1000)

        avg_valid = statistics.mean(valid_times)
        avg_invalid = statistics.mean(invalid_times)
        diff_ms = abs(avg_valid - avg_invalid)
        diff_pct = (diff_ms / max(avg_valid, avg_invalid)) * 100 if max(avg_valid, avg_invalid) > 0 else 0

        # Significant if >20% difference
        timing_vuln = diff_pct > 20

        summary = (
            f"Timing test: valid avg={avg_valid:.0f}ms, invalid avg={avg_invalid:.0f}ms, "
            f"diff={diff_ms:.0f}ms ({diff_pct:.0f}%) — "
            f"{'user enumeration POSSIBLE' if timing_vuln else 'no significant timing difference'}"
        )

        return ToolResult(
            success=timing_vuln,
            tool=self.name,
            summary=summary,
            parsed_data={
                "action": "timing",
                "target": target,
                "avg_valid_ms": round(avg_valid, 1),
                "avg_invalid_ms": round(avg_invalid, 1),
                "diff_ms": round(diff_ms, 1),
                "diff_pct": round(diff_pct, 1),
                "timing_vulnerability": timing_vuln,
                "severity": "MEDIUM" if timing_vuln else "INFO",
            },
        )

    def _race_test(self, kwargs: Dict) -> ToolResult:
        target = normalise_target(kwargs.get("target", ""))
        concurrent = int(kwargs.get("concurrent", 10))
        method = (kwargs.get("method") or "POST").upper()
        body = kwargs.get("body")
        headers = self._parse_headers(kwargs.get("headers"))

        results = asyncio.run(self._concurrent_requests(target, method, body, headers, concurrent))

        success_codes = [r for r in results if r.get("status") == 200]
        all_success = len(success_codes) > 1

        summary = (
            f"Race test: {len(success_codes)}/{concurrent} concurrent requests succeeded — "
            f"{'race condition POSSIBLE' if all_success else 'no race condition detected'}"
        )

        return ToolResult(
            success=all_success,
            tool=self.name,
            summary=summary,
            parsed_data={
                "action": "race",
                "target": target,
                "concurrent": concurrent,
                "success_count": len(success_codes),
                "results": results,
                "race_condition": all_success,
                "severity": "HIGH" if all_success else "INFO",
            },
        )

    async def _concurrent_requests(self, target, method, body, headers, count) -> List[Dict]:
        import aiohttp

        results = []
        async with aiohttp.ClientSession() as session:
            tasks = []
            for i in range(count):
                tasks.append(self._single_request(session, target, method, body, headers, i))
            results = await asyncio.gather(*tasks, return_exceptions=True)

        return [r for r in results if isinstance(r, dict)]

    async def _single_request(self, session, target, method, body, headers, index) -> Dict:
        try:
            start = time.perf_counter()
            kwargs = {"ssl": False}
            if headers:
                kwargs["headers"] = headers

            if method == "POST":
                async with session.post(target, data=body, **kwargs) as resp:
                    await resp.read()
                    elapsed = (time.perf_counter() - start) * 1000
                    return {"index": index, "status": resp.status, "elapsed_ms": round(elapsed, 1)}
            else:
                async with session.get(target, **kwargs) as resp:
                    await resp.read()
                    elapsed = (time.perf_counter() - start) * 1000
                    return {"index": index, "status": resp.status, "elapsed_ms": round(elapsed, 1)}
        except Exception as exc:
            return {"index": index, "error": str(exc)}

    def _parse_headers(self, headers_str: str | None) -> Dict[str, str] | None:
        if not headers_str:
            return None
        import json
        try:
            return json.loads(headers_str)
        except json.JSONDecodeError:
            return None
