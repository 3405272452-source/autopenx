"""Burp proxy-assisted request adapter."""
from __future__ import annotations

from typing import Any, Dict

from config.settings import RuntimeConfig, settings

from .._http import normalise_target, request
from ..base import BaseTool, ToolResult, register


@register
class BurpProxyScanTool(BaseTool):
    category = "scan"
    managed_external = True
    required_capability = "active_scan"

    @property
    def name(self) -> str:
        return "burp_proxy_scan"

    @property
    def description(self) -> str:
        return (
            "Replay a target request through a configured Burp proxy to capture traffic and surface "
            "response metadata. Requires AUTOPENX_BURP_PROXY_URL plus active-scan approval."
        )

    def availability(self, runtime_config: RuntimeConfig | None = None) -> Dict[str, Any]:
        runtime = runtime_config or settings.effective()
        scope_allowed = "active_scan" in runtime.approved_scopes or "exploit" in runtime.approved_scopes
        enabled = bool(runtime.allow_external_tools and runtime.burp_proxy_url and scope_allowed)
        if not runtime.burp_proxy_url:
            reason = "missing_burp_proxy_url"
        elif not runtime.allow_external_tools:
            reason = "disabled_by_runtime_config"
        elif not scope_allowed:
            reason = "missing_capability:active_scan"
        else:
            reason = "enabled"
        return {
            "name": self.name,
            "category": self.category,
            "external": True,
            "binary": "burp-proxy",
            "binary_path": runtime.burp_proxy_url or None,
            "installed": bool(runtime.burp_proxy_url),
            "allowed": runtime.allow_external_tools,
            "required_capability": self.required_capability,
            "scope_allowed": scope_allowed,
            "exploit_allowed": True,
            "enabled": enabled,
            "reason": reason,
        }

    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Full target URL to replay through Burp proxy."},
                "method": {"type": "string", "enum": ["GET", "POST"], "description": "HTTP method."},
            },
            "required": ["target"],
        }

    def _run(self, **kwargs: Any) -> ToolResult:
        runtime = settings.effective()
        target = normalise_target(kwargs.get("target", ""))
        method = (kwargs.get("method") or "GET").upper()
        resp, err, elapsed = request(
            method,
            target,
            timeout=runtime.http_timeout,
            headers={"X-AutoPenX-Proxy": "burp"},
            proxies={"http": runtime.burp_proxy_url, "https": runtime.burp_proxy_url},
        )
        if resp is None:
            return ToolResult(False, self.name, f"burp proxied request failed: {err}", error=str(err))
        summary = f"Burp replayed {method} {target} -> HTTP {resp.status_code} in {elapsed:.2f}s"
        return ToolResult(
            success=True,
            tool=self.name,
            summary=summary,
            raw_output=(resp.text or "")[:2000],
            parsed_data={
                "url": target,
                "status": resp.status_code,
                "headers": dict(resp.headers),
                "content_length": len(resp.text or ""),
                "scanner": "burp_proxy",
            },
        )
