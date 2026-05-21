"""JavaScript bundle analyzer — detect secrets, XSS sinks, and API endpoints.

Inspired by Shannon's shannon-js-analyze tool. Scans JS files for security issues
including hardcoded credentials, dangerous DOM operations, and exposed API routes.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

from ..base import BaseTool, ToolResult, register
from .._http import normalise_target, request


# Patterns for detecting security issues in JS
PATTERNS = {
    "api_keys": [
        r'(?:api[_-]?key|apikey)\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']',
        r'(?:secret|token)\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']',
        r'(?:aws_access_key_id|aws_secret_access_key)\s*[:=]\s*["\']([A-Za-z0-9/+=]{20,})["\']',
        r'AIza[0-9A-Za-z_\-]{35}',  # Google API key
        r'sk-[A-Za-z0-9]{32,}',  # OpenAI key
        r'ghp_[A-Za-z0-9]{36}',  # GitHub token
    ],
    "xss_sinks": [
        r'\.innerHTML\s*=',
        r'\.outerHTML\s*=',
        r'document\.write\s*\(',
        r'document\.writeln\s*\(',
        r'\.insertAdjacentHTML\s*\(',
        r'eval\s*\(',
        r'new\s+Function\s*\(',
        r'setTimeout\s*\(\s*["\']',
        r'setInterval\s*\(\s*["\']',
        r'\.html\s*\(',  # jQuery .html()
    ],
    "api_endpoints": [
        r'["\']/(api|v[12]|rest|graphql)[^"\']{3,80}["\']',
        r'(?:fetch|axios|ajax)\s*\(\s*["\']([^"\']+)["\']',
        r'(?:get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']',
        r'baseURL\s*[:=]\s*["\']([^"\']+)["\']',
    ],
    "credentials": [
        r'(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\']{3,})["\']',
        r'(?:username|user)\s*[:=]\s*["\']([^"\']{3,})["\']',
        r'(?:Bearer|Basic)\s+[A-Za-z0-9_\-\.=]{20,}',
    ],
    "sensitive_comments": [
        r'//\s*(?:TODO|FIXME|HACK|BUG|XXX)\s*:?\s*(.+)',
        r'/\*\s*(?:password|secret|key|token)\s*(.+?)\s*\*/',
    ],
    "file_paths": [
        r'(?:/etc/(?:passwd|shadow|hosts))',
        r'(?:C:\\\\[Ww]indows\\\\)',
        r'(?:\.env|\.git|\.svn|\.hg)',
        r'(?:config|secret|credential)\.(?:json|yaml|yml|xml|properties)',
    ],
}


@register
class JsAnalyzeTool(BaseTool):
    category = "scan"

    @property
    def name(self) -> str:
        return "js_analyze"

    @property
    def description(self) -> str:
        return (
            "Analyze JavaScript bundles for security issues: hardcoded API keys, "
            "credentials, XSS sinks (innerHTML, eval, document.write), exposed "
            "API endpoints, sensitive file paths, and security-relevant comments."
        )

    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target URL for context.",
                },
                "url": {
                    "type": "string",
                    "description": "URL of the JS file to analyze.",
                },
                "content": {
                    "type": "string",
                    "description": "Direct JS content to analyze (alternative to url).",
                },
            },
            "required": ["target"],
        }

    def _run(self, **kwargs: Any) -> ToolResult:
        target = normalise_target(kwargs.get("target", ""))
        url = kwargs.get("url", "")
        content = kwargs.get("content", "")

        if not target:
            return ToolResult(False, self.name, "target required", error="missing_args")

        # Fetch JS content if URL provided
        if url and not content:
            resp, err, _ = request("GET", url)
            if resp is None:
                return ToolResult(False, self.name, f"Failed to fetch JS: {err}", error=err)
            content = resp.text or ""

        if not content:
            # Try common JS bundle paths
            for path in ["/main.js", "/bundle.js", "/app.js", "/static/js/main.js"]:
                resp, err, _ = request("GET", target.rstrip("/") + path)
                if resp and resp.status_code == 200 and len(resp.text) > 100:
                    content = resp.text
                    url = target.rstrip("/") + path
                    break

        if not content:
            return ToolResult(False, self.name, "No JS content to analyze", error="no_content")

        # Analyze content
        findings: Dict[str, List[Dict[str, Any]]] = {}
        total_issues = 0

        for category, patterns in PATTERNS.items():
            category_hits = []
            for pattern in patterns:
                for match in re.finditer(pattern, content, re.IGNORECASE):
                    # Get surrounding context
                    start = max(0, match.start() - 30)
                    end = min(len(content), match.end() + 30)
                    context = content[start:end].replace("\n", " ").strip()

                    category_hits.append({
                        "pattern": pattern[:50],
                        "match": match.group(0)[:100],
                        "context": context[:200],
                        "position": match.start(),
                    })
            if category_hits:
                # Deduplicate by match text
                seen = set()
                unique_hits = []
                for hit in category_hits:
                    key = hit["match"][:50]
                    if key not in seen:
                        seen.add(key)
                        unique_hits.append(hit)
                findings[category] = unique_hits[:20]
                total_issues += len(unique_hits)

        has_critical = bool(findings.get("api_keys") or findings.get("credentials"))
        success = total_issues > 0
        summary = f"JS analysis: {total_issues} issues found in {url or 'provided content'}"

        return ToolResult(
            success=success,
            tool=self.name,
            summary=summary,
            parsed_data={
                "target": target,
                "url": url,
                "findings": findings,
                "total_issues": total_issues,
                "has_critical_secrets": has_critical,
                "categories": list(findings.keys()),
                "severity": "HIGH" if has_critical else ("MEDIUM" if success else "INFO"),
            },
            raw_output=str(findings)[:3000],
        )
