"""Lightweight web technology fingerprinting via HTTP headers + HTML signatures."""
from __future__ import annotations

import re
from typing import Any, Dict, List

from ..base import BaseTool, ToolResult, register
from .._http import normalise_target, request


HEADER_SIGNATURES = {
    "server": {
        r"nginx": "Nginx",
        r"apache": "Apache",
        r"iis": "Microsoft IIS",
        r"litespeed": "LiteSpeed",
        r"openresty": "OpenResty",
        r"caddy": "Caddy",
    },
    "x-powered-by": {
        r"php/([\d.]+)?": "PHP",
        r"express": "Express.js",
        r"asp\.net": "ASP.NET",
        r"next\.js": "Next.js",
    },
    "set-cookie": {
        r"phpsessid": "PHP",
        r"jsessionid": "Java EE / Servlet",
        r"asp\.net_sessionid": "ASP.NET",
        r"ci_session": "CodeIgniter",
        r"laravel_session": "Laravel",
        r"connect\.sid": "Express.js",
    },
}


BODY_SIGNATURES = {
    r"wp-content/|wp-includes/|/wp-json/": "WordPress",
    r"drupal-settings-json|/sites/default/files/": "Drupal",
    r"joomla!|/media/jui/": "Joomla",
    r"name=\"generator\" content=\"ghost": "Ghost",
    r"ng-app|ng-controller|angular\.min\.js": "AngularJS",
    r"vue(\.min)?\.js|data-v-[0-9a-f]+": "Vue.js",
    r"react(-dom)?(\.min)?\.js|data-reactroot": "React",
    r"__NEXT_DATA__": "Next.js",
    r"laravel": "Laravel",
    r"csrfmiddlewaretoken|djdt-": "Django",
    r"static/flask_|flask-debug": "Flask",
    r"spring\.io|x-application-context": "Spring",
    r"phpmyadmin": "phpMyAdmin",
    r"bootstrap(\.min)?\.css": "Bootstrap",
    r"jquery(\.min)?\.js|jquery-\d": "jQuery",
}


@register
class TechDetectorTool(BaseTool):
    category = "recon"
    scan_mode_required = "passive"

    @property
    def name(self) -> str:
        return "tech_detect"

    @property
    def description(self) -> str:
        return "Detect the web technology stack of a URL via HTTP headers, cookies and HTML body fingerprints."

    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "URL to fingerprint."},
            },
            "required": ["target"],
        }

    def _run(self, **kwargs: Any) -> ToolResult:
        target = normalise_target(kwargs.get("target", ""))
        if not target:
            return ToolResult(False, self.name, "target required", error="missing_target")
        resp, err, _ = request("GET", target)
        if resp is None:
            return ToolResult(False, self.name, f"request failed: {err}", error=err)

        detected: List[str] = []
        # Header / cookie signatures
        for header_name, rules in HEADER_SIGNATURES.items():
            value = resp.headers.get(header_name, "")
            if not value:
                continue
            for pattern, label in rules.items():
                if re.search(pattern, value, flags=re.IGNORECASE):
                    if label not in detected:
                        detected.append(label)
                    m = re.search(pattern, value, flags=re.IGNORECASE)
                    if m and m.groups() and m.group(1):
                        ver = f"{label} {m.group(1)}"
                        if ver not in detected:
                            detected.append(ver)

        # Body signatures
        body = resp.text if resp.text else ""
        snippet = body[:20000]
        for pattern, label in BODY_SIGNATURES.items():
            if re.search(pattern, snippet, flags=re.IGNORECASE):
                if label not in detected:
                    detected.append(label)

        security_headers = {
            h: resp.headers.get(h, "")
            for h in (
                "content-security-policy",
                "strict-transport-security",
                "x-content-type-options",
                "x-frame-options",
                "referrer-policy",
                "permissions-policy",
            )
        }

        parsed_data = {
            "status": resp.status_code,
            "final_url": resp.url,
            "server": resp.headers.get("server", ""),
            "powered_by": resp.headers.get("x-powered-by", ""),
            "content_type": resp.headers.get("content-type", ""),
            "technologies": detected,
            "security_headers": security_headers,
            "title": _extract_title(body),
        }
        summary = (
            f"{resp.status_code} {parsed_data['content_type']} | server={parsed_data['server']!r} | "
            f"tech={', '.join(detected) if detected else 'unknown'} | title={parsed_data['title']!r}"
        )
        return ToolResult(True, self.name, summary, parsed_data=parsed_data, raw_output=str(dict(resp.headers)))


def _extract_title(html: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", html or "", flags=re.IGNORECASE | re.DOTALL)
    return m.group(1).strip()[:120] if m else ""
