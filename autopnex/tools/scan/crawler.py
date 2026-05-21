"""Same-origin BFS crawler that discovers pages, forms and query parameters."""
from __future__ import annotations

from collections import deque
from typing import Any, Dict, List, Set
from urllib.parse import urljoin, urlparse, parse_qsl

from bs4 import BeautifulSoup

from ..base import BaseTool, ToolResult, register
from .._http import normalise_target, request


@register
class CrawlerTool(BaseTool):
    category = "scan"
    scan_mode_required = "passive"

    @property
    def name(self) -> str:
        return "crawl"

    @property
    def description(self) -> str:
        return (
            "Same-origin breadth-first crawler. Discovers pages, HTML forms and URL query "
            "parameters so downstream vuln detectors know where to inject payloads."
        )

    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "max_pages": {"type": "integer", "description": "Default 25."},
                "max_depth": {"type": "integer", "description": "Default 2."},
            },
            "required": ["target"],
        }

    def _run(self, **kwargs: Any) -> ToolResult:
        target = normalise_target(kwargs.get("target", ""))
        if not target:
            return ToolResult(False, self.name, "target required", error="missing_target")
        max_pages = int(kwargs.get("max_pages") or 25)
        max_depth = int(kwargs.get("max_depth") or 2)

        origin = urlparse(target).netloc
        visited: Set[str] = set()
        queue: deque = deque([(target, 0)])
        pages: List[str] = []
        forms: List[Dict[str, Any]] = []
        parameters: List[Dict[str, Any]] = []

        while queue and len(pages) < max_pages:
            url, depth = queue.popleft()
            if url in visited or depth > max_depth:
                continue
            visited.add(url)
            resp, err, _ = request("GET", url, allow_redirects=True)
            if resp is None or resp.status_code >= 400:
                continue
            # Skip login pages — the global session already has auth cookies
            final_url = (resp.url or url).lower()
            body_lower = (resp.text or "").lower()[:2000]
            _login_hints = ("login", "signin", "sign-in", "log in")
            if any(hint in final_url for hint in _login_hints) and "logout" not in body_lower:
                continue
            pages.append(url)

            # Parameters directly on URL
            qs = parse_qsl(urlparse(url).query, keep_blank_values=True)
            for k, _v in qs:
                parameters.append({"url": url, "name": k, "method": "GET"})

            ctype = resp.headers.get("content-type", "")
            if "html" not in ctype.lower():
                continue
            soup = BeautifulSoup(resp.text or "", "lxml")

            # Forms
            for form in soup.find_all("form"):
                action = urljoin(url, form.get("action") or url)
                method = (form.get("method") or "GET").upper()
                inputs = []
                for inp in form.find_all(["input", "textarea", "select"]):
                    name = inp.get("name")
                    if not name:
                        continue
                    inputs.append(
                        {
                            "name": name,
                            "type": (inp.get("type") or "text"),
                            "value": inp.get("value") or "",
                        }
                    )
                    parameters.append({"url": action, "name": name, "method": method})
                if inputs:
                    forms.append({"url": action, "method": method, "inputs": inputs})

            # Follow same-origin links
            for a in soup.find_all("a", href=True):
                nxt = urljoin(url, a["href"].split("#", 1)[0])
                if urlparse(nxt).netloc != origin:
                    continue
                if nxt not in visited:
                    queue.append((nxt, depth + 1))

        # Deduplicate
        dedup_params: List[Dict[str, Any]] = []
        seen = set()
        for p in parameters:
            key = (p["url"], p["name"], p["method"])
            if key in seen:
                continue
            seen.add(key)
            dedup_params.append(p)

        summary = f"crawled {len(pages)} pages, {len(forms)} forms, {len(dedup_params)} unique params"
        return ToolResult(
            True,
            self.name,
            summary,
            parsed_data={"pages": pages, "forms": forms, "parameters": dedup_params},
            raw_output="\n".join(pages),
        )
