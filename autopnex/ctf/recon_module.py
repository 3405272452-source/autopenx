"""Recon Module - Attack surface discovery for CTF web challenges.

Discovers target attack surface before exploitation:
- robots.txt and sitemap.xml parsing
- HTML link, form, and JavaScript URL extraction
- JavaScript API endpoint pattern detection

Registered as `recon_scan` tool in the ToolRouter.
"""
from __future__ import annotations

import logging
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List
from urllib.parse import urljoin

import requests

log = logging.getLogger("autopnex.ctf.recon_module")


# ---------------------------------------------------------------------------
# Data Model
# ---------------------------------------------------------------------------


@dataclass
class AttackSurface:
    """Structured report of discovered attack surface."""

    paths: List[str] = field(default_factory=list)
    parameters: Dict[str, List[str]] = field(default_factory=dict)
    js_urls: List[str] = field(default_factory=list)
    api_endpoints: List[str] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    forms: List[Dict[str, Any]] = field(default_factory=list)
    robots_paths: List[str] = field(default_factory=list)
    sitemap_urls: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to plain dictionary."""
        return asdict(self)

    def to_prompt_context(self) -> str:
        """Generate a concise attack surface summary for LLM consumption."""
        lines: List[str] = ["## Attack Surface Summary"]

        if self.paths:
            lines.append(f"\n### Discovered Paths ({len(self.paths)})")
            for p in self.paths[:20]:
                lines.append(f"  - {p}")
            if len(self.paths) > 20:
                lines.append(f"  ... and {len(self.paths) - 20} more")

        if self.parameters:
            lines.append(f"\n### Parameters ({len(self.parameters)} paths)")
            for path, params in list(self.parameters.items())[:10]:
                lines.append(f"  - {path}: {', '.join(params)}")

        if self.api_endpoints:
            lines.append(f"\n### API Endpoints ({len(self.api_endpoints)})")
            for ep in self.api_endpoints[:15]:
                lines.append(f"  - {ep}")

        if self.js_urls:
            lines.append(f"\n### JavaScript Resources ({len(self.js_urls)})")
            for js in self.js_urls[:10]:
                lines.append(f"  - {js}")

        if self.technologies:
            lines.append("\n### Technologies Detected")
            lines.append(f"  {', '.join(self.technologies)}")

        if self.forms:
            lines.append(f"\n### Forms ({len(self.forms)})")
            for form in self.forms[:10]:
                action = form.get("action", "?")
                method = form.get("method", "GET")
                lines.append(f"  - [{method}] {action}")

        if self.robots_paths:
            lines.append(f"\n### robots.txt Paths ({len(self.robots_paths)})")
            for rp in self.robots_paths[:10]:
                lines.append(f"  - {rp}")

        if self.sitemap_urls:
            lines.append(f"\n### Sitemap URLs ({len(self.sitemap_urls)})")
            for su in self.sitemap_urls[:10]:
                lines.append(f"  - {su}")

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Recon Module
# ---------------------------------------------------------------------------


class ReconModule:
    """Entry-point reconnaissance module - discovers target attack surface.

    Usage:
        recon = ReconModule(session, "http://target:8080")
        surface = recon.scan()
        print(surface.to_prompt_context())
    """

    def __init__(self, session: requests.Session, base_url: str) -> None:
        """Initialize the recon module.

        Args:
            session: Requests session for HTTP calls (supports cookies/auth).
            base_url: Target base URL (e.g. "http://target:8080").
        """
        self._session = session
        self._base_url = base_url.rstrip("/")

    @property
    def base_url(self) -> str:
        return self._base_url

    def scan(self) -> AttackSurface:
        """Execute a full reconnaissance scan of the target.

        Orchestrates all sub-methods and aggregates results into an
        AttackSurface report. Errors in individual steps are logged
        and skipped so the scan always completes.

        Returns:
            AttackSurface with all discovered information.
        """
        surface = AttackSurface()

        # 1. Fetch robots.txt
        try:
            surface.robots_paths = self.fetch_robots()
            surface.paths.extend(surface.robots_paths)
        except Exception as exc:
            log.warning("robots.txt fetch failed: %s", exc)

        # 2. Fetch sitemap.xml
        try:
            surface.sitemap_urls = self.fetch_sitemap()
            surface.paths.extend(surface.sitemap_urls)
        except Exception as exc:
            log.warning("sitemap.xml fetch failed: %s", exc)

        # 3. Fetch main page and extract links/forms/JS
        try:
            resp = self._session.get(self._base_url, timeout=10)
            html = resp.text

            links = self.extract_links(html)
            surface.paths.extend(links)

            forms = self.extract_forms(html)
            surface.forms.extend(forms)

            js_urls = self.extract_js_urls(html)
            surface.js_urls.extend(js_urls)
        except Exception as exc:
            log.warning("Main page fetch/parse failed: %s", exc)

        # 4. Scan discovered JS files for API endpoints
        for js_url in list(surface.js_urls):
            try:
                full_url = urljoin(self._base_url + "/", js_url)
                js_resp = self._session.get(full_url, timeout=10)
                apis = self.scan_js_for_apis(js_resp.text)
                surface.api_endpoints.extend(apis)
            except Exception as exc:
                log.warning("JS scan failed for %s: %s", js_url, exc)

        # Deduplicate paths
        surface.paths = list(dict.fromkeys(surface.paths))
        surface.api_endpoints = list(dict.fromkeys(surface.api_endpoints))

        return surface

    # ------------------------------------------------------------------
    # Sub-methods (stubs - to be implemented in tasks 3.2-3.4)
    # ------------------------------------------------------------------

    def fetch_robots(self) -> List[str]:
        """Fetch and parse robots.txt for Disallow/Allow paths.

        GETs {base_url}/robots.txt and extracts paths from Disallow and
        Allow directives. Returns an empty list on 404 or connection errors.

        Returns:
            List of paths found in robots.txt.
        """
        url = f"{self._base_url}/robots.txt"
        try:
            resp = self._session.get(url, timeout=10)
            if resp.status_code == 404:
                return []
            resp.raise_for_status()
        except (requests.RequestException, OSError) as exc:
            log.debug("robots.txt unavailable at %s: %s", url, exc)
            return []

        paths: List[str] = []
        for line in resp.text.splitlines():
            line = line.strip()
            # Skip comments and empty lines
            if not line or line.startswith("#"):
                continue
            # Match Disallow: /path or Allow: /path
            if ":" in line:
                directive, _, value = line.partition(":")
                directive = directive.strip().lower()
                value = value.strip()
                if directive in ("disallow", "allow") and value:
                    paths.append(value)

        return paths

    def fetch_sitemap(self) -> List[str]:
        """Fetch and parse sitemap.xml for URLs.

        GETs {base_url}/sitemap.xml and extracts URLs from <loc> tags.
        Returns an empty list on 404 or connection errors.

        Returns:
            List of URLs found in sitemap.xml.
        """
        url = f"{self._base_url}/sitemap.xml"
        try:
            resp = self._session.get(url, timeout=10)
            if resp.status_code == 404:
                return []
            resp.raise_for_status()
        except (requests.RequestException, OSError) as exc:
            log.debug("sitemap.xml unavailable at %s: %s", url, exc)
            return []

        # Parse <loc>...</loc> tags using regex (avoids XML parser dependency
        # and handles malformed XML gracefully)
        urls: List[str] = re.findall(r"<loc>\s*(.*?)\s*</loc>", resp.text, re.IGNORECASE)
        return urls

    def extract_links(self, html: str) -> List[str]:
        """Extract hyperlinks from HTML content.

        Finds all <a href="..."> patterns and returns the href values.
        Handles single quotes, double quotes, and no quotes around the URL.
        Gracefully handles malformed HTML by returning what can be found.

        Args:
            html: Raw HTML string.

        Returns:
            List of discovered link URLs (deduplicated, order preserved).
        """
        if not html:
            return []

        # Match href attribute with double quotes, single quotes, or no quotes
        pattern = r"""<a\s[^>]*?href\s*=\s*(?:"([^"]*?)"|'([^']*?)'|([^\s>]+))"""
        matches = re.findall(pattern, html, re.IGNORECASE | re.DOTALL)

        links: List[str] = []
        for groups in matches:
            # Each match is a tuple of 3 groups; only one will be non-empty
            href = groups[0] or groups[1] or groups[2]
            href = href.strip()
            if href and not href.startswith(("#", "javascript:")):
                links.append(href)

        # Deduplicate while preserving order
        return list(dict.fromkeys(links))

    def extract_forms(self, html: str) -> List[Dict[str, Any]]:
        """Extract form information from HTML content.

        Finds all <form> elements and extracts their action, method, and
        input fields (name and type). Handles malformed HTML gracefully.

        Args:
            html: Raw HTML string.

        Returns:
            List of form dicts, each containing:
                - action (str): Form action URL (empty string if not specified)
                - method (str): HTTP method, uppercased (defaults to "GET")
                - inputs (List[Dict]): List of {name, type} dicts for each input
        """
        if not html:
            return []

        forms: List[Dict[str, Any]] = []

        # Find all <form ...> ... </form> blocks (non-greedy, DOTALL for multiline)
        form_pattern = r"<form\s([^>]*)>(.*?)</form>"
        form_matches = re.finditer(form_pattern, html, re.IGNORECASE | re.DOTALL)

        for form_match in form_matches:
            attrs_str = form_match.group(1)
            form_body = form_match.group(2)

            # Extract action attribute
            action_match = re.search(
                r"""action\s*=\s*(?:"([^"]*?)"|'([^']*?)'|([^\s>]+))""",
                attrs_str,
                re.IGNORECASE,
            )
            if action_match:
                action = action_match.group(1) or action_match.group(2) or action_match.group(3)
            else:
                action = ""

            # Extract method attribute
            method_match = re.search(
                r"""method\s*=\s*(?:"([^"]*?)"|'([^']*?)'|([^\s>]+))""",
                attrs_str,
                re.IGNORECASE,
            )
            if method_match:
                method = (method_match.group(1) or method_match.group(2) or method_match.group(3)).upper()
            else:
                method = "GET"

            # Extract input fields from form body
            inputs: List[Dict[str, str]] = []
            input_pattern = r"<input\s([^>]*?)/?>"
            for input_match in re.finditer(input_pattern, form_body, re.IGNORECASE | re.DOTALL):
                input_attrs = input_match.group(1)

                # Extract name attribute
                name_match = re.search(
                    r"""name\s*=\s*(?:"([^"]*?)"|'([^']*?)'|([^\s>]+))""",
                    input_attrs,
                    re.IGNORECASE,
                )
                name = ""
                if name_match:
                    name = name_match.group(1) or name_match.group(2) or name_match.group(3)

                # Extract type attribute
                type_match = re.search(
                    r"""type\s*=\s*(?:"([^"]*?)"|'([^']*?)'|([^\s>]+))""",
                    input_attrs,
                    re.IGNORECASE,
                )
                input_type = "text"  # default HTML input type
                if type_match:
                    input_type = (type_match.group(1) or type_match.group(2) or type_match.group(3)).lower()

                if name:
                    inputs.append({"name": name, "type": input_type})

            forms.append({
                "action": action,
                "method": method,
                "inputs": inputs,
            })

        return forms

    def extract_js_urls(self, html: str) -> List[str]:
        """Extract JavaScript source URLs from HTML content.

        Finds all <script src="..."> patterns and returns the src values.
        Handles single quotes, double quotes, and no quotes around the URL.
        Gracefully handles malformed HTML by returning what can be found.

        Args:
            html: Raw HTML string.

        Returns:
            List of JS resource URLs (deduplicated, order preserved).
        """
        if not html:
            return []

        # Match <script ... src="..." ...> with various quoting styles
        pattern = r"""<script\s[^>]*?src\s*=\s*(?:"([^"]*?)"|'([^']*?)'|([^\s>]+))"""
        matches = re.findall(pattern, html, re.IGNORECASE | re.DOTALL)

        urls: List[str] = []
        for groups in matches:
            src = groups[0] or groups[1] or groups[2]
            src = src.strip()
            if src:
                urls.append(src)

        # Deduplicate while preserving order
        return list(dict.fromkeys(urls))

    def scan_js_for_apis(self, js_content: str) -> List[str]:
        """Scan JavaScript content for API endpoint patterns.

        Looks for:
        1. URL paths containing /api/ (e.g. "/api/users", "/api/v1/login")
        2. fetch() call URL arguments
        3. axios call URL arguments (axios.get, axios.post, etc.)
        4. String literals that look like API endpoint paths

        Args:
            js_content: Raw JavaScript source code.

        Returns:
            Deduplicated list of discovered API endpoint paths.
        """
        if not js_content:
            return []

        endpoints: List[str] = []

        # Pattern 1: Paths containing /api/ (in string literals)
        # Matches "/api/...", '/api/...', or `/api/...` (template literals)
        api_path_pattern = r"""(?:["'`])(/api/[^\s"'`<>{}()\[\]]*?)(?:["'`])"""
        for match in re.finditer(api_path_pattern, js_content):
            endpoints.append(match.group(1))

        # Pattern 2: fetch() calls with URL argument
        # Matches fetch("/path"), fetch('/path'), fetch(`/path`)
        fetch_pattern = r"""fetch\s*\(\s*(?:["'`])([^\s"'`<>{}()\[\]]+?)(?:["'`])"""
        for match in re.finditer(fetch_pattern, js_content):
            endpoints.append(match.group(1))

        # Pattern 3: axios method calls (get, post, put, delete, patch)
        # Matches axios.get("/path"), axios.post('/path'), etc.
        axios_pattern = r"""axios\s*\.\s*(?:get|post|put|delete|patch|head|options|request)\s*\(\s*(?:["'`])([^\s"'`<>{}()\[\]]+?)(?:["'`])"""
        for match in re.finditer(axios_pattern, js_content, re.IGNORECASE):
            endpoints.append(match.group(1))

        # Pattern 4: axios() direct call with URL string
        # Matches axios("/path") or axios('/path')
        axios_direct_pattern = r"""axios\s*\(\s*(?:["'`])([^\s"'`<>{}()\[\]]+?)(?:["'`])"""
        for match in re.finditer(axios_direct_pattern, js_content):
            endpoints.append(match.group(1))

        # Pattern 5: Generic string literals that look like API paths
        # Matches paths starting with / that have at least one segment
        # (e.g. "/users", "/v1/auth/login") but not common non-API patterns
        path_literal_pattern = r"""(?:["'`])(/(?:v\d+/)?[a-zA-Z][a-zA-Z0-9_/\-]*?)(?:["'`])"""
        for match in re.finditer(path_literal_pattern, js_content):
            path = match.group(1)
            # Only include paths that look like API endpoints (have multiple segments
            # or are under common API prefixes)
            if "/" in path[1:]:  # has at least one slash after the leading /
                endpoints.append(path)

        # Deduplicate while preserving order
        return list(dict.fromkeys(endpoints))
