"""JavaScript content analyzer for CTF Web challenges.

Extracts API endpoints, secrets/tokens, source map references, and
frontend route definitions from JavaScript bundle content. Used by
ReconAgent to discover hidden attack surface in modern web applications.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional


# --- API endpoint patterns ---

# Matches string literals containing /api/ paths
_API_PATH_RE = re.compile(
    r"""['"`](/api/[^'"`\s}{]+)['"`]""",
    re.IGNORECASE,
)

# Matches fetch("url") or fetch('url') calls
_FETCH_RE = re.compile(
    r"""\bfetch\s*\(\s*['"`]([^'"`\s]+)['"`]""",
    re.IGNORECASE,
)

# Matches axios.get/post/put/delete/patch("url") calls
_AXIOS_RE = re.compile(
    r"""\baxios\s*\.\s*(?:get|post|put|delete|patch|request|head|options)\s*\(\s*['"`]([^'"`\s]+)['"`]""",
    re.IGNORECASE,
)

# Matches XMLHttpRequest .open("METHOD", "url") calls
_XHR_RE = re.compile(
    r"""\.open\s*\(\s*['"`]\w+['"`]\s*,\s*['"`]([^'"`\s]+)['"`]""",
    re.IGNORECASE,
)

# Matches baseURL or base_url assignments
_BASE_URL_RE = re.compile(
    r"""\b(?:baseURL|base_url|apiUrl|API_URL|apiBase|API_BASE)\s*[:=]\s*['"`]([^'"`\s]+)['"`]""",
    re.IGNORECASE,
)

# --- Secret/token patterns ---

_SECRET_PATTERNS: List[Dict[str, re.Pattern[str]]] = [
    {
        "type": "api_key",
        "pattern": re.compile(
            r"""['"`]?(?:api[_-]?key|apikey|api[_-]?secret)\s*['"`]?\s*[:=]\s*['"`]([A-Za-z0-9_\-]{16,})['"`]""",
            re.IGNORECASE,
        ),
    },
    {
        "type": "jwt_secret",
        "pattern": re.compile(
            r"""['"`]?(?:jwt[_-]?secret|secret[_-]?key|signing[_-]?key|SECRET_KEY)\s*['"`]?\s*[:=]\s*['"`]([^'"`]{4,})['"`]""",
            re.IGNORECASE,
        ),
    },
    {
        "type": "bearer_token",
        "pattern": re.compile(
            r"""['"`]Bearer\s+([A-Za-z0-9_\-\.]{20,})['"`]""",
        ),
    },
    {
        "type": "authorization_header",
        "pattern": re.compile(
            r"""['"`]?(?:Authorization|auth[_-]?token|access[_-]?token)\s*['"`]?\s*[:=]\s*['"`]([A-Za-z0-9_\-\.]{16,})['"`]""",
            re.IGNORECASE,
        ),
    },
    {
        "type": "aws_key",
        "pattern": re.compile(
            r"""(?:AKIA[0-9A-Z]{16})""",
        ),
    },
    {
        "type": "private_key",
        "pattern": re.compile(
            r"""-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----""",
        ),
    },
    {
        "type": "password",
        "pattern": re.compile(
            r"""['"`]?(?:password|passwd|pwd)\s*['"`]?\s*[:=]\s*['"`]([^'"`]{4,})['"`]""",
            re.IGNORECASE,
        ),
    },
    {
        "type": "database_url",
        "pattern": re.compile(
            r"""['"`]((?:mysql|postgres|mongodb|redis)://[^'"`\s]+)['"`]""",
            re.IGNORECASE,
        ),
    },
]

# --- Source map pattern ---

_SOURCE_MAP_RE = re.compile(
    r"""//[#@]\s*sourceMappingURL\s*=\s*(\S+)""",
)

# --- Frontend route patterns ---

# React Router: <Route path="/xxx" ... /> or path: "/xxx"
_REACT_ROUTE_RE = re.compile(
    r"""<Route\s+[^>]*path\s*=\s*['"`]([^'"`]+)['"`]""",
    re.IGNORECASE,
)

# Vue Router: { path: '/xxx', ... }
_VUE_ROUTE_RE = re.compile(
    r"""\bpath\s*:\s*['"`]([^'"`]+)['"`]""",
)

# Angular Router: { path: 'xxx', ... } (no leading slash typically)
_ANGULAR_ROUTE_RE = re.compile(
    r"""\bpath\s*:\s*['"`]([^'"`]+)['"`]""",
)

# Next.js / file-based routing patterns in imports
_NEXTJS_ROUTE_RE = re.compile(
    r"""['"`](/pages?/[^'"`]+)['"`]""",
)


@dataclass
class JSAnalyzer:
    """Analyzes JavaScript content to extract security-relevant information."""

    def extract_api_endpoints(self, js_content: str) -> List[str]:
        """Extract API endpoint URLs from JavaScript content.

        Matches:
        - /api/... path patterns in string literals
        - fetch() call URLs
        - axios method call URLs
        - XMLHttpRequest .open() URLs
        - baseURL / API_URL assignments

        Returns deduplicated list of endpoint strings.
        """
        endpoints: set[str] = set()

        for match in _API_PATH_RE.finditer(js_content):
            endpoints.add(match.group(1))

        for match in _FETCH_RE.finditer(js_content):
            endpoints.add(match.group(1))

        for match in _AXIOS_RE.finditer(js_content):
            endpoints.add(match.group(1))

        for match in _XHR_RE.finditer(js_content):
            url = match.group(1)
            # Only include if it looks like an API path (not a full external URL to CDN etc.)
            if url.startswith("/") or "api" in url.lower():
                endpoints.add(url)

        for match in _BASE_URL_RE.finditer(js_content):
            endpoints.add(match.group(1))

        return sorted(endpoints)

    def extract_secrets(self, js_content: str) -> List[Dict[str, str]]:
        """Extract potential secrets, API keys, tokens from JavaScript content.

        Returns list of dicts with keys: type, value, context.
        """
        secrets: List[Dict[str, str]] = []
        seen: set[str] = set()

        for entry in _SECRET_PATTERNS:
            secret_type = entry["type"]
            pattern = entry["pattern"]
            for match in pattern.finditer(js_content):
                value = match.group(1) if match.lastindex else match.group(0)
                if value in seen:
                    continue
                seen.add(value)

                # Extract surrounding context (up to 80 chars around match)
                start = max(0, match.start() - 20)
                end = min(len(js_content), match.end() + 20)
                context = js_content[start:end].replace("\n", " ").strip()

                secrets.append({
                    "type": secret_type,
                    "value": value,
                    "context": context,
                })

        return secrets

    def detect_source_map(self, js_content: str) -> Optional[str]:
        """Detect sourceMappingURL comment in JavaScript content.

        Returns the source map URL/path if found, None otherwise.
        """
        match = _SOURCE_MAP_RE.search(js_content)
        if match:
            return match.group(1)
        return None

    def extract_routes(self, js_content: str) -> List[str]:
        """Extract frontend route definitions from JavaScript content.

        Matches React Router, Vue Router, Angular Router, and Next.js patterns.
        Returns deduplicated list of route path strings.
        """
        routes: set[str] = set()

        for match in _REACT_ROUTE_RE.finditer(js_content):
            routes.add(match.group(1))

        for match in _VUE_ROUTE_RE.finditer(js_content):
            path = match.group(1)
            # Filter out non-route paths (must start with / or be a relative segment)
            if path.startswith("/") or not any(c in path for c in ".:{}[]"):
                routes.add(path)

        for match in _NEXTJS_ROUTE_RE.finditer(js_content):
            routes.add(match.group(1))

        return sorted(routes)
