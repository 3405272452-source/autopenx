"""Strict Web Benchmark — registry of targets that map to challenges.py.

Each entry references a ChallengeTarget class from tests.benchmark.challenges.
12 targets: 8 original (§10.7.6) + 4 modern web (GraphQL, WebSocket, XSS) (§10.7.8).
"""
from __future__ import annotations

from typing import Dict, List, Any

from tests.benchmark.challenges import (
    LFIReadDirect,
    LFIReadEncoded,
    SSTIReflectedJinja2,
    SQLiUnionBased,
    SQLiBooleanBlind,
    CMDiFilteredChars,
    JWTAlgNone,
    SourceLeakGitHead,
    GraphQLIntrospection,
    WebSocketAuthBypass,
    XSSReflected,
    XSSStored,
    ChallengeTarget,
)

# First 8 strict web benchmarks (roadmap §10.7.6)
STRICT_BENCHMARK_8: Dict[str, type] = {
    "lfi_basic": LFIReadDirect,
    "lfi_filter": LFIReadEncoded,
    "ssti_jinja": SSTIReflectedJinja2,
    "sqli_union": SQLiUnionBased,
    "sqli_blind": SQLiBooleanBlind,
    "cmdi_filter": CMDiFilteredChars,
    "jwt_none": JWTAlgNone,
    "source_leak_git": SourceLeakGitHead,
}

# Expanded 12 targets (adds GraphQL, WebSocket, XSS reflected, XSS stored)
STRICT_BENCHMARK_12: Dict[str, type] = {
    **STRICT_BENCHMARK_8,
    "graphql_introspection": GraphQLIntrospection,
    "websocket_auth_bypass": WebSocketAuthBypass,
    "xss_reflected": XSSReflected,
    "xss_stored": XSSStored,
}

# Metadata for each target (maps to the roadmap metadata.json format)
TARGET_METADATA: Dict[str, Dict[str, Any]] = {
    "lfi_basic": {
        "id": "lfi_basic",
        "name": "LFI Basic — Direct Path Traversal",
        "category": "lfi",
        "difficulty": 1,
        "flag": LFIReadDirect.flag,
        "expected_route": "lfi",
        "expected_max_rounds": 8,
        "port": 0,
        "description": "Direct path traversal via 'page' parameter, flag readable from /tmp",
        "hints": ["GET /?page=/tmp/benchmark_flag_lfi"],
        "tags": ["lfi", "path_traversal", "no_filter"],
    },
    "lfi_filter": {
        "id": "lfi_filter",
        "name": "LFI Filtered — Double-Encoding Bypass",
        "category": "lfi",
        "difficulty": 2,
        "flag": LFIReadEncoded.flag,
        "expected_route": "lfi",
        "expected_max_rounds": 12,
        "port": 0,
        "description": "LFI with '../' filtered, requires double URL encoding bypass",
        "hints": ["GET /?path=..%252f..%252f", "flag at /tmp/benchmark_flag_lfi2"],
        "tags": ["lfi", "encoding_bypass", "path_traversal"],
    },
    "ssti_jinja": {
        "id": "ssti_jinja",
        "name": "SSTI Jinja2 — Reflected Template Injection",
        "category": "ssti",
        "difficulty": 1,
        "flag": SSTIReflectedJinja2.flag,
        "expected_route": "ssti",
        "expected_max_rounds": 8,
        "port": 0,
        "description": "Reflected Jinja2 SSTI via 'name' parameter, no filtering",
        "hints": ["GET /?name={{7*7}}", "SSTI via Jinja2 config access"],
        "tags": ["ssti", "jinja2", "reflected"],
    },
    "sqli_union": {
        "id": "sqli_union",
        "name": "SQLi Union-Based — UNION SELECT Injection",
        "category": "sqli",
        "difficulty": 1,
        "flag": SQLiUnionBased.flag,
        "expected_route": "sqli",
        "expected_max_rounds": 10,
        "port": 0,
        "description": "UNION-based SQL injection via 'q' parameter, SQLite error messages",
        "hints": ["GET /?q=' UNION SELECT 1,flag,3--", "SQLite errors on quote"],
        "tags": ["sqli", "union", "sqlite"],
    },
    "sqli_blind": {
        "id": "sqli_blind",
        "name": "SQLi Boolean-Blind — Conditional Response",
        "category": "sqli",
        "difficulty": 2,
        "flag": SQLiBooleanBlind.flag,
        "expected_route": "sqli",
        "expected_max_rounds": 15,
        "port": 0,
        "description": "Boolean-based blind SQLi via 'user_id' parameter, response differs with OR 1=1",
        "hints": ["GET /?user_id=1 OR 1=1--", "Response length differs on true condition"],
        "tags": ["sqli", "boolean_blind", "conditional"],
    },
    "cmdi_filter": {
        "id": "cmdi_filter",
        "name": "CMDi Filtered — Character Blacklist Bypass",
        "category": "cmdi",
        "difficulty": 2,
        "flag": CMDiFilteredChars.flag,
        "expected_route": "cmdi",
        "expected_max_rounds": 10,
        "port": 0,
        "description": "Command injection with ';', '|', '&' blocked, bypass via newline or backtick",
        "hints": ["GET /?host=127.0.0.1%0acat flag", "Blocked chars: ; | &"],
        "tags": ["cmdi", "filter_bypass", "blacklist"],
    },
    "jwt_none": {
        "id": "jwt_none",
        "name": "JWT Alg=None — Algorithm Confusion",
        "category": "jwt",
        "difficulty": 1,
        "flag": JWTAlgNone.flag,
        "expected_route": "jwt",
        "expected_max_rounds": 8,
        "port": 0,
        "description": "JWT accepts alg=none, admin access via token modification",
        "hints": ["Cookie: token=<JWT>", "/admin requires valid JWT, alg=none accepted"],
        "tags": ["jwt", "alg_none", "algorithm_confusion"],
    },
    "source_leak_git": {
        "id": "source_leak_git",
        "name": "Source Leak — .git/HEAD Exposed",
        "category": "source_leak",
        "difficulty": 1,
        "flag": SourceLeakGitHead.flag,
        "expected_route": "source_leak",
        "expected_max_rounds": 5,
        "port": 0,
        "description": ".git/HEAD file exposed, flag in source code comment",
        "hints": ["GET /.git/HEAD", "PHP app with source leak"],
        "tags": ["source_leak", "git", "php"],
    },
    "graphql_introspection": {
        "id": "graphql_introspection",
        "name": "GraphQL — Introspection + Hidden Query",
        "category": "graphql",
        "difficulty": 1,
        "flag": GraphQLIntrospection.flag,
        "expected_route": "graphql",
        "expected_max_rounds": 8,
        "port": 0,
        "description": "GraphQL endpoint with introspection enabled, flag in getFlag query",
        "hints": ["POST /graphql query { __schema { ... } }", "Flag via getFlag query"],
        "tags": ["graphql", "introspection", "api"],
    },
    "websocket_auth_bypass": {
        "id": "websocket_auth_bypass",
        "name": "WebSocket — Auth Token Bypass",
        "category": "websocket",
        "difficulty": 1,
        "flag": WebSocketAuthBypass.flag,
        "expected_route": "websocket",
        "expected_max_rounds": 8,
        "port": 0,
        "description": "WebSocket-like endpoint with role-based access, flag via admin token",
        "hints": ["GET /api/ws/connect?token=admin", "Guest role needs escalation"],
        "tags": ["websocket", "auth_bypass", "token"],
    },
    "xss_reflected": {
        "id": "xss_reflected",
        "name": "XSS — Reflected + Admin Bot",
        "category": "xss",
        "difficulty": 2,
        "flag": XSSReflected.flag,
        "expected_route": "xss",
        "expected_max_rounds": 12,
        "port": 0,
        "description": "Reflected XSS with admin bot that visits URL and exposes flag in cookie",
        "hints": ["GET /?q=<script>...</script>", "Admin bot at /admin/bot?visit=..."],
        "tags": ["xss", "reflected", "admin_bot", "cookie_steal"],
    },
    "xss_stored": {
        "id": "xss_stored",
        "name": "XSS — Stored Guestbook + Admin Review",
        "category": "xss",
        "difficulty": 2,
        "flag": XSSStored.flag,
        "expected_route": "xss",
        "expected_max_rounds": 12,
        "port": 0,
        "description": "Stored XSS in guestbook, admin reviews messages and exposes flag via cookie",
        "hints": ["POST / message=<script>...</script>", "Admin reads at /admin/read"],
        "tags": ["xss", "stored", "admin_bot", "cookie_steal"],
    },
}


def get_first_8_targets() -> List[Dict[str, Any]]:
    """Return the first 8 strict benchmark target metadata entries."""
    return [TARGET_METADATA[key] for key in STRICT_BENCHMARK_8]


def get_all_targets() -> List[Dict[str, Any]]:
    """Return all 12 strict benchmark target metadata entries."""
    return [TARGET_METADATA[key] for key in STRICT_BENCHMARK_12]


def get_target_class(target_id: str):
    """Get the ChallengeTarget class for a given target ID (searches both registries)."""
    return STRICT_BENCHMARK_12.get(target_id) or STRICT_BENCHMARK_8.get(target_id)


def get_target_metadata(target_id: str) -> Dict[str, Any]:
    """Get metadata for a given target ID."""
    return TARGET_METADATA.get(target_id, {})


def get_target_flag(target_id: str) -> str:
    """Get the known flag for a given target ID."""
    return get_target_class(target_id).flag
