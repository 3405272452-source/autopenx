"""IDOR (Insecure Direct Object Reference) systematic tester.

Inspired by Shannon's shannon-idor tool. Auto-discovers REST API patterns
and tests for cross-user resource access vulnerabilities.
"""
from __future__ import annotations

from typing import Any, Dict, List

from ..base import BaseTool, ToolResult, register
from .._http import normalise_target, request


# Common REST API patterns with ID placeholders
REST_PATTERNS = [
    "/api/users/{id}",
    "/api/v1/users/{id}",
    "/api/v2/users/{id}",
    "/api/user/{id}",
    "/api/account/{id}",
    "/api/accounts/{id}",
    "/api/profile/{id}",
    "/api/profiles/{id}",
    "/api/orders/{id}",
    "/api/order/{id}",
    "/api/documents/{id}",
    "/api/items/{id}",
    "/api/products/{id}",
    "/api/invoices/{id}",
    "/api/messages/{id}",
    "/api/notifications/{id}",
    "/api/settings/{id}",
]

# Numeric ID test values
TEST_IDS = [1, 2, 0, 999, -1]

# Sensitive data indicators
SENSITIVE_INDICATORS = [
    "email", "username", "name", "phone", "address",
    "password", "hash", "token", "secret", "ssn",
    "credit_card", "card_number", "account_number",
    "role", "admin", "privilege", "permission",
]


@register
class IдорTestTool(BaseTool):
    category = "vuln"
    required_capability = "exploit"
    requires_exploit_enabled = True

    @property
    def name(self) -> str:
        return "idor_test"

    @property
    def description(self) -> str:
        return (
            "Systematic IDOR testing. Auto-discovers REST API endpoints and tests "
            "cross-user resource access by enumerating numeric IDs. Supports auto "
            "mode (discover and test 17+ common patterns) and manual mode."
        )

    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Base URL of the target (e.g. https://example.com).",
                },
                "auth_token": {
                    "type": "string",
                    "description": "Authorization header value (e.g. 'Bearer eyJ...').",
                },
                "own_user_id": {
                    "type": "number",
                    "description": "Your authenticated user's ID. Other IDs are tested as cross-user.",
                },
                "endpoints": {
                    "type": "string",
                    "description": 'JSON array of endpoints to test. Format: [{"method":"GET","path":"/api/users/{id}","ids":[1,2,3]}].',
                },
                "mode": {
                    "type": "string",
                    "enum": ["auto", "manual"],
                    "description": "Test mode: auto (discover patterns) or manual (test specified endpoints). Default: auto.",
                },
            },
            "required": ["target"],
        }

    def _run(self, **kwargs: Any) -> ToolResult:
        target = normalise_target(kwargs.get("target", ""))
        auth_token = kwargs.get("auth_token", "")
        own_user_id = kwargs.get("own_user_id")
        endpoints_json = kwargs.get("endpoints", "")
        mode = kwargs.get("mode", "auto")

        if not target:
            return ToolResult(False, self.name, "target required", error="missing_args")

        headers = {}
        if auth_token:
            headers["Authorization"] = auth_token

        results: List[Dict[str, Any]] = []
        endpoints_to_test = []

        if mode == "manual" and endpoints_json:
            import json
            try:
                endpoints_to_test = json.loads(endpoints_json)
            except json.JSONDecodeError:
                return ToolResult(False, self.name, "Invalid endpoints JSON", error="parse_error")
        else:
            # Auto mode: generate endpoints from patterns
            for pattern in REST_PATTERNS:
                for test_id in TEST_IDS:
                    path = pattern.replace("{id}", str(test_id))
                    endpoints_to_test.append({
                        "method": "GET",
                        "path": path,
                        "id": test_id,
                    })

        # Test each endpoint
        total_requests = 0
        accessible = 0
        blocked = 0
        errors = 0

        for ep in endpoints_to_test:
            method = ep.get("method", "GET").upper()
            path = ep.get("path", "")
            test_id = ep.get("id", ep.get("ids", [1])[0] if isinstance(ep.get("ids"), list) else 1)

            url = target.rstrip("/") + path
            total_requests += 1

            resp, err, elapsed = request(method, url, headers=headers or None)
            if resp is None:
                errors += 1
                continue

            body = resp.text or ""
            body_lower = body.lower()

            # Check if response contains sensitive data
            has_sensitive = any(indicator in body_lower for indicator in SENSITIVE_INDICATORS)
            is_large = len(body) > 100
            is_200 = resp.status_code == 200

            if is_200 and is_large and has_sensitive:
                # Check if this is accessing another user's data
                is_other_user = own_user_id is not None and test_id != own_user_id
                accessible += 1
                results.append({
                    "method": method,
                    "endpoint": path,
                    "id_tested": test_id,
                    "status_code": resp.status_code,
                    "response_size": len(body),
                    "accessible": True,
                    "is_other_user": is_other_user,
                    "body_snippet": body[:300],
                    "elapsed_ms": int(elapsed * 1000),
                })
            elif resp.status_code in (401, 403):
                blocked += 1
            elif is_200:
                # 200 but no clear sensitive data
                results.append({
                    "method": method,
                    "endpoint": path,
                    "id_tested": test_id,
                    "status_code": resp.status_code,
                    "response_size": len(body),
                    "accessible": True,
                    "is_other_user": False,
                    "body_snippet": body[:200],
                    "elapsed_ms": int(elapsed * 1000),
                })

        vulnerable = [r for r in results if r.get("accessible") and r.get("is_other_user")]

        success = bool(vulnerable)
        summary = (
            f"IDOR: {len(vulnerable)} potentially vulnerable endpoints "
            f"(tested {total_requests}, accessible {accessible}, blocked {blocked})"
        )

        return ToolResult(
            success=success,
            tool=self.name,
            summary=summary,
            parsed_data={
                "target": target,
                "mode": mode,
                "total_requests": total_requests,
                "accessible": accessible,
                "blocked": blocked,
                "errors": errors,
                "vulnerable_endpoints": vulnerable,
                "all_results": results[:50],
                "severity": "HIGH" if success else "INFO",
            },
            raw_output=str(results[:20]),
        )
