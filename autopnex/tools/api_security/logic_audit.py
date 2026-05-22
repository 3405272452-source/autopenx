"""Business logic vulnerability auditor.

Inspired by Shannon's shannon-logic-audit tool. Tests for common business logic
flaws: negative quantities, price manipulation, step skipping, coupon reuse, etc.
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List

from ..base import BaseTool, ToolResult, register
from .._http import normalise_target, request


# Semantic field patterns and their test mutations
FIELD_MUTATIONS = {
    "price": {
        "keywords": ["price", "amount", "cost", "total", "fee", "payment"],
        "mutations": [
            {"value": "-1", "description": "Negative price"},
            {"value": "0", "description": "Zero price"},
            {"value": "0.01", "description": "Minimal price"},
            {"value": "-999999", "description": "Large negative"},
        ],
    },
    "quantity": {
        "keywords": ["quantity", "qty", "count", "num", "number"],
        "mutations": [
            {"value": "-1", "description": "Negative quantity"},
            {"value": "0", "description": "Zero quantity"},
            {"value": "999999", "description": "Excessive quantity"},
        ],
    },
    "discount": {
        "keywords": ["discount", "coupon", "promo", "voucher", "code"],
        "mutations": [
            {"value": "100", "description": "100% discount"},
            {"value": "-10", "description": "Negative discount"},
            {"value": "999999", "description": "Extreme discount"},
        ],
    },
    "role": {
        "keywords": ["role", "type", "level", "permission", "admin", "privilege"],
        "mutations": [
            {"value": "admin", "description": "Admin role"},
            {"value": "administrator", "description": "Administrator role"},
            {"value": "superuser", "description": "Superuser role"},
            {"value": "1", "description": "Elevated numeric role"},
        ],
    },
    "step": {
        "keywords": ["step", "stage", "phase", "sequence", "order"],
        "mutations": [
            {"value": "999", "description": "Skip to final step"},
            {"value": "-1", "description": "Negative step"},
            {"value": "0", "description": "Zero step"},
        ],
    },
    "id": {
        "keywords": ["user_id", "account_id", "profile_id", "owner_id"],
        "mutations": [
            {"value": "1", "description": "First user ID"},
            {"value": "0", "description": "Zero ID"},
            {"value": "-1", "description": "Negative ID"},
        ],
    },
}


@register
class LogicAuditTool(BaseTool):
    category = "vuln"

    @property
    def name(self) -> str:
        return "logic_audit"

    @property
    def description(self) -> str:
        return (
            "Detect business logic vulnerabilities: negative price/quantity, "
            "step skipping, coupon reuse, role tampering, and price manipulation. "
            "Analyzes form fields semantically and tests mutations."
        )

    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target URL.",
                },
                "forms": {
                    "type": "string",
                    "description": 'JSON array of forms to test. Format: [{"action":"/api/order","method":"POST","fields":[{"name":"price","type":"text"},{"name":"quantity","type":"number"}]}].',
                },
            },
            "required": ["target"],
        }

    def _run(self, **kwargs: Any) -> ToolResult:
        target = normalise_target(kwargs.get("target", ""))
        forms_str = kwargs.get("forms", "")

        if not target:
            return ToolResult(False, self.name, "target required", error="missing_args")

        forms: List[Dict[str, Any]] = []
        if forms_str:
            try:
                forms = json.loads(forms_str)
            except json.JSONDecodeError:
                return ToolResult(False, self.name, "Invalid forms JSON", error="parse_error")

        # If no forms provided, try to discover from target
        if not forms:
            forms = self._discover_forms(target)

        if not forms:
            return ToolResult(
                True, self.name,
                "No forms found to test",
                parsed_data={"target": target, "forms_tested": 0, "issues": []},
            )

        issues: List[Dict[str, Any]] = []
        total_tests = 0

        for form in forms:
            action = form.get("action", "")
            method = (form.get("method") or "POST").upper()
            fields = form.get("fields", [])
            form_url = target.rstrip("/") + action if action and not action.startswith("http") else action or target

            # Build base form data
            base_data = {}
            for field in fields:
                name = field.get("name", "")
                if name:
                    base_data[name] = field.get("value", "test")

            # Test each field for logic issues
            for field in fields:
                field_name = field.get("name", "")
                if not field_name:
                    continue

                field_lower = field_name.lower()
                for mutation_type, mutation_config in FIELD_MUTATIONS.items():
                    if not any(kw in field_lower for kw in mutation_config["keywords"]):
                        continue

                    for mutation in mutation_config["mutations"]:
                        total_tests += 1
                        test_data = dict(base_data)
                        test_data[field_name] = mutation["value"]

                        resp, err, elapsed = request(method, form_url, data=test_data)
                        if resp is None:
                            continue

                        # Check if the mutation was accepted (200/201) instead of rejected (400/422)
                        if resp.status_code in (200, 201):
                            body = resp.text or ""
                            # Verify it's not just an error page
                            if len(body) > 50 and not self._is_error_page(body):
                                issues.append({
                                    "type": mutation_type,
                                    "field": field_name,
                                    "mutation": mutation["description"],
                                    "value": mutation["value"],
                                    "form_url": form_url,
                                    "status_code": resp.status_code,
                                    "response_size": len(body),
                                    "severity": self._severity(mutation_type),
                                })
                                break  # One hit per field per mutation type

        success = bool(issues)
        issue_types = list({i["type"] for i in issues})
        summary = (
            f"Logic audit: {len(issues)} potential issues found "
            f"({', '.join(issue_types)}) in {total_tests} tests"
            if success
            else f"Logic audit: no logic issues found in {total_tests} tests"
        )

        return ToolResult(
            success=success,
            tool=self.name,
            summary=summary,
            parsed_data={
                "target": target,
                "forms_tested": len(forms),
                "total_tests": total_tests,
                "issues": issues,
                "issue_types": issue_types,
                "severity": "HIGH" if success else "INFO",
            },
            raw_output=str(issues)[:2000],
        )

    def _discover_forms(self, target: str) -> List[Dict[str, Any]]:
        """Try to discover forms from the target page."""
        resp, err, _ = request("GET", target)
        if resp is None:
            return []

        body = resp.text or ""
        forms = []

        # Simple regex form extraction
        form_pattern = re.compile(
            r'<form[^>]*action=["\']([^"\']*)["\'][^>]*method=["\']?(\w+)?["\']?[^>]*>(.*?)</form>',
            re.DOTALL | re.IGNORECASE,
        )
        input_pattern = re.compile(
            r'<input[^>]*name=["\']([^"\']+)["\'][^>]*(?:type=["\']([^"\']+)["\'])?[^>]*>',
            re.IGNORECASE,
        )

        for form_match in form_pattern.finditer(body):
            action = form_match.group(1) or ""
            method = form_match.group(2) or "POST"
            form_body = form_match.group(3)

            fields = []
            for input_match in input_pattern.finditer(form_body):
                fields.append({
                    "name": input_match.group(1),
                    "type": input_match.group(2) or "text",
                })

            if fields:
                forms.append({"action": action, "method": method, "fields": fields})

        return forms[:10]

    def _is_error_page(self, body: str) -> bool:
        """Check if response looks like an error page."""
        error_indicators = ["error", "invalid", "failed", "denied", "unauthorized", "forbidden"]
        body_lower = body.lower()
        return sum(1 for ind in error_indicators if ind in body_lower) >= 2

    def _severity(self, mutation_type: str) -> str:
        severity_map = {
            "price": "CRITICAL",
            "quantity": "HIGH",
            "discount": "CRITICAL",
            "role": "CRITICAL",
            "step": "HIGH",
            "id": "HIGH",
        }
        return severity_map.get(mutation_type, "MEDIUM")
