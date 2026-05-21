"""HTTP security headers auditor.

Inspired by Shannon's shannon-headers-audit tool. Checks for missing or
misconfigured security response headers and identifies potential vulnerabilities.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..base import BaseTool, ToolResult, register
from .._http import normalise_target, request


# Security headers and their expected configurations
SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "severity": "HIGH",
        "description": "Content Security Policy — mitigates XSS, clickjacking, injection attacks",
        "recommendation": "Implement a strict CSP with nonces or hashes; avoid 'unsafe-inline'",
        "bad_values": ["", "none"],
        "weak_indicators": ["unsafe-inline", "unsafe-eval", "data:", "*"],
    },
    "Strict-Transport-Security": {
        "severity": "MEDIUM",
        "description": "HTTP Strict Transport Security — enforces HTTPS",
        "recommendation": "Set HSTS with max-age=31536000; includeSubDomains; preload",
        "bad_values": [""],
        "weak_indicators": ["max-age=0"],
    },
    "X-Content-Type-Options": {
        "severity": "MEDIUM",
        "description": "Prevents MIME type sniffing",
        "recommendation": "Set to 'nosniff'",
        "expected": "nosniff",
        "bad_values": [""],
    },
    "X-Frame-Options": {
        "severity": "MEDIUM",
        "description": "Clickjacking protection — controls iframe embedding",
        "recommendation": "Set to DENY or SAMEORIGIN",
        "expected_values": ["DENY", "SAMEORIGIN"],
        "bad_values": [""],
    },
    "X-XSS-Protection": {
        "severity": "LOW",
        "description": "Legacy XSS filter (deprecated but still useful for older browsers)",
        "recommendation": "Set to '1; mode=block' or rely on CSP instead",
        "bad_values": [""],
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "description": "Controls referrer information sent with requests",
        "recommendation": "Set to 'no-referrer' or 'strict-origin-when-cross-origin'",
        "bad_values": [""],
    },
    "Permissions-Policy": {
        "severity": "LOW",
        "description": "Controls browser feature access (camera, microphone, geolocation, etc.)",
        "recommendation": "Restrict unused features: camera=(), microphone=(), geolocation=()",
        "bad_values": [""],
    },
    "Cross-Origin-Opener-Policy": {
        "severity": "LOW",
        "description": "Controls cross-origin window interactions (Spectre mitigation)",
        "recommendation": "Set to 'same-origin'",
        "bad_values": [""],
    },
    "Cross-Origin-Resource-Policy": {
        "severity": "LOW",
        "description": "Controls cross-origin resource loading",
        "recommendation": "Set to 'same-origin' or 'same-site'",
        "bad_values": [""],
    },
    "Cross-Origin-Embedder-Policy": {
        "severity": "LOW",
        "description": "Controls cross-origin embedding (Spectre mitigation)",
        "recommendation": "Set to 'require-corp'",
        "bad_values": [""],
    },
}

# Headers that reveal server information (information disclosure)
INFO_DISCLOSURE_HEADERS = {
    "Server": {
        "severity": "LOW",
        "description": "Reveals web server software and version",
        "recommendation": "Remove or genericize the Server header",
    },
    "X-Powered-By": {
        "severity": "LOW",
        "description": "Reveals backend technology (PHP, Express, ASP.NET, etc.)",
        "recommendation": "Remove the X-Powered-By header",
    },
    "X-AspNet-Version": {
        "severity": "LOW",
        "description": "Reveals ASP.NET version",
        "recommendation": "Remove the X-AspNet-Version header",
    },
    "X-AspNetMvc-Version": {
        "severity": "LOW",
        "description": "Reveals ASP.NET MVC version",
        "recommendation": "Remove the X-AspNetMvc-Version header",
    },
}


@register
class HeadersAuditTool(BaseTool):
    category = "recon"

    @property
    def name(self) -> str:
        return "headers_audit"

    @property
    def description(self) -> str:
        return (
            "Audit HTTP security response headers. Checks for missing or weak "
            "Content-Security-Policy, HSTS, X-Frame-Options, X-Content-Type-Options, "
            "Referrer-Policy, Permissions-Policy, and CORS headers. Also detects "
            "information disclosure via Server, X-Powered-By, and similar headers."
        )

    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target URL to audit.",
                },
            },
            "required": ["target"],
        }

    def _run(self, **kwargs: Any) -> ToolResult:
        target = normalise_target(kwargs.get("target", ""))

        if not target:
            return ToolResult(False, self.name, "target required", error="missing_args")

        resp, err, elapsed = request("GET", target)
        if resp is None:
            return ToolResult(False, self.name, f"Request failed: {err}", error=err)

        headers = {k: v for k, v in resp.headers.items()}
        issues: List[Dict[str, Any]] = []
        present_headers: List[str] = []
        missing_headers: List[str] = []
        info_disclosure: List[Dict[str, Any]] = []

        # Check security headers
        for header_name, config in SECURITY_HEADERS.items():
            value = headers.get(header_name, "")
            if not value:
                missing_headers.append(header_name)
                issues.append({
                    "type": "missing",
                    "header": header_name,
                    "severity": config["severity"],
                    "description": config["description"],
                    "recommendation": config["recommendation"],
                })
            else:
                present_headers.append(header_name)
                # Check for weak values
                weak_found = False
                for indicator in config.get("weak_indicators", []):
                    if indicator in value:
                        issues.append({
                            "type": "weak",
                            "header": header_name,
                            "value": value[:200],
                            "severity": config["severity"],
                            "description": f"{config['description']} — weak value detected: {indicator}",
                            "recommendation": config["recommendation"],
                        })
                        weak_found = True
                        break

                # Check expected values
                expected = config.get("expected_values")
                if expected and value.upper() not in [e.upper() for e in expected]:
                    issues.append({
                        "type": "weak",
                        "header": header_name,
                        "value": value[:200],
                        "severity": config["severity"],
                        "description": f"Unexpected value. Expected one of: {expected}",
                        "recommendation": config["recommendation"],
                    })

                expected_single = config.get("expected")
                if expected_single and value.lower() != expected_single.lower():
                    issues.append({
                        "type": "weak",
                        "header": header_name,
                        "value": value[:200],
                        "severity": config["severity"],
                        "description": f"Expected '{expected_single}', got '{value}'",
                        "recommendation": config["recommendation"],
                    })

        # Check CORS configuration
        acao = headers.get("Access-Control-Allow-Origin", "")
        if acao:
            if acao == "*":
                issues.append({
                    "type": "cors_wildcard",
                    "header": "Access-Control-Allow-Origin",
                    "value": acao,
                    "severity": "MEDIUM",
                    "description": "CORS wildcard allows any origin — potential for data theft",
                    "recommendation": "Restrict to specific trusted origins",
                })
            present_headers.append("Access-Control-Allow-Origin")

        acac = headers.get("Access-Control-Allow-Credentials", "")
        if acac.lower() == "true" and acao == "*":
            issues.append({
                "type": "cors_misconfiguration",
                "header": "Access-Control-Allow-Credentials",
                "value": acac,
                "severity": "HIGH",
                "description": "Credentials allowed with wildcard origin — critical CORS misconfiguration",
                "recommendation": "Never combine Allow-Credentials with wildcard origin",
            })

        # Check information disclosure
        for header_name, config in INFO_DISCLOSURE_HEADERS.items():
            value = headers.get(header_name, "")
            if value:
                info_disclosure.append({
                    "header": header_name,
                    "value": value[:200],
                    "severity": config["severity"],
                    "description": config["description"],
                    "recommendation": config["recommendation"],
                })

        # Check cookie security
        cookies = resp.cookies
        insecure_cookies = []
        for cookie in cookies:
            cookie_issues = []
            if not cookie.secure:
                cookie_issues.append("missing Secure flag")
            if "httponly" not in str(cookie).lower():
                cookie_issues.append("missing HttpOnly flag")
            if cookie_issues:
                insecure_cookies.append({
                    "name": cookie.name,
                    "issues": cookie_issues,
                })

        # Build result
        has_high = any(i["severity"] in ("HIGH", "CRITICAL") for i in issues)
        has_medium = any(i["severity"] == "MEDIUM" for i in issues)

        security_score = self._calculate_score(present_headers, missing_headers, issues)

        success = bool(issues or info_disclosure or insecure_cookies)
        issue_count = len(issues) + len(info_disclosure) + len(insecure_cookies)
        summary = (
            f"Headers audit: {issue_count} issues found (score {security_score}/100) — "
            f"{len(missing_headers)} missing headers, {len(issues)} weak configurations, "
            f"{len(info_disclosure)} info disclosures, {len(insecure_cookies)} insecure cookies"
        )

        return ToolResult(
            success=success,
            tool=self.name,
            summary=summary,
            parsed_data={
                "target": target,
                "status_code": resp.status_code,
                "security_score": security_score,
                "issues": issues,
                "missing_headers": missing_headers,
                "present_headers": present_headers,
                "info_disclosure": info_disclosure,
                "insecure_cookies": insecure_cookies,
                "total_issues": issue_count,
                "severity": "HIGH" if has_high else ("MEDIUM" if has_medium else "LOW"),
            },
            raw_output=str(issues + info_disclosure)[:3000],
        )

    def _calculate_score(self, present: List[str], missing: List[str], issues: List[Dict]) -> int:
        """Calculate a security header score (0-100)."""
        score = 100

        # Deduct for missing headers
        high_impact = {"Content-Security-Policy", "Strict-Transport-Security", "X-Content-Type-Options", "X-Frame-Options"}
        medium_impact = {"Referrer-Policy", "Permissions-Policy"}

        for header in missing:
            if header in high_impact:
                score -= 15
            elif header in medium_impact:
                score -= 8
            else:
                score -= 4

        # Deduct for weak values
        for issue in issues:
            if issue["type"] == "weak":
                score -= 5
            elif issue["type"] in ("cors_wildcard", "cors_misconfiguration"):
                score -= 10

        return max(0, min(100, score))
