"""Normalize tool results into the shared findings state."""
from __future__ import annotations

from typing import Dict

from ..knowledge_base.vuln_patterns import VULN_PATTERNS
from ..knowledge_base.cwe_mapping import auto_correlate
from ..tools.base import ToolResult
from .findings import Finding, StateFindings


def ingest_tool_result(
    findings: StateFindings,
    *,
    phase: str,
    tool: str,
    arguments: Dict[str, object],
    result: ToolResult,
) -> None:
    if not result.success:
        findings.log_state(phase, f"tool {tool} failed: {result.summary}", level="error")
        return

    data = result.parsed_data or {}

    if tool in {"port_scan", "nmap_scan"}:
        findings.open_ports = data.get("open_ports", findings.open_ports)
        return

    if tool == "tech_detect":
        techs = data.get("technologies", [])
        for tech in techs:
            if tech not in findings.technologies:
                findings.technologies.append(tech)
        missing = [header for header, present in (data.get("security_headers") or {}).items() if not present]
        if missing:
            findings.add_finding(
                Finding(
                    title="Missing HTTP security headers",
                    severity="LOW",
                    status="confirmed",
                    category="security_headers",
                    description=f"The target is missing recommended security response headers: {', '.join(missing)}",
                    evidence=str(data.get("security_headers")),
                    url=data.get("final_url") or findings.target,
                    tool=tool,
                    recommendation=VULN_PATTERNS["security_headers"]["recommendation"],
                )
            )
        return

    if tool == "subdomain_find":
        for subdomain in data.get("subdomains", []):
            if subdomain not in findings.subdomains:
                findings.subdomains.append(subdomain)
        return

    if tool == "web_scan":
        hits = data.get("sensitive_files", [])
        for hit in hits:
            findings.interesting_files.append(hit)
            findings.add_finding(
                Finding(
                    title=f"Sensitive file exposed: {hit['url']}",
                    severity=VULN_PATTERNS["sensitive_file"]["severity"],
                    status="confirmed",
                    category="sensitive_file",
                    description=f"HTTP {hit['status']} {hit.get('content_type', '')} - {hit.get('size', 0)} bytes",
                    evidence=hit["url"],
                    url=hit["url"],
                    tool=tool,
                    recommendation=VULN_PATTERNS["sensitive_file"]["recommendation"],
                )
            )
        missing = data.get("missing_security_headers") or []
        if missing and not any(f.title == "Missing HTTP security headers" for f in findings.findings):
            findings.add_finding(
                Finding(
                    title="Missing HTTP security headers",
                    severity="LOW",
                    status="confirmed",
                    category="security_headers",
                    description=f"Missing: {', '.join(missing)}",
                    evidence=", ".join(missing),
                    url=findings.target,
                    tool=tool,
                    recommendation=VULN_PATTERNS["security_headers"]["recommendation"],
                )
            )
        return

    if tool in {"dir_buster", "ffuf_scan"}:
        for hit in data.get("hits", []):
            findings.add_path(hit["url"])
        return

    if tool == "burp_proxy_scan":
        findings.add_artifact(
            parent_ref=None,
            phase=phase,
            tool=tool,
            kind="http_capture",
            summary=result.summary,
            raw_output_excerpt=result.raw_output,
            metadata=data,
        )
        return

    if tool == "crawl":
        for page in data.get("pages", []):
            findings.add_path(page)
        for form in data.get("forms", []):
            if form not in findings.forms:
                findings.forms.append(form)
        for parameter in data.get("parameters", []):
            findings.add_parameter(parameter["url"], parameter["name"], parameter.get("method", "GET"))
        return

    if tool == "sqli_detect" and data.get("vulnerable"):
        signals = data.get("signals") or []
        status = "confirmed" if any(signal in {"error", "boolean"} for signal in signals) else "suspected"
        findings.add_finding(
            Finding(
                title="SQL injection",
                severity=data.get("severity", "HIGH"),
                status=status,
                category="sqli",
                description=f"Parameter `{data.get('parameter')}` is SQL-injectable ({', '.join(signals)}).",
                evidence="\n".join(data.get("evidence") or []),
                url=data.get("url"),
                parameter=data.get("parameter"),
                payload=data.get("payload"),
                tool=tool,
                recommendation=VULN_PATTERNS["sql_injection"]["recommendation"],
            )
        )
        return

    if tool == "sqlmap_scan" and data.get("vulnerable"):
        dbms = data.get("dbms")
        description = f"Parameter `{data.get('parameter')}` appears SQL injectable according to sqlmap."
        if dbms:
            description += f" Backend DBMS: {dbms}."
        findings.add_finding(
            Finding(
                title="SQL injection",
                severity=data.get("severity", "HIGH"),
                status="confirmed",
                category="sqli",
                description=description,
                evidence="\n".join(data.get("evidence") or []),
                url=data.get("url"),
                parameter=data.get("parameter"),
                payload=data.get("payload"),
                tool=tool,
                recommendation=VULN_PATTERNS["sql_injection"]["recommendation"],
            )
        )
        return

    if tool == "xss_detect" and data.get("vulnerable"):
        reflections = data.get("reflections") or []
        findings.add_finding(
            Finding(
                title="Reflected XSS",
                severity=data.get("severity", "MEDIUM"),
                status="confirmed" if reflections else "suspected",
                category="xss",
                description=f"Parameter `{data.get('parameter')}` reflects payload unencoded in response.",
                evidence=str(reflections[:2]),
                url=data.get("url"),
                parameter=data.get("parameter"),
                payload=reflections[0]["payload"] if reflections else None,
                tool=tool,
                recommendation=VULN_PATTERNS["xss_reflected"]["recommendation"],
            )
        )
        return

    if tool == "ssrf_detect" and data.get("vulnerable"):
        hits = data.get("hits") or []
        has_indicator = any(hit.get("indicator") for hit in hits)
        status = "confirmed" if len(hits) >= 2 and has_indicator else "suspected"
        findings.add_finding(
            Finding(
                title="Potential SSRF",
                severity=data.get("severity", "HIGH"),
                status=status,
                category="ssrf",
                description=f"Parameter `{data.get('parameter')}` may fetch attacker-controlled URLs.",
                evidence=str(hits[:2]),
                url=data.get("url"),
                parameter=data.get("parameter"),
                payload=hits[0]["payload"] if hits else None,
                tool=tool,
                recommendation=VULN_PATTERNS["ssrf"]["recommendation"],
            )
        )
        return

    if tool == "cmdi_detect" and data.get("vulnerable"):
        hits = data.get("hits") or []
        status = "confirmed" if hits else "suspected"
        findings.add_finding(
            Finding(
                title="Command Injection",
                severity=data.get("severity", "CRITICAL"),
                status=status,
                category="cmdi",
                description=f"Parameter `{data.get('parameter')}` executes OS commands (time-based).",
                evidence=str(hits),
                url=data.get("url"),
                parameter=data.get("parameter"),
                payload=hits[0]["payload"] if hits else None,
                tool=tool,
                recommendation=VULN_PATTERNS["command_injection"]["recommendation"],
            )
        )
        return

    if tool == "ssti_detect" and data.get("vulnerable"):
        findings.add_finding(
            Finding(
                title="Server-Side Template Injection",
                severity=data.get("severity", "HIGH"),
                status="confirmed",
                category="ssti",
                description=f"Parameter `{data.get('param')}` evaluates template expressions.",
                evidence=str(data.get("evidence") or result.raw_output[:300]),
                url=data.get("url"),
                parameter=data.get("param"),
                payload=data.get("payload"),
                tool=tool,
                recommendation="Never render user-controlled input as a template; use strict allowlists and sandboxing.",
                **auto_correlate("ssti"),
            )
        )
        return

    if tool == "lfi_detect" and data.get("vulnerable"):
        findings.add_finding(
            Finding(
                title="Local File Inclusion",
                severity=data.get("severity", "HIGH"),
                status="confirmed",
                category="lfi",
                description=f"Parameter `{data.get('param')}` can read local files via {data.get('payload_type')}.",
                evidence=str(data.get("evidence") or data.get("file_content_excerpt") or result.raw_output[:300]),
                url=data.get("url"),
                parameter=data.get("param"),
                payload=data.get("payload"),
                tool=tool,
                recommendation="Do not concatenate user-controlled paths; resolve paths against an allowlisted directory and block stream wrappers.",
                **auto_correlate("lfi"),
            )
        )
        return

    if tool == "unserialize_detect" and data.get("vulnerable"):
        findings.add_finding(
            Finding(
                title="PHP Unserialize Handling",
                severity=data.get("severity", "HIGH"),
                status="suspected",
                category="php_unserialize",
                description=f"Parameter `{data.get('param')}` appears to reach PHP unserialize handling.",
                evidence=str((data.get("indicators") or [])[:5]),
                url=data.get("url"),
                parameter=data.get("param"),
                tool=tool,
                recommendation="Avoid unserialize() on user input; use JSON or allowed_classes=false and authenticate serialized data.",
                **auto_correlate("php_unserialize"),
            )
        )
        return

    if tool == "flag_reader":
        findings.add_artifact(
            parent_ref=None,
            phase=phase,
            tool=tool,
            kind="flag_probe",
            summary=result.summary,
            raw_output_excerpt=result.raw_output,
            metadata=data,
        )
        if data.get("found"):
            findings.add_finding(
                Finding(
                    title="CTF Flag Found",
                    severity="CRITICAL",
                    status="exploited",
                    category="ctf_flag",
                    description=f"Flag was found via {data.get('method')} at {data.get('path')}.",
                    evidence=data.get("flag") or data.get("content_excerpt") or result.raw_output[:300],
                    url=data.get("url") or findings.target,
                    tool=tool,
                    recommendation="This is a CTF success condition. In real systems, remove exposed secrets and restrict file access.",
                )
            )
        return

    if tool == "sqli_exploit" and data.get("success"):
        for evidence_item in data.get("evidence", []):
            findings.exploit_evidence.append(
                {
                    "vulnerability": "sqli",
                    "url": data.get("url"),
                    "parameter": data.get("parameter"),
                    "probe": evidence_item.get("probe"),
                    "payload": evidence_item.get("payload"),
                    "markers": evidence_item.get("markers"),
                    "excerpt": evidence_item.get("excerpt"),
                }
            )
        _upgrade_finding_status(findings, "SQL injection", data.get("url"), data.get("parameter"), "exploited")
        findings.add_artifact(
            parent_ref=None,
            phase=phase,
            tool=tool,
            kind="exploit_evidence",
            summary=result.summary,
            raw_output_excerpt=result.raw_output,
            metadata=data,
        )
        return

    if tool == "finding_replay" and data.get("success"):
        findings.exploit_evidence.append(
            {
                "vulnerability": data.get("finding_title", "replay"),
                "url": data.get("url"),
                "parameter": data.get("parameter"),
                "probe": "replay",
                "payload": data.get("payload"),
                "markers": [f"status={data.get('status_code')}"],
                "excerpt": data.get("evidence"),
            }
        )
        _upgrade_finding_status(
            findings,
            data.get("finding_title"),
            data.get("url"),
            data.get("parameter"),
            "exploited",
        )
        findings.add_artifact(
            parent_ref=None,
            phase=phase,
            tool=tool,
            kind="exploit_evidence",
            summary=result.summary,
            raw_output_excerpt=result.raw_output,
            metadata=data,
        )
        return

    if tool == "xss_exploit" and data.get("success"):
        for evidence_item in data.get("evidence", []):
            findings.exploit_evidence.append(
                {
                    "vulnerability": "xss",
                    "url": data.get("url"),
                    "parameter": data.get("parameter"),
                    "probe": evidence_item.get("probe"),
                    "payload": evidence_item.get("payload"),
                    "markers": [
                        f"reflected={evidence_item.get('reflected')}",
                        f"httponly={evidence_item.get('cookie_httponly')}",
                        f"csp={evidence_item.get('csp_present')}",
                    ],
                    "excerpt": evidence_item.get("excerpt"),
                }
            )
        _upgrade_finding_status(findings, "Reflected XSS", data.get("url"), data.get("parameter"), "exploited")
        findings.add_artifact(
            parent_ref=None,
            phase=phase,
            tool=tool,
            kind="exploit_evidence",
            summary=result.summary,
            raw_output_excerpt=result.raw_output,
            metadata=data,
        )
        return

    if tool == "auth_bypass" and data.get("success"):
        evidence_items = data.get("evidence", [])
        bypass_type = evidence_items[0].get("type", "unknown") if evidence_items else "unknown"
        findings.add_finding(
            Finding(
                title="Authentication Bypass",
                severity=data.get("severity", "CRITICAL"),
                status="exploited",
                category="auth_bypass",
                description=f"Authentication bypass via {bypass_type} on {data.get('url')}.",
                evidence=str(evidence_items[:2]),
                url=data.get("url"),
                tool=tool,
                recommendation="Enforce strong, unique credentials; disable default accounts; implement account lockout.",
            )
        )
        findings.add_artifact(
            parent_ref=None,
            phase=phase,
            tool=tool,
            kind="exploit_evidence",
            summary=result.summary,
            raw_output_excerpt=result.raw_output,
            metadata=data,
        )
        return

    if tool == "file_upload_exploit" and data.get("success"):
        evidence_items = data.get("evidence", [])
        findings.add_finding(
            Finding(
                title="Unrestricted File Upload",
                severity=data.get("severity", "CRITICAL"),
                status="exploited",
                category="file_upload",
                description=f"Uploaded PoC file was accessible and executed on {data.get('url')}.",
                evidence=str(evidence_items[:2]),
                url=data.get("url"),
                tool=tool,
                recommendation="Validate file types server-side, store uploads outside webroot, disable execution in upload directories.",
            )
        )
        findings.add_artifact(
            parent_ref=None,
            phase=phase,
            tool=tool,
            kind="exploit_evidence",
            summary=result.summary,
            raw_output_excerpt=result.raw_output,
            metadata=data,
        )
        return

    if tool == "privilege_escalation" and data.get("success"):
        evidence_items = data.get("evidence", [])
        vectors = data.get("vectors", [])
        findings.add_finding(
            Finding(
                title="Privilege Escalation",
                severity=data.get("severity", "HIGH"),
                status="exploited",
                category="privilege_escalation",
                description=f"Privilege escalation via {', '.join(vectors)} on {data.get('url')}.",
                evidence=str(evidence_items[:2]),
                url=data.get("url"),
                tool=tool,
                recommendation="Enforce server-side authorization checks; use indirect object references; validate role parameters.",
            )
        )
        findings.add_artifact(
            parent_ref=None,
            phase=phase,
            tool=tool,
            kind="exploit_evidence",
            summary=result.summary,
            raw_output_excerpt=result.raw_output,
            metadata=data,
        )

    # ---- Shannon-integrated tools ----

    if tool == "headers_audit":
        issues = data.get("issues", [])
        missing = data.get("missing_headers", [])
        info_disclosure = data.get("info_disclosure", [])
        insecure_cookies = data.get("insecure_cookies", [])
        score = data.get("security_score", 100)

        if missing:
            cwe = auto_correlate("security_headers")
            findings.add_finding(
                Finding(
                    title="Missing HTTP Security Headers",
                    severity="MEDIUM" if score >= 50 else "HIGH",
                    status="confirmed",
                    category="security_headers",
                    description=f"Missing security headers: {', '.join(missing)}. Security score: {score}/100",
                    evidence=", ".join(missing),
                    url=data.get("target") or findings.target,
                    tool=tool,
                    recommendation="Implement all recommended security headers. See OWASP Secure Headers Project.",
                    **cwe,
                )
            )
        for issue in issues:
            if issue.get("type") == "weak":
                cwe = auto_correlate("security_headers")
                findings.add_finding(
                    Finding(
                        title=f"Weak security header: {issue['header']}",
                        severity=issue.get("severity", "LOW"),
                        status="confirmed",
                        category="security_headers",
                        description=issue.get("description", ""),
                        evidence=f"{issue['header']}: {issue.get('value', '')}",
                        url=data.get("target") or findings.target,
                        tool=tool,
                        recommendation=issue.get("recommendation", ""),
                        **cwe,
                    )
                )
        for disc in info_disclosure:
            cwe = auto_correlate("info_disclosure")
            findings.add_finding(
                Finding(
                    title=f"Information Disclosure: {disc['header']}",
                    severity="LOW",
                    status="confirmed",
                    category="info_disclosure",
                    description=disc.get("description", ""),
                    evidence=f"{disc['header']}: {disc.get('value', '')}",
                    url=data.get("target") or findings.target,
                    tool=tool,
                    recommendation=disc.get("recommendation", ""),
                    **cwe,
                )
            )
        for cookie in insecure_cookies:
            cwe = auto_correlate("insecure_cookie")
            findings.add_finding(
                Finding(
                    title=f"Insecure Cookie: {cookie['name']}",
                    severity="LOW",
                    status="confirmed",
                    category="insecure_cookie",
                    description=f"Cookie '{cookie['name']}' has issues: {', '.join(cookie['issues'])}",
                    evidence=str(cookie),
                    url=data.get("target") or findings.target,
                    tool=tool,
                    recommendation="Set Secure and HttpOnly flags on all cookies; use SameSite=Strict where possible.",
                    **cwe,
                )
            )
        findings.add_artifact(
            parent_ref=None,
            phase=phase,
            tool=tool,
            kind="headers_audit",
            summary=result.summary,
            raw_output_excerpt=result.raw_output,
            metadata=data,
        )
        return

    if tool == "js_analyze":
        findings_dict = data.get("findings", {})
        for category, hits in findings_dict.items():
            for hit in hits[:5]:
                if category == "api_keys":
                    cwe = auto_correlate("js_secret")
                    findings.add_finding(
                        Finding(
                            title="Hardcoded API Key in JS",
                            severity="HIGH",
                            status="confirmed",
                            category="js_secret",
                            description=f"API key detected: {hit.get('match', '')[:60]}",
                            evidence=hit.get("context", ""),
                            url=data.get("url") or findings.target,
                            tool=tool,
                            recommendation="Remove secrets from client-side code; use environment variables and backend proxies.",
                            **cwe,
                        )
                    )
                elif category == "credentials":
                    cwe = auto_correlate("js_secret")
                    findings.add_finding(
                        Finding(
                            title="Hardcoded Credentials in JS",
                            severity="HIGH",
                            status="confirmed",
                            category="js_secret",
                            description=f"Credential pattern found: {hit.get('match', '')[:60]}",
                            evidence=hit.get("context", ""),
                            url=data.get("url") or findings.target,
                            tool=tool,
                            recommendation="Never embed credentials in client-side code.",
                            **cwe,
                        )
                    )
                elif category == "xss_sinks":
                    cwe = auto_correlate("js_xss_sink")
                    findings.add_finding(
                        Finding(
                            title=f"XSS Sink in JS: {hit.get('match', '')[:40]}",
                            severity="MEDIUM",
                            status="suspected",
                            category="js_xss_sink",
                            description=f"Dangerous DOM operation: {hit.get('match', '')[:80]}",
                            evidence=hit.get("context", ""),
                            url=data.get("url") or findings.target,
                            tool=tool,
                            recommendation="Use textContent instead of innerHTML; sanitize DOM inputs.",
                            **cwe,
                        )
                    )
        return

    if tool == "param_fuzzer":
        hits = data.get("hits", [])
        for hit in hits:
            vuln_type = hit.get("type", "")
            category = vuln_type.split("_")[0] if "_" not in vuln_type else vuln_type
            cwe = auto_correlate(category) or auto_correlate("ssti")
            findings.add_finding(
                Finding(
                    title=f"Parameter Injection: {vuln_type}",
                    severity=hit.get("severity", "MEDIUM"),
                    status="confirmed",
                    category=category,
                    description=f"Vulnerability via parameter fuzzing ({vuln_type}). Payload: {hit.get('payload', '')}",
                    evidence=f"Status: {hit.get('status')}, Size: {hit.get('response_size')}",
                    url=data.get("url"),
                    parameter=data.get("parameter"),
                    payload=hit.get("payload"),
                    tool=tool,
                    recommendation="Validate and sanitize all user input; use allow-lists.",
                    **cwe,
                )
            )
        return

    if tool == "logic_audit":
        issues = data.get("issues", [])
        for issue in issues:
            cwe = auto_correlate("logic_flaw")
            findings.add_finding(
                Finding(
                    title=f"Business Logic Flaw: {issue.get('mutation', '')}",
                    severity=issue.get("severity", "HIGH"),
                    status="confirmed",
                    category="logic_flaw",
                    description=f"Field '{issue.get('field', '')}' accepted {issue.get('mutation', '')} value: {issue.get('value', '')}",
                    evidence=f"Form URL: {issue.get('form_url', '')}, Status: {issue.get('status_code')}",
                    url=issue.get("form_url"),
                    parameter=issue.get("field"),
                    payload=issue.get("value"),
                    tool=tool,
                    recommendation="Implement server-side validation for all business logic constraints.",
                    **cwe,
                )
            )
        return

    if tool == "idor_test":
        hits = data.get("hits", [])
        for hit in hits:
            cwe = auto_correlate("idor")
            findings.add_finding(
                Finding(
                    title="Insecure Direct Object Reference (IDOR)",
                    severity="HIGH",
                    status="confirmed" if hit.get("confirmed") else "suspected",
                    category="idor",
                    description=f"IDOR at {hit.get('endpoint', '')} — accessed resource with ID {hit.get('tested_id', '')}",
                    evidence=hit.get("evidence", ""),
                    url=hit.get("endpoint"),
                    parameter=hit.get("parameter"),
                    payload=str(hit.get("tested_id", "")),
                    tool=tool,
                    recommendation="Enforce object-level authorization checks; use indirect references.",
                    **cwe,
                )
            )
        return

    if tool == "rate_limit_test":
        action = data.get("action", "")
        if action == "burst" and not data.get("rate_limit_detected"):
            cwe = auto_correlate("rate_limit")
            findings.add_finding(
                Finding(
                    title="Missing Rate Limiting",
                    severity="MEDIUM",
                    status="confirmed",
                    category="rate_limit",
                    description=f"Sent {data.get('total_requests', 0)} requests without being rate-limited ({data.get('success_count', 0)} succeeded).",
                    evidence=f"Blocked: {data.get('blocked_count', 0)}/{data.get('total_requests', 0)}",
                    url=data.get("target"),
                    tool=tool,
                    recommendation="Implement rate limiting per IP/session; use exponential backoff.",
                    **cwe,
                )
            )
        elif action == "timing" and data.get("timing_vulnerability"):
            cwe = auto_correlate("timing_attack")
            findings.add_finding(
                Finding(
                    title="Timing-Based User Enumeration",
                    severity="MEDIUM",
                    status="confirmed",
                    category="timing_attack",
                    description=f"Timing difference of {data.get('diff_ms', 0)}ms ({data.get('diff_pct', 0)}%) between valid and invalid inputs.",
                    evidence=f"Valid avg: {data.get('avg_valid_ms')}ms, Invalid avg: {data.get('avg_invalid_ms')}ms",
                    url=data.get("target"),
                    tool=tool,
                    recommendation="Use constant-time comparison for authentication; add random jitter.",
                    **cwe,
                )
            )
        elif action == "race" and data.get("race_condition"):
            cwe = auto_correlate("race_condition")
            findings.add_finding(
                Finding(
                    title="Race Condition",
                    severity="HIGH",
                    status="confirmed",
                    category="race_condition",
                    description=f"{data.get('success_count', 0)}/{data.get('concurrent', 0)} concurrent requests succeeded simultaneously.",
                    evidence=str(data.get("results", [])[:5]),
                    url=data.get("target"),
                    tool=tool,
                    recommendation="Use database-level locks or atomic operations for critical state changes.",
                    **cwe,
                )
            )
        return

    if tool == "browser_test":
        vulns = data.get("vulnerabilities", [])
        for vuln in vulns:
            category = vuln.get("category", "xss")
            cwe = auto_correlate(category) or auto_correlate("xss")
            findings.add_finding(
                Finding(
                    title=vuln.get("title", "Browser Test Finding"),
                    severity=vuln.get("severity", "MEDIUM"),
                    status="confirmed",
                    category=category,
                    description=vuln.get("description", ""),
                    evidence=vuln.get("evidence", ""),
                    url=data.get("target") or findings.target,
                    tool=tool,
                    recommendation=vuln.get("recommendation", ""),
                    **cwe,
                )
            )
        findings.add_artifact(
            parent_ref=None,
            phase=phase,
            tool=tool,
            kind="browser_test",
            summary=result.summary,
            raw_output_excerpt=result.raw_output,
            metadata=data,
        )
        return

    if tool == "nuclei_scan":
        matches = data.get("matches", [])
        for match in matches:
            category = match.get("type", "misc")
            cwe = auto_correlate(category)
            findings.add_finding(
                Finding(
                    title=match.get("name", "Nuclei Finding"),
                    severity=match.get("severity", "MEDIUM"),
                    status="confirmed",
                    category=category,
                    description=match.get("description", f"Matched template: {match.get('template_id', '')}"),
                    evidence=match.get("matched_at", ""),
                    url=match.get("matched_at") or data.get("target"),
                    tool=tool,
                    recommendation=match.get("remediation", ""),
                    **(cwe or {}),
                )
            )
        return

    if tool == "hydra_crack" and data.get("cracked"):
        for cred in data.get("credentials", []):
            findings.add_finding(
                Finding(
                    title=f"Cracked Credentials: {cred.get('service', '')}",
                    severity="CRITICAL",
                    status="exploited",
                    category="auth_bypass",
                    description=f"Successfully cracked {cred.get('service', '')} credentials for user '{cred.get('username', '')}'.",
                    evidence=f"User: {cred.get('username', '')}, Service: {cred.get('service', '')}",
                    url=data.get("target"),
                    tool=tool,
                    recommendation="Enforce strong password policies; implement account lockout; use MFA.",
                    **auto_correlate("auth_bypass"),
                )
            )
        return


def _upgrade_finding_status(
    findings: StateFindings,
    title: str | None,
    url: str | None,
    parameter: str | None,
    new_status: str,
) -> None:
    for finding in findings.findings:
        if finding.title == title and finding.url == url and finding.parameter == parameter:
            from .findings import STATUS_ORDER
            if STATUS_ORDER.get(new_status, 0) > STATUS_ORDER.get(finding.status, 0):
                finding.status = new_status
            return
