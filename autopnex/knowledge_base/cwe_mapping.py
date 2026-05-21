"""CWE / OWASP Top 10 / CVSS mapping for vulnerability categories.

Auto-correlates finding categories to standardized identifiers for
compliance reporting and severity scoring.
"""
from __future__ import annotations

from typing import Dict, Optional, Tuple


# (CWE_ID, OWASP_2021_Category, CVSS_Base_Score, CVSS_Vector)
VULN_CWE_MAP: Dict[str, Tuple[str, str, float, str]] = {
    "sqli": (
        "CWE-89",
        "A03:2021-Injection",
        9.8,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    ),
    "xss": (
        "CWE-79",
        "A03:2021-Injection",
        6.1,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    ),
    "ssrf": (
        "CWE-918",
        "A10:2021-Server-Side Request Forgery",
        8.6,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
    ),
    "cmdi": (
        "CWE-78",
        "A03:2021-Injection",
        9.8,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    ),
    "idor": (
        "CWE-639",
        "A01:2021-Broken Access Control",
        7.5,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    ),
    "auth_bypass": (
        "CWE-287",
        "A07:2021-Identification and Authentication Failures",
        9.8,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    ),
    "file_upload": (
        "CWE-434",
        "A04:2021-Insecure Design",
        9.8,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    ),
    "privilege_escalation": (
        "CWE-269",
        "A01:2021-Broken Access Control",
        8.8,
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    ),
    "security_headers": (
        "CWE-693",
        "A05:2021-Security Misconfiguration",
        3.1,
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
    ),
    "sensitive_file": (
        "CWE-538",
        "A01:2021-Broken Access Control",
        5.3,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    ),
    "rate_limit": (
        "CWE-770",
        "A04:2021-Insecure Design",
        5.3,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
    ),
    "race_condition": (
        "CWE-362",
        "A04:2021-Insecure Design",
        7.5,
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
    ),
    "timing_attack": (
        "CWE-208",
        "A07:2021-Identification and Authentication Failures",
        5.3,
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
    ),
    "js_secret": (
        "CWE-200",
        "A01:2021-Broken Access Control",
        5.3,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    ),
    "js_xss_sink": (
        "CWE-79",
        "A03:2021-Injection",
        6.1,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    ),
    "logic_flaw": (
        "CWE-840",
        "A04:2021-Insecure Design",
        7.5,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
    ),
    "ssti": (
        "CWE-1336",
        "A03:2021-Injection",
        9.8,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    ),
    "lfi": (
        "CWE-98",
        "A03:2021-Injection",
        7.5,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    ),
    "xxe": (
        "CWE-611",
        "A05:2021-Security Misconfiguration",
        9.1,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H",
    ),
    "cors_misconfiguration": (
        "CWE-942",
        "A05:2021-Security Misconfiguration",
        5.3,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    ),
    "open_redirect": (
        "CWE-601",
        "A01:2021-Broken Access Control",
        3.5,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
    ),
    "crlf_injection": (
        "CWE-93",
        "A03:2021-Injection",
        5.4,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
    ),
    "prototype_pollution": (
        "CWE-1321",
        "A03:2021-Injection",
        6.5,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
    ),
    "jwt_weakness": (
        "CWE-347",
        "A07:2021-Identification and Authentication Failures",
        7.5,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    ),
    "http_request_smuggling": (
        "CWE-444",
        "A03:2021-Injection",
        8.1,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
    ),
    "insecure_deserialization": (
        "CWE-502",
        "A08:2021-Software and Data Integrity Failures",
        9.8,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    ),
    "graphql_introspection": (
        "CWE-200",
        "A01:2021-Broken Access Control",
        5.3,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    ),
    "info_disclosure": (
        "CWE-200",
        "A01:2021-Broken Access Control",
        5.3,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    ),
    "insecure_cookie": (
        "CWE-614",
        "A05:2021-Security Misconfiguration",
        4.3,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
    ),
}


# OWASP Top 10 2021 summary for report appendix
OWASP_TOP10_2021: Dict[str, str] = {
    "A01:2021-Broken Access Control": "限制超出预期权限的操作失败",
    "A02:2021-Cryptographic Failures": "敏感数据暴露与加密实现缺陷",
    "A03:2021-Injection": "用户输入未充分验证导致注入攻击",
    "A04:2021-Insecure Design": "缺乏安全设计模式与威胁建模",
    "A05:2021-Security Misconfiguration": "安全配置缺失或不当",
    "A06:2021-Vulnerable and Outdated Components": "使用已知漏洞的组件",
    "A07:2021-Identification and Authentication Failures": "身份验证与会话管理缺陷",
    "A08:2021-Software and Data Integrity Failures": "代码与数据完整性验证不足",
    "A09:2021-Security Logging and Monitoring Failures": "日志记录与监控不足",
    "A10:2021-Server-Side Request Forgery": "服务端请求伪造",
}


def lookup_cwe(category: str) -> Optional[Tuple[str, str, float, str]]:
    """Return (CWE, OWASP, CVSS, vector) for a finding category, or None."""
    return VULN_CWE_MAP.get(category)


def auto_correlate(category: str) -> Dict[str, Optional[str]]:
    """Return a dict of cwe_id, owasp_category, cvss_score, cvss_vector."""
    mapping = VULN_CWE_MAP.get(category)
    if mapping:
        cwe_id, owasp, cvss, vector = mapping
        return {
            "cwe_id": cwe_id,
            "owasp_category": owasp,
            "cvss_score": cvss,
            "cvss_vector": vector,
        }
    return {
        "cwe_id": None,
        "owasp_category": None,
        "cvss_score": None,
        "cvss_vector": None,
    }
