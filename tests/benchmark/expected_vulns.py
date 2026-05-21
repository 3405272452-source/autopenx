"""Ground truth vulnerability definitions for each benchmark target.

Each target entry contains:
- vulns:  known vulnerabilities with type, path, parameter, severity
- expected_ports:  ports the target exposes inside the container
- expected_techs:  technologies a proper recon phase should identify
- expected_paths:  key paths a scan phase should discover
"""
from __future__ import annotations

from typing import Any, Dict

DVWA_EXPECTED: Dict[str, Any] = {
    "vulns": [
        {
            "type": "sqli",
            "path": "/vulnerabilities/sqli/",
            "parameter": "id",
            "severity": "HIGH",
            "description": "SQL injection via id parameter",
        },
        {
            "type": "xss_reflected",
            "path": "/vulnerabilities/xss_r/",
            "parameter": "name",
            "severity": "MEDIUM",
            "description": "Reflected XSS in name field",
        },
        {
            "type": "cmdi",
            "path": "/vulnerabilities/exec/",
            "parameter": "ip",
            "severity": "CRITICAL",
            "description": "OS command injection via ip parameter",
        },
        {
            "type": "file_upload",
            "path": "/vulnerabilities/upload/",
            "parameter": "uploaded",
            "severity": "HIGH",
            "description": "Unrestricted file upload allows web shell",
        },
        {
            "type": "csrf",
            "path": "/vulnerabilities/csrf/",
            "parameter": "password_new",
            "severity": "MEDIUM",
            "description": "Password change without CSRF token",
        },
        {
            "type": "lfi",
            "path": "/vulnerabilities/fi/",
            "parameter": "page",
            "severity": "HIGH",
            "description": "Local file inclusion via page parameter",
        },
        {
            "type": "xss_stored",
            "path": "/vulnerabilities/xss_s/",
            "parameter": "txtName",
            "severity": "HIGH",
            "description": "Stored XSS in guestbook name field",
        },
        {
            "type": "brute_force",
            "path": "/vulnerabilities/brute/",
            "parameter": "username",
            "severity": "MEDIUM",
            "description": "Login form with no rate-limiting or lockout",
        },
    ],
    "expected_ports": [80],
    "expected_techs": ["apache", "php", "mysql"],
    "expected_paths": [
        "/login.php",
        "/index.php",
        "/phpinfo.php",
        "/robots.txt",
        "/setup.php",
        "/security.php",
    ],
}

JUICE_SHOP_EXPECTED: Dict[str, Any] = {
    "vulns": [
        {
            "type": "sqli",
            "path": "/rest/products/search",
            "parameter": "q",
            "severity": "HIGH",
            "description": "SQL injection in product search",
        },
        {
            "type": "xss_reflected",
            "path": "/",
            "parameter": "search",
            "severity": "MEDIUM",
            "description": "DOM-based reflected XSS via search",
        },
        {
            "type": "idor",
            "path": "/api/Baskets/",
            "parameter": "id",
            "severity": "HIGH",
            "description": "Insecure direct object reference on baskets",
        },
        {
            "type": "ssrf",
            "path": "/profile/image/url",
            "parameter": "imageUrl",
            "severity": "HIGH",
            "description": "SSRF via profile image URL parameter",
        },
        {
            "type": "auth_bypass",
            "path": "/rest/user/login",
            "parameter": "email",
            "severity": "CRITICAL",
            "description": "Authentication bypass via SQL injection in login",
        },
        {
            "type": "sensitive_exposure",
            "path": "/ftp/",
            "parameter": "",
            "severity": "MEDIUM",
            "description": "Exposed FTP directory with sensitive files",
        },
    ],
    "expected_ports": [3000],
    "expected_techs": ["express", "node.js", "angular"],
    "expected_paths": [
        "/api/",
        "/rest/",
        "/ftp/",
        "/assets/",
        "/api/Products",
        "/rest/user/login",
    ],
}

WEBGOAT_EXPECTED: Dict[str, Any] = {
    "vulns": [
        {
            "type": "sqli",
            "path": "/WebGoat/SqlInjection/attack5a",
            "parameter": "account",
            "severity": "HIGH",
            "description": "SQL injection lesson - string injection",
        },
        {
            "type": "xss_reflected",
            "path": "/WebGoat/CrossSiteScripting/attack5a",
            "parameter": "field1",
            "severity": "MEDIUM",
            "description": "Reflected XSS lesson",
        },
        {
            "type": "xxe",
            "path": "/WebGoat/xxe/simple",
            "parameter": "xml",
            "severity": "HIGH",
            "description": "XML External Entity injection",
        },
        {
            "type": "path_traversal",
            "path": "/WebGoat/PathTraversal/random",
            "parameter": "fullName",
            "severity": "HIGH",
            "description": "Path traversal via file name parameter",
        },
        {
            "type": "insecure_deserialization",
            "path": "/WebGoat/InsecureDeserialization/task",
            "parameter": "token",
            "severity": "CRITICAL",
            "description": "Java deserialization vulnerability",
        },
        {
            "type": "jwt_bypass",
            "path": "/WebGoat/JWT/secret/gettoken",
            "parameter": "token",
            "severity": "HIGH",
            "description": "JWT secret bypass via weak key",
        },
    ],
    "expected_ports": [8080],
    "expected_techs": ["spring-boot", "java", "tomcat"],
    "expected_paths": [
        "/WebGoat/login",
        "/WebGoat/start.mvc",
        "/WebGoat/service/",
        "/WebGoat/images/",
    ],
}

ALL_EXPECTED: Dict[str, Dict[str, Any]] = {
    "dvwa": DVWA_EXPECTED,
    "juice-shop": JUICE_SHOP_EXPECTED,
    "webgoat": WEBGOAT_EXPECTED,
}


def get_expected(target_name: str) -> Dict[str, Any]:
    """Return expected vulnerability data for a target, or raise ValueError."""
    if target_name not in ALL_EXPECTED:
        raise ValueError(
            f"No expected vulns for {target_name!r}. "
            f"Available: {list(ALL_EXPECTED)}"
        )
    return ALL_EXPECTED[target_name]
