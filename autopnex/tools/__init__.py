"""Tool package: auto-import all concrete tool modules to populate ToolRegistry."""
from __future__ import annotations

from .base import BaseTool, ToolResult, ToolRegistry  # noqa: F401


def load_all() -> None:
    """Import all tool modules so @ToolRegistry.register decorators fire."""
    from .recon import port_scanner, tech_detector, subdomain_finder, nmap_scan  # noqa: F401
    from .scan import web_scanner, dir_buster, crawler, ffuf_scan, burp_proxy_scan  # noqa: F401
    from .scan import headers_audit  # noqa: F401
    from .vuln import sqli_detector, xss_detector, ssrf_detector, cmdi_detector, sqlmap_scan  # noqa: F401
    from .exploit import sqli_exploiter, finding_replay  # noqa: F401
    from .exploit import xss_exploiter, auth_bypass, file_upload_exploit, privilege_escalation  # noqa: F401
    # Shannon-integrated tools
    from .api_security import idor_test, js_analyze, rate_limit_test  # noqa: F401
    from .api_security import session_manager, param_fuzzer, logic_audit  # noqa: F401
    from .browser import browser_test  # noqa: F401
    # CTF web exploitation tools
    from .ctf_web import ssti_detect, lfi_detect, unserialize_detect, flag_reader  # noqa: F401
    # CTF pwn exploitation tools
    from .ctf_pwn import checksec, rop_chain, format_string, remote_interact  # noqa: F401
    # Docker-backed tools (optional — only loaded if docker package available)
    try:
        from .docker_tools import docker_exec, nuclei_scan, hydra_crack, gowitness  # noqa: F401
    except Exception:  # noqa: BLE001
        pass


load_all()
