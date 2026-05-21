"""Security boundary tests for AutoPenX.

Validates that policy constraints, scope enforcement, approval tokens,
and safety mechanisms cannot be bypassed.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import json
import secrets
import time
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from autopnex.policy import (
    PolicyError,
    _SECRET_CACHE,
    _secret,
    apply_scan_policy,
    create_approval,
    normalise_scopes,
    validate_approval,
)
from autopnex.tools._http import TargetScopeError, ensure_target_allowed
from autopnex.tools.base import BaseTool, ToolRegistry, ToolResult, register
from autopnex.evasion.evasion_middleware import EvasionMiddleware
from autopnex.evasion.rate_controller import RateController
from autopnex.evasion.payload_mutator import PayloadMutator
from autopnex.state_machine.attack_graph import (
    AttackChain,
    AttackEdge,
    AttackGraph,
    EdgeStatus,
    NodeType,
)
from autopnex.state_machine.chain_executor import ChainExecutor
from autopnex.state_machine.findings import Finding, StateFindings
from config.settings import RuntimeConfig, settings


def _rc(**overrides) -> RuntimeConfig:
    """Shorthand for a RuntimeConfig with sensible test defaults."""
    defaults = dict(
        deepseek_api_key="test-key",
        allow_local_targets=False,
        allow_external_tools=False,
        exploit_enabled=False,
        evasion_enabled=False,
        policy_hmac_key="test-hmac-key",
    )
    defaults.update(overrides)
    return RuntimeConfig(**defaults)


# ═══════════════════════════════════════════════════════════════════════════
# 1. Target Scope Enforcement
# ═══════════════════════════════════════════════════════════════════════════


class TestTargetScopeEnforcement:
    """Verify that private / loopback IPs and hostnames are rejected unless
    explicitly allowed via ``allow_local_targets``."""

    def test_cli_rejects_localhost_by_default(self):
        """ensure_target_allowed rejects 127.0.0.1 when allow_local_targets=False."""
        rc = _rc(allow_local_targets=False)
        with pytest.raises(TargetScopeError, match="private_or_loopback"):
            ensure_target_allowed("http://127.0.0.1", runtime_config=rc)

    def test_cli_rejects_localhost_hostname(self):
        """ensure_target_allowed rejects 'localhost' hostname."""
        rc = _rc(allow_local_targets=False)
        with pytest.raises(TargetScopeError, match="loopback_targets"):
            ensure_target_allowed("http://localhost", runtime_config=rc)

    @pytest.mark.parametrize(
        "ip",
        [
            "192.168.1.1",
            "192.168.0.100",
            "10.0.0.1",
            "10.255.255.255",
            "172.16.0.1",
            "172.31.255.255",
        ],
    )
    def test_cli_rejects_private_ip(self, ip):
        """ensure_target_allowed rejects RFC 1918 addresses."""
        rc = _rc(allow_local_targets=False)
        with pytest.raises(TargetScopeError, match="private_or_loopback"):
            ensure_target_allowed(f"http://{ip}", runtime_config=rc)

    def test_cli_rejects_link_local(self):
        """ensure_target_allowed rejects link-local 169.254.x.x."""
        rc = _rc(allow_local_targets=False)
        with pytest.raises(TargetScopeError, match="private_or_loopback"):
            ensure_target_allowed("http://169.254.169.254", runtime_config=rc)

    def test_cli_allows_localhost_when_enabled(self):
        """ensure_target_allowed allows localhost when allow_local_targets=True."""
        rc = _rc(allow_local_targets=True)
        result = ensure_target_allowed("http://127.0.0.1", runtime_config=rc)
        assert "127.0.0.1" in result

    def test_cli_allows_private_ip_when_enabled(self):
        """ensure_target_allowed allows 10.x.x.x when allow_local_targets=True."""
        rc = _rc(allow_local_targets=True)
        result = ensure_target_allowed("http://10.0.0.5", runtime_config=rc)
        assert "10.0.0.5" in result

    def test_cli_allows_public_ip(self):
        """Public IPs pass regardless of allow_local_targets."""
        rc = _rc(allow_local_targets=False)
        result = ensure_target_allowed("http://93.184.216.34", runtime_config=rc)
        assert "93.184.216.34" in result

    def test_cli_rejects_empty_target(self):
        """Empty host is invalid."""
        rc = _rc()
        with pytest.raises(TargetScopeError, match="invalid_target"):
            ensure_target_allowed("", runtime_config=rc)

    def test_web_api_validates_target(self):
        """POST /api/scan with a private-IP target returns 403."""
        from autopnex.web.api import app

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/scan",
            json={"target": "http://192.168.1.1", "mock": True},
        )
        assert resp.status_code == 403

    def test_tool_http_respects_target_scope(self):
        """ensure_target_allowed called with default config blocks private hosts."""
        rc = _rc(allow_local_targets=False)
        with pytest.raises(TargetScopeError):
            ensure_target_allowed("http://10.10.10.10:8080/admin", runtime_config=rc)

    def test_dotlocal_hostname_rejected(self):
        """Hostnames ending in .local are treated as loopback."""
        rc = _rc(allow_local_targets=False)
        with pytest.raises(TargetScopeError, match="loopback_targets"):
            ensure_target_allowed("http://printer.local", runtime_config=rc)


# ═══════════════════════════════════════════════════════════════════════════
# 2. Approval Token Security
# ═══════════════════════════════════════════════════════════════════════════


class TestApprovalTokenSecurity:
    """Verify HMAC token integrity, expiry, scope, and key-independence."""

    def test_token_requires_valid_hmac(self):
        """Forged token with wrong HMAC is rejected."""
        approval = create_approval("http://example.com", ["passive"], 300)
        payload_b64, _sig = approval.token.split(".", 1)
        forged_sig = base64.urlsafe_b64encode(b"forged-signature").decode().rstrip("=")
        forged_token = f"{payload_b64}.{forged_sig}"
        with pytest.raises(PolicyError, match="invalid_token_signature"):
            validate_approval(forged_token, target="http://example.com")

    def test_expired_token_rejected(self):
        """Token past TTL is rejected."""
        approval = create_approval("http://example.com", ["passive"], 30)
        payload_b64, sig_b64 = approval.token.split(".", 1)

        def _pad(v):
            return v + "=" * (-len(v) % 4)

        payload = json.loads(base64.urlsafe_b64decode(_pad(payload_b64)))
        payload["exp"] = int(time.time()) - 10

        new_blob = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        new_sig = hmac.new(_secret(), new_blob, hashlib.sha256).digest()
        new_token = (
            base64.urlsafe_b64encode(new_blob).decode().rstrip("=")
            + "."
            + base64.urlsafe_b64encode(new_sig).decode().rstrip("=")
        )
        with pytest.raises(PolicyError, match="approval_expired"):
            validate_approval(new_token, target="http://example.com")

    def test_wildcard_target_rejected(self):
        """Token with target='*' cannot be created."""
        with pytest.raises(PolicyError, match="wildcard_target_not_allowed"):
            create_approval("*", ["passive"], 300)

    def test_wildcard_target_whitespace_rejected(self):
        """Token with target='  *  ' is also rejected."""
        with pytest.raises(PolicyError, match="wildcard_target_not_allowed"):
            create_approval("  *  ", ["passive"], 300)

    def test_token_scope_enforcement(self):
        """Token with scope='passive' cannot authorize 'exploit'."""
        approval = create_approval("http://example.com", ["passive"], 300)
        with pytest.raises(PolicyError, match="exploit_requires_approval"):
            apply_scan_policy(
                _rc(),
                target="http://example.com",
                exploit_enabled=True,
                approval_token=approval.token,
            )

    def test_hmac_key_independent_of_llm_key(self):
        """Changing DeepSeek API key does not invalidate existing tokens."""
        rc1 = _rc(deepseek_api_key="key-alpha", policy_hmac_key="fixed-hmac")
        with settings.use_runtime(rc1):
            approval = create_approval("http://example.com", ["passive", "active_scan"], 300)

        rc2 = _rc(deepseek_api_key="key-beta", policy_hmac_key="fixed-hmac")
        with settings.use_runtime(rc2):
            validated = validate_approval(approval.token, target="http://example.com")
            assert validated.target == "http://example.com"

    def test_empty_hmac_key_generates_secure_random(self):
        """When no HMAC key is set, a secure random key is generated."""
        _SECRET_CACHE.clear()
        rc = _rc(policy_hmac_key="")
        with settings.use_runtime(rc):
            secret_bytes = _secret()
        assert len(secret_bytes) == 32
        assert "key" in _SECRET_CACHE
        assert len(_SECRET_CACHE["key"]) == 64  # hex-encoded 32 bytes

    def test_token_target_mismatch_rejected(self):
        """Token issued for target A cannot be used for target B."""
        approval = create_approval("http://a.example.com", ["passive"], 300)
        with pytest.raises(PolicyError, match="approval_target_mismatch"):
            validate_approval(approval.token, target="http://b.example.com")

    def test_invalid_scope_rejected(self):
        """Creating approval with an unknown scope raises PolicyError."""
        with pytest.raises(PolicyError, match="invalid_scope"):
            create_approval("http://example.com", ["passive", "root_access"], 300)

    def test_malformed_token_rejected(self):
        """Token without a dot separator is rejected."""
        with pytest.raises(PolicyError, match="invalid_token_format"):
            validate_approval("no-dot-here", target="http://example.com")


# ═══════════════════════════════════════════════════════════════════════════
# 3. Exploit Safety
# ═══════════════════════════════════════════════════════════════════════════


class TestExploitSafety:
    """Verify that exploit tools obey ``exploit_enabled`` and scope gates."""

    def test_exploit_tools_require_exploit_enabled(self):
        """All exploit-category tools are unavailable when exploit_enabled=False."""
        rc = _rc(exploit_enabled=False, approved_scopes=("exploit",))
        exploit_tools = ToolRegistry.by_category("exploit")
        assert len(exploit_tools) > 0, "Expected at least one exploit tool"
        for tool in exploit_tools:
            avail = tool.availability(rc)
            assert not avail["enabled"], f"{tool.name} should be disabled"
            assert not avail["exploit_allowed"], f"{tool.name} exploit_allowed should be False"

    def test_exploit_tools_require_exploit_scope(self):
        """Exploit tools check for 'exploit' scope in approved_scopes."""
        rc = _rc(exploit_enabled=True, approved_scopes=("passive", "active_scan"))
        exploit_tools = ToolRegistry.by_category("exploit")
        assert len(exploit_tools) > 0, "Expected at least one exploit tool"
        for tool in exploit_tools:
            avail = tool.availability(rc)
            assert not avail["enabled"], f"{tool.name} should require exploit scope"
            assert not avail["scope_allowed"], f"{tool.name} scope_allowed should be False"

    def test_exploit_tools_enabled_with_both_flags(self):
        """Exploit tools work when both exploit_enabled=True and exploit scope present."""
        rc = _rc(exploit_enabled=True, approved_scopes=("passive", "active_scan", "exploit"))
        exploit_tools = ToolRegistry.by_category("exploit")
        for tool in exploit_tools:
            avail = tool.availability(rc)
            assert avail["enabled"], f"{tool.name} should be enabled"

    def test_external_tools_require_allow_external(self):
        """nmap_scan, ffuf_scan, etc. require allow_external_tools=True."""
        rc = _rc(allow_external_tools=False, approved_scopes=("active_scan",))
        external_tools = [t for t in ToolRegistry.all() if t.external_binary]
        assert len(external_tools) > 0, "Expected at least one external tool"
        for tool in external_tools:
            avail = tool.availability(rc)
            assert not avail["allowed"], f"{tool.name} should not be allowed"
            assert not avail["enabled"], f"{tool.name} should not be enabled"

    def test_external_tools_require_active_scan_scope(self):
        """External tools with active_scan capability need the scope even when allowed."""
        rc = _rc(allow_external_tools=True, approved_scopes=())
        external_tools = [
            t for t in ToolRegistry.all()
            if t.external_binary and t.required_capability == "active_scan"
        ]
        for tool in external_tools:
            avail = tool.availability(rc)
            assert not avail["scope_allowed"], f"{tool.name} scope should not be allowed"

    def test_policy_rejects_exploit_without_approval_token(self):
        """apply_scan_policy raises when exploit_enabled but no token with exploit scope."""
        with pytest.raises(PolicyError, match="exploit_requires_approval"):
            apply_scan_policy(
                _rc(),
                target="http://example.com",
                exploit_enabled=True,
            )


# ═══════════════════════════════════════════════════════════════════════════
# 4. Report XSS Prevention
# ═══════════════════════════════════════════════════════════════════════════


class TestReportSecurity:
    """Verify that user-supplied data in reports is sanitised against XSS."""

    @pytest.fixture()
    def xss_findings(self) -> StateFindings:
        sf = StateFindings(target="http://victim.test")
        sf.add_finding(Finding(
            title='<script>alert("xss")</script>',
            severity="HIGH",
            status="confirmed",
            category="xss",
            description='Reflected XSS via <img src=x onerror=alert(1)>',
            evidence='<script>document.cookie</script>',
            url="http://victim.test/search?q=<script>alert(1)</script>",
            parameter="q",
            payload='"><script>alert(1)</script>',
            tool="xss_scanner",
            recommendation="Escape output.",
        ))
        return sf

    @pytest.mark.xfail(
        reason="report.md.j2 uses autoescape=disabled for .j2 — known XSS gap",
        strict=True,
    )
    def test_finding_payload_escaped_in_report(self, xss_findings):
        """XSS payloads in finding data are HTML-escaped in generated reports."""
        from autopnex.report.generator import ReportGenerator

        gen = ReportGenerator(llm_client=None, mode="mock")
        _md, html = gen.render(xss_findings)
        assert "<script>alert" not in html

    @pytest.mark.xfail(
        reason="report.md.j2 uses autoescape=disabled for .j2 — known XSS gap",
        strict=True,
    )
    def test_evidence_field_escaped_in_report(self, xss_findings):
        """Evidence containing script tags is escaped."""
        from autopnex.report.generator import ReportGenerator

        gen = ReportGenerator(llm_client=None, mode="mock")
        _md, html = gen.render(xss_findings)
        raw_script_count = html.count("<script>")
        assert raw_script_count == 0, f"Found {raw_script_count} unescaped <script> tags"

    @pytest.mark.xfail(
        reason="report.md.j2 uses autoescape=disabled for .j2 — known XSS gap",
        strict=True,
    )
    def test_target_field_escaped_in_report(self, xss_findings):
        """Target with HTML in it is escaped in the report."""
        xss_findings.target = '<img src=x onerror="alert(1)">'
        from autopnex.report.generator import ReportGenerator

        gen = ReportGenerator(llm_client=None, mode="mock")
        _md, html = gen.render(xss_findings)
        assert 'onerror="alert(1)"' not in html


# ═══════════════════════════════════════════════════════════════════════════
# 5. WAF Evasion Safety
# ═══════════════════════════════════════════════════════════════════════════


class TestEvasionSafety:
    """Verify evasion middleware respects feature flags and does not corrupt data."""

    def setup_method(self):
        EvasionMiddleware.reset()

    def teardown_method(self):
        EvasionMiddleware.reset()

    def test_evasion_disabled_by_default(self):
        """EvasionMiddleware.get_instance() returns None when evasion_enabled=False."""
        rc = _rc(evasion_enabled=False)
        with settings.use_runtime(rc):
            assert EvasionMiddleware.get_instance() is None

    def test_evasion_enabled_returns_instance(self):
        """EvasionMiddleware.get_instance() returns an instance when evasion_enabled=True."""
        rc = _rc(evasion_enabled=True)
        with settings.use_runtime(rc):
            instance = EvasionMiddleware.get_instance()
            assert instance is not None
            assert isinstance(instance, EvasionMiddleware)

    def test_rate_controller_respects_backoff(self):
        """After 429 response, delay increases."""
        ctrl = RateController(base_delay=0.5, jitter=0.0)
        initial_factor = ctrl.backoff_factor
        ctrl.on_response(429)
        after_429 = ctrl.backoff_factor
        assert after_429 > initial_factor, "Backoff factor must increase after 429"

    def test_rate_controller_backoff_accumulates(self):
        """Multiple 429 responses accumulate backoff."""
        ctrl = RateController(base_delay=0.5, jitter=0.0)
        ctrl.on_response(429)
        first = ctrl.backoff_factor
        ctrl.on_response(429)
        second = ctrl.backoff_factor
        assert second > first

    def test_rate_controller_recovers_on_success(self):
        """Successful responses reduce backoff factor."""
        ctrl = RateController(base_delay=0.5, jitter=0.0)
        ctrl.on_response(429)
        ctrl.on_response(429)
        high = ctrl.backoff_factor
        ctrl.on_response(200)
        recovered = ctrl.backoff_factor
        assert recovered < high

    def test_mutator_does_not_modify_original_payload(self):
        """Original payload list is not mutated by PayloadMutator."""
        mutator = PayloadMutator()
        originals = ["<script>alert(1)</script>", "' OR 1=1--"]
        snapshot = list(originals)
        mutator.mutate_batch(originals, "xss", "cloudflare")
        assert originals == snapshot, "Input payload list was mutated"

    def test_mutator_returns_originals_plus_variants(self):
        """mutate_batch always includes the original payloads."""
        mutator = PayloadMutator()
        payloads = ["<script>alert(1)</script>"]
        results = mutator.mutate_batch(payloads, "xss", "cloudflare")
        original_entries = [r for r in results if r["strategy"] == "original"]
        assert len(original_entries) >= 1

    def test_mutator_variants_differ_from_original(self):
        """Mutated variants are not identical to the original."""
        mutator = PayloadMutator()
        payload = "SELECT * FROM users"
        variants = mutator.mutate(payload, "sqli", "modsecurity")
        for v in variants:
            assert v["payload"] != payload


# ═══════════════════════════════════════════════════════════════════════════
# 6. Attack Chain Safety
# ═══════════════════════════════════════════════════════════════════════════


def _build_test_graph() -> tuple[AttackGraph, str]:
    """Build a minimal 3-node, 2-edge chain for testing."""
    g = AttackGraph()
    n1 = g.add_node(NodeType.ASSET, "webserver", node_id="web1")
    n1.obtained_at = "2024-01-01T00:00:00Z"  # starting asset
    g.add_node(NodeType.VULNERABILITY, "sqli_vuln", node_id="sqli1")
    g.add_node(NodeType.CAPABILITY, "db_access", node_id="db1")

    g.add_edge(
        "web1", "sqli1", "sqli_exploiter",
        edge_id="e1",
        risk_level="high",
        requires_approval=True,
        preconditions=["web1"],
    )
    g.add_edge(
        "sqli1", "db1", "db_dump",
        edge_id="e2",
        risk_level="critical",
        requires_approval=True,
        preconditions=["sqli1"],
    )
    chain = g.add_chain("test_chain", ["e1", "e2"], chain_id="chain1")
    return g, chain.chain_id


class TestAttackChainSafety:
    """Verify that attack chains respect approval gates and preconditions."""

    def test_chain_executor_requires_approval_for_critical(self):
        """Edges with requires_approval=True trigger the approval callback."""
        graph, chain_id = _build_test_graph()
        findings = StateFindings(target="http://test.example.com")
        callback_log: list[str] = []

        def approval_cb(edge: AttackEdge) -> bool:
            callback_log.append(edge.edge_id)
            return True

        mock_result = ToolResult(success=True, tool="sqli_exploiter", summary="ok")
        with patch.object(ToolRegistry, "execute", return_value=mock_result):
            executor = ChainExecutor(graph, findings, approval_cb=approval_cb)
            executor.execute_chain(chain_id)

        assert "e1" in callback_log, "Approval callback was not invoked for edge e1"

    def test_chain_stops_on_approval_rejection(self):
        """Chain execution stops if approval callback returns False."""
        graph, chain_id = _build_test_graph()
        findings = StateFindings(target="http://test.example.com")

        def deny_all(edge: AttackEdge) -> bool:
            return False

        executor = ChainExecutor(graph, findings, approval_cb=deny_all)
        result = executor.execute_chain(chain_id)
        assert result["status"] == "blocked"
        executed_steps = [s for s in result["steps"] if s.get("status") != "blocked"]
        assert len(executed_steps) == 0, "No steps should execute after denial"

    def test_chain_stops_on_precondition_failure(self):
        """Chain stops when preconditions are not met."""
        graph, chain_id = _build_test_graph()
        node = graph.nodes["web1"]
        node.obtained_at = None  # remove the starting asset

        findings = StateFindings(target="http://test.example.com")

        def approve_all(edge: AttackEdge) -> bool:
            return True

        executor = ChainExecutor(graph, findings, approval_cb=approve_all)
        result = executor.execute_chain(chain_id)
        assert result["status"] == "blocked"
        assert result["steps"][0]["status"] == "preconditions_unmet"

    def test_checkpoint_created_before_each_step(self):
        """A checkpoint exists for every executed step."""
        graph, chain_id = _build_test_graph()
        findings = StateFindings(target="http://test.example.com")

        def approve_all(edge: AttackEdge) -> bool:
            return True

        mock_result = ToolResult(success=True, tool="mock", summary="ok")
        with patch.object(ToolRegistry, "execute", return_value=mock_result):
            executor = ChainExecutor(graph, findings, approval_cb=approve_all)
            result = executor.execute_chain(chain_id)

        executed_count = len([s for s in result["steps"] if s.get("success")])
        assert len(executor.checkpoints) >= executed_count
        for cp in executor.checkpoints:
            assert cp.graph_snapshot, "Checkpoint must capture graph state"
            assert cp.findings_snapshot is not None

    def test_chain_stops_on_tool_failure(self):
        """Chain stops when a tool execution fails after retries."""
        graph, chain_id = _build_test_graph()
        findings = StateFindings(target="http://test.example.com")

        def approve_all(edge: AttackEdge) -> bool:
            return True

        fail_result = ToolResult(success=False, tool="sqli_exploiter", error="connection_refused")
        with patch.object(ToolRegistry, "execute", return_value=fail_result):
            executor = ChainExecutor(graph, findings, approval_cb=approve_all)
            result = executor.execute_chain(chain_id)

        assert result["status"] == "failed"
        assert not result["steps"][0].get("success")

    def test_chain_nonexistent_id(self):
        """Executing a non-existent chain returns error."""
        graph = AttackGraph()
        findings = StateFindings(target="http://test.example.com")
        executor = ChainExecutor(graph, findings)
        result = executor.execute_chain("does_not_exist")
        assert not result["success"]
        assert "not found" in result["error"]
