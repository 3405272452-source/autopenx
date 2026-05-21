"""Smoke tests for the strict web benchmark infrastructure.

These tests verify that:
- All 12 challenge targets start and stop correctly
- Each target's vulnerable endpoint is reachable
- Expected flag format matches actual flag
- MultiAgentOrchestrator can be instantiated against each target
- No LLM required — these are infrastructure-only tests

Targets (12): first 8 + GraphQL/WebSocket/XSS reflected/XSS stored.
"""
from __future__ import annotations

import pytest
import requests

from tests.benchmark.web_targets.registry import (
    STRICT_BENCHMARK_8,
    STRICT_BENCHMARK_12,
    get_target_class,
    get_target_flag,
    get_target_metadata,
)


# ---------------------------------------------------------------------------
# Infrastructure smoke tests (no LLM)
# ---------------------------------------------------------------------------

class TestBenchmarkTargetLifecycle:
    """Verify all 12 benchmark targets can start/stop correctly."""

    @pytest.mark.parametrize("target_id", list(STRICT_BENCHMARK_12.keys()))
    def test_target_starts_and_responds(self, target_id, benchmark_target):
        target = benchmark_target(target_id)
        resp = requests.get(target.url, timeout=5)
        assert resp.status_code in (200, 302, 401, 403), (
            f"Target {target_id} returned {resp.status_code}"
        )

    @pytest.mark.parametrize("target_id", list(STRICT_BENCHMARK_12.keys()))
    def test_target_flag_format(self, target_id):
        flag = get_target_flag(target_id)
        assert flag.startswith("flag{"), (
            f"Target {target_id} flag should start with 'flag{{': {flag}"
        )
        assert flag.endswith("}")

    @pytest.mark.parametrize("target_id", list(STRICT_BENCHMARK_12.keys()))
    def test_target_has_metadata(self, target_id):
        meta = get_target_metadata(target_id)
        assert meta["id"] == target_id
        assert "category" in meta
        assert "difficulty" in meta
        assert "expected_route" in meta

    @pytest.mark.parametrize("target_id", list(STRICT_BENCHMARK_12.keys()))
    def test_target_class_instantiable(self, target_id):
        cls = get_target_class(target_id)
        assert cls is not None
        target = cls()
        assert target.name is not None
        assert target.category is not None
        assert target.flag is not None


class TestBenchmarkEndpointsReachable:
    """Verify that each target serves its vulnerable endpoint correctly."""

    def test_lfi_basic_page_param(self, benchmark_target):
        target = benchmark_target("lfi_basic")
        resp = requests.get(f"{target.url}/?page=/etc/hosts", timeout=5)
        assert resp.status_code == 200

    def test_lfi_filter_encoded_param(self, benchmark_target):
        target = benchmark_target("lfi_filter")
        resp = requests.get(
            f"{target.url}/?path=..%252f..%252f..%252fetc%252fhostname",
            timeout=5,
        )
        assert resp.status_code in (200, 404)

    def test_ssti_jinja_name_param(self, benchmark_target):
        target = benchmark_target("ssti_jinja")
        resp = requests.get(f"{target.url}/?name=%7B%7B7*7%7D%7D", timeout=5)
        assert resp.status_code == 200
        assert "49" in resp.text

    def test_sqli_union_error_response(self, benchmark_target):
        target = benchmark_target("sqli_union")
        resp = requests.get(f"{target.url}/?q='", timeout=5)
        assert resp.status_code == 200
        assert "error" in resp.text.lower() or "SQLite" in resp.text

    def test_sqli_blind_true_condition(self, benchmark_target):
        target = benchmark_target("sqli_blind")
        resp = requests.get(f"{target.url}/?user_id=1 OR 1=1--", timeout=5)
        assert resp.status_code == 200

    def test_cmdi_filter_blocked_chars(self, benchmark_target):
        target = benchmark_target("cmdi_filter")
        resp = requests.get(f"{target.url}/?host=127.0.0.1;id", timeout=5)
        assert resp.status_code == 403  # Blocked

    def test_jwt_none_admin_401(self, benchmark_target):
        target = benchmark_target("jwt_none")
        resp = requests.get(f"{target.url}/admin", timeout=5)
        assert resp.status_code == 401

    def test_source_leak_git_head(self, benchmark_target):
        target = benchmark_target("source_leak_git")
        resp = requests.get(f"{target.url}/.git/HEAD", timeout=5)
        assert resp.status_code == 200
        assert "ref:" in resp.text

    # GraphQL / WebSocket / XSS (M5 expanded benchmark)

    def test_graphql_introspection_endpoint(self, benchmark_target):
        target = benchmark_target("graphql_introspection")
        resp = requests.post(
            f"{target.url}/graphql",
            json={"query": "{ __schema { queryType { name } } }"},
            timeout=5,
        )
        assert resp.status_code == 200
        assert "__schema" in resp.text or "getFlag" in resp.text

    def test_graphql_flag_query(self, benchmark_target):
        target = benchmark_target("graphql_introspection")
        resp = requests.post(
            f"{target.url}/graphql",
            json={"query": "{ getFlag }"},
            timeout=5,
        )
        assert resp.status_code == 200
        assert "flag{" in resp.text

    def test_websocket_guest_connect(self, benchmark_target):
        target = benchmark_target("websocket_auth_bypass")
        resp = requests.get(f"{target.url}/api/ws/connect?token=guest", timeout=5)
        assert resp.status_code == 200
        assert "guest" in resp.text

    def test_websocket_admin_flag(self, benchmark_target):
        target = benchmark_target("websocket_auth_bypass")
        resp = requests.get(f"{target.url}/api/ws/connect?token=admin", timeout=5)
        assert resp.status_code == 200
        assert "flag{" in resp.text

    def test_xss_reflected_search(self, benchmark_target):
        target = benchmark_target("xss_reflected")
        resp = requests.get(f"{target.url}/?q=test", timeout=5)
        assert resp.status_code == 200
        assert "test" in resp.text

    def test_xss_reflected_admin_bot(self, benchmark_target):
        target = benchmark_target("xss_reflected")
        resp = requests.get(
            f"{target.url}/admin/bot?visit=document.cookie",
            timeout=5,
        )
        assert resp.status_code == 200
        assert "flag{" in resp.text

    def test_xss_stored_guestbook(self, benchmark_target):
        target = benchmark_target("xss_stored")
        resp = requests.get(f"{target.url}/", timeout=5)
        assert resp.status_code == 200
        assert "Guestbook" in resp.text

    def test_xss_stored_post_message(self, benchmark_target):
        target = benchmark_target("xss_stored")
        resp = requests.post(
            f"{target.url}/",
            data="message=<script>fetch('/steal?c='+document.cookie)</script>",
            timeout=5,
        )
        assert resp.status_code in (200, 302, 303)


class TestMultiAgentIntegration:
    """Verify MultiAgentOrchestrator can be created against each target."""

    @pytest.mark.parametrize("target_id", list(STRICT_BENCHMARK_12.keys()))
    def test_orchestrator_instantiation(self, target_id, benchmark_target):
        from autopnex.ctf.multi_agent import MultiAgentOrchestrator

        target = benchmark_target(target_id)
        orch = MultiAgentOrchestrator(
            target_url=target.url,
            flag_format=r"flag\{[^}]+\}",
            max_rounds=3,
        )
        assert orch.blackboard is not None
        assert orch.coordinator is not None
        assert orch.recon is not None
        assert orch.exploit is not None
        assert orch.critic is not None
