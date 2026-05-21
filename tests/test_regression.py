"""Regression tests ensuring backward compatibility after multi-agent additions."""
from __future__ import annotations

import pytest

from autopnex.state_machine.machine import PenTestStateMachine
from autopnex.orchestrator import LLMOrchestrator
from autopnex.tools.base import ToolRegistry
from config.settings import RuntimeConfig


class TestBackwardCompatibility:
    def test_default_is_single_agent(self):
        """PenTestStateMachine defaults to single-agent mode."""
        orch = LLMOrchestrator(mock=True)
        fsm = PenTestStateMachine("http://example.com", orchestrator=orch)
        assert not fsm.multi_agent

    def test_single_agent_pipeline_mock(self):
        """Full pipeline in mock+single-agent mode produces findings."""
        orch = LLMOrchestrator(mock=True)
        fsm = PenTestStateMachine("http://example.com", orchestrator=orch)
        result = fsm.run()
        assert result.target == "http://example.com"
        assert len(result.state_log) > 0
        assert any(entry["state"] == "DONE" for entry in result.state_log)

    def test_tool_registry_has_original_tools(self):
        """All 16 original tools still registered."""
        names = [t.name for t in ToolRegistry.all()]
        for expected in [
            "port_scan", "tech_detect", "subdomain_find",
            "web_scan", "dir_buster", "crawl",
            "sqli_detect", "xss_detect", "ssrf_detect", "cmdi_detect",
            "sqli_exploit", "finding_replay",
        ]:
            assert expected in names, f"original tool '{expected}' missing from registry"

    def test_new_exploit_tools_registered(self):
        """New exploit tools are registered alongside originals."""
        names = [t.name for t in ToolRegistry.all()]
        for expected in ["xss_exploit", "auth_bypass", "file_upload_exploit", "privilege_escalation"]:
            assert expected in names, f"new tool '{expected}' missing from registry"

    def test_runtime_config_backward_compatible(self):
        """RuntimeConfig can be created with no arguments (all defaults)."""
        config = RuntimeConfig()
        assert config.multi_agent_enabled is False
        assert config.evasion_enabled is False
        assert config.max_concurrent_tools == 4

    def test_runtime_config_original_defaults(self):
        """RuntimeConfig preserves original default values."""
        config = RuntimeConfig()
        assert config.exploit_enabled is False
        assert config.allow_external_tools is False
        assert config.scan_mode == "active"
        assert config.max_iter_per_state == 6
        assert config.http_timeout == 8
        assert config.user_agent == "AutoPenX/0.1"

    def test_findings_backward_compatible(self):
        """StateFindings still supports all original fields."""
        from autopnex.state_machine.findings import StateFindings

        f = StateFindings(target="http://example.com")
        assert hasattr(f, "open_ports")
        assert hasattr(f, "technologies")
        assert hasattr(f, "findings")
        assert hasattr(f, "subdomains")
        assert hasattr(f, "discovered_paths")
        assert hasattr(f, "parameters")
        assert hasattr(f, "exploit_evidence")
        assert hasattr(f, "attack_graph")
        assert f.attack_graph is not None

    def test_taskitem_has_priority_score(self):
        """TaskItem has the new priority_score field with default 0.0."""
        from autopnex.state_machine.findings import TaskItem

        t = TaskItem(
            ref="test", phase="RECON", tool="port_scan",
            title="test", arguments={},
        )
        assert t.priority_score == 0.0

    def test_taskitem_preserves_original_fields(self):
        """TaskItem still carries all original fields."""
        from autopnex.state_machine.findings import TaskItem

        t = TaskItem(
            ref="r1", phase="EXPLOIT", tool="sqli_exploit",
            title="SQLi exploit", arguments={"url": "http://x"},
            status="pending_approval", risk_level="high",
            required_capability="exploit", finding_key="sqli|http://x|id",
        )
        assert t.ref == "r1"
        assert t.phase == "EXPLOIT"
        assert t.status == "pending_approval"
        assert t.risk_level == "high"
        assert t.required_capability == "exploit"
        assert t.finding_key == "sqli|http://x|id"

    def test_orchestrator_modes(self):
        """LLMOrchestrator mode property works correctly."""
        orch = LLMOrchestrator(mock=True)
        assert orch.mode == "mock"

    def test_orchestrator_step_returns_react_step(self):
        """Orchestrator.step returns a ReActStep dataclass."""
        from autopnex.orchestrator import ReActStep

        orch = LLMOrchestrator(mock=True)
        orch.reset_for_state("RECON")
        snapshot = {"target": "http://example.com", "phase_tasks": []}
        step = orch.step("RECON", snapshot, 1, 6)
        assert isinstance(step, ReActStep)
        assert step.state == "RECON"

    def test_build_user_prompt_backward_compatible(self):
        """build_user_prompt works with and without rag_context."""
        from autopnex.orchestrator.prompts import build_user_prompt

        prompt = build_user_prompt(
            "RECON", {"target": "http://example.com"}, 1, 6,
        )
        assert "RECON" in prompt

        prompt2 = build_user_prompt(
            "RECON", {"target": "http://example.com"}, 1, 6,
            rag_context="CVE-2021-41773",
        )
        assert "CVE-2021-41773" in prompt2

    def test_state_machine_states_unchanged(self):
        """STATES and NEXT_STATE mappings haven't changed."""
        from autopnex.state_machine.machine import STATES, NEXT_STATE

        assert STATES == ["INIT", "RECON", "SCAN", "VULN_DETECT", "EXPLOIT", "REPORT", "DONE"]
        assert NEXT_STATE["INIT"] == "RECON"
        assert NEXT_STATE["RECON"] == "SCAN"
        assert NEXT_STATE["SCAN"] == "VULN_DETECT"
        assert NEXT_STATE["VULN_DETECT"] == "EXPLOIT"
        assert NEXT_STATE["EXPLOIT"] == "REPORT"
        assert NEXT_STATE["REPORT"] == "DONE"

    def test_compact_snapshot_keys(self):
        """compact_snapshot returns the expected keys."""
        from autopnex.state_machine.findings import StateFindings

        f = StateFindings(target="http://example.com")
        snap = f.compact_snapshot()
        for key in (
            "target", "open_ports", "technologies", "subdomains",
            "discovered_paths", "interesting_files", "forms_count",
            "parameters", "findings", "recent_tool_invocations", "phase_notes",
        ):
            assert key in snap, f"compact_snapshot missing key '{key}'"


class TestModuleImports:
    def test_import_agents(self):
        """All agent modules import without error."""
        from autopnex.agents import Blackboard, BaseAgent, Coordinator
        from autopnex.agents import (
            ReconAgent, ScanAgent, VulnDetectAgent, ExploitAgent, ReportAgent,
        )
        assert Blackboard is not None
        assert BaseAgent is not None
        assert Coordinator is not None
        assert ReconAgent is not None
        assert ScanAgent is not None
        assert VulnDetectAgent is not None
        assert ExploitAgent is not None
        assert ReportAgent is not None

    def test_import_attack_chain(self):
        """Attack chain modules import without error."""
        from autopnex.state_machine.attack_graph import (
            AttackGraph, AttackNode, AttackEdge, AttackChain,
        )
        from autopnex.state_machine.chain_planner import ChainPlanner
        from autopnex.state_machine.chain_executor import ChainExecutor
        assert AttackGraph is not None
        assert AttackNode is not None
        assert AttackEdge is not None
        assert AttackChain is not None
        assert ChainPlanner is not None
        assert ChainExecutor is not None

    def test_import_evasion(self):
        """Evasion modules import without error."""
        from autopnex.evasion import (
            WAFDetector, PayloadMutator, RateController, EvasionMiddleware,
        )
        assert WAFDetector is not None
        assert PayloadMutator is not None
        assert RateController is not None
        assert EvasionMiddleware is not None

    def test_import_knowledge_base(self):
        """Knowledge base modules import without error."""
        from autopnex.knowledge_base.poc_registry import PoCRegistry
        from autopnex.knowledge_base.cpe_matcher import CPEMatcher
        from autopnex.knowledge_base.dynamic_wordlist import generate_wordlist
        assert PoCRegistry is not None
        assert CPEMatcher is not None
        assert callable(generate_wordlist)

    def test_import_top_level_package(self):
        """Top-level autopnex package imports cleanly."""
        import autopnex
        assert hasattr(autopnex, "__version__")
