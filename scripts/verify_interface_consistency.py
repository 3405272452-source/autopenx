#!/usr/bin/env python3
"""Interface consistency verification script.

Validates that all public APIs on WebStateBlackboard and MultiAgentOrchestrator
are callable without AttributeError or TypeError. Connection errors from the
orchestrator's run_loop are expected (no real server), but type/attribute errors
indicate broken interfaces.

Validates: Requirements 7.6
"""
from __future__ import annotations

import os
import sys

# Ensure project root is on sys.path so autopnex is importable
_project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)


def main() -> None:
    errors: list[str] = []

    # -----------------------------------------------------------------------
    # Part 1: WebStateBlackboard public API verification
    # -----------------------------------------------------------------------
    try:
        from autopnex.ctf.web_state_blackboard import WebStateBlackboard

        bb = WebStateBlackboard(target_url="http://127.0.0.1:9999", flag_format=r"flag\{[^}]+\}")

        # record_endpoint
        ep = bb.record_endpoint(
            path="/test",
            method="GET",
            status_code=200,
            content_type="text/html",
            content_length=100,
            discovered_from="verify_script",
            headers={"Server": "TestServer"},
            body_snippet="<html>hello</html>",
        )
        assert ep is not None, "record_endpoint returned None"
        assert len(bb.endpoints) >= 1, f"Expected >=1 endpoints, got {len(bb.endpoints)}"

        # add_flag_candidate
        cf = bb.add_flag_candidate(value="flag{test123}", source="verify_script", confidence=0.8)
        assert cf is not None, "add_flag_candidate returned None"
        assert len(bb.candidate_flags) >= 1, f"Expected >=1 candidate_flags, got {len(bb.candidate_flags)}"

        # add_evidence
        ev = bb.add_evidence(
            route="sqli",
            score=0.7,
            source="verify_script",
            observation="SQL error in response",
        )
        assert ev is not None, "add_evidence returned None"
        assert len(bb.evidence) >= 1, f"Expected >=1 evidence, got {len(bb.evidence)}"

        # record_attempt
        att = bb.record_attempt(
            route="sqli",
            tool="http_request",
            args={"url": "http://127.0.0.1:9999/vuln", "params": {"id": "1' OR 1=1--"}},
            success=False,
            result_summary="500 Internal Server Error",
            failure_reason="no_flag_found",
        )
        assert att is not None, "record_attempt returned None"
        assert len(bb.attempts) >= 1, f"Expected >=1 attempts, got {len(bb.attempts)}"

        # state_summary
        summary = bb.state_summary()
        assert isinstance(summary, dict), f"state_summary returned {type(summary)}, expected dict"
        assert "endpoint_count" in summary, "state_summary missing 'endpoint_count'"
        assert "top_evidence" in summary, "state_summary missing 'top_evidence'"

        # check_and_record_flag
        found = bb.check_and_record_flag("The flag is flag{abc_def_123}", source="verify_script")
        assert found == "flag{abc_def_123}", f"check_and_record_flag returned {found!r}"

        # ingest_tool_result
        result = bb.ingest_tool_result(
            tool_name="http_get",
            tool_args={"path": "/api/data", "method": "GET"},
            result={"status_code": 200, "body": "<html>no flag here</html>", "headers": {}},
            route_hint="recon",
        )
        assert isinstance(result, dict), f"ingest_tool_result returned {type(result)}, expected dict"

        print("  [OK] WebStateBlackboard: all public APIs consistent")

    except (AttributeError, TypeError) as exc:
        errors.append(f"WebStateBlackboard interface error: {exc}")
        print(f"  [FAIL] WebStateBlackboard: {exc}", file=sys.stderr)

    # -----------------------------------------------------------------------
    # Part 2: MultiAgentOrchestrator instantiation and run_loop
    # -----------------------------------------------------------------------
    try:
        import requests
        from requests.adapters import BaseAdapter
        from requests.models import Response
        from autopnex.ctf.multi_agent import MultiAgentOrchestrator

        # Custom adapter that immediately returns a dummy response (no network)
        class _ImmediateFailAdapter(BaseAdapter):
            """Returns a fake 503 response instantly — no network I/O."""

            def send(self, request, stream=False, timeout=None,
                     verify=True, cert=None, proxies=None):
                resp = Response()
                resp.status_code = 503
                resp._content = b"Service Unavailable (no real server)"
                resp.headers["Content-Type"] = "text/plain"
                resp.url = request.url
                resp.request = request
                resp.connection = self
                return resp

            def close(self):
                pass

        session = requests.Session()
        session.mount("http://", _ImmediateFailAdapter())
        session.mount("https://", _ImmediateFailAdapter())

        orch = MultiAgentOrchestrator(
            target_url="http://127.0.0.1:9999",
            flag_format=r"flag\{[^}]+\}",
            max_rounds=15,
            session=session,
        )

        # Verify orchestrator has expected attributes
        assert hasattr(orch, "blackboard"), "Missing attribute: blackboard"
        assert hasattr(orch, "coordinator"), "Missing attribute: coordinator"
        assert hasattr(orch, "recon"), "Missing attribute: recon"
        assert hasattr(orch, "exploit"), "Missing attribute: exploit"
        assert hasattr(orch, "critic"), "Missing attribute: critic"
        assert hasattr(orch, "run_loop"), "Missing method: run_loop"
        assert hasattr(orch, "get_state_summary"), "Missing method: get_state_summary"

        # Run loop with max_rounds=1 — uses fake adapter so no real network.
        # Must not raise AttributeError or TypeError.
        try:
            found, flag, action_log = orch.run_loop(max_rounds=1)
            # If it completes, verify return types
            assert isinstance(found, bool), f"run_loop[0] should be bool, got {type(found)}"
            assert isinstance(action_log, list), f"run_loop[2] should be list, got {type(action_log)}"
        except (AttributeError, TypeError):
            # These are the errors we're specifically checking for — re-raise
            raise
        except Exception:
            # Any other errors (e.g. from route state machine internals) are acceptable
            pass

        # get_state_summary
        summary = orch.get_state_summary()
        assert isinstance(summary, dict), f"get_state_summary returned {type(summary)}"

        print("  [OK] MultiAgentOrchestrator: instantiation and run_loop consistent")

    except (AttributeError, TypeError) as exc:
        errors.append(f"MultiAgentOrchestrator interface error: {exc}")
        print(f"  [FAIL] MultiAgentOrchestrator: {exc}", file=sys.stderr)

    # -----------------------------------------------------------------------
    # Final verdict
    # -----------------------------------------------------------------------
    if errors:
        print(f"\nFAIL: {len(errors)} interface error(s) detected:")
        for e in errors:
            print(f"  - {e}")
        sys.exit(1)
    else:
        print("\nPASS: interface consistency verified")


if __name__ == "__main__":
    main()
