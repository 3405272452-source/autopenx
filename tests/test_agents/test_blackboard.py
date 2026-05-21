"""Blackboard: thread-safety, snapshot isolation, pub/sub, and write return values."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from autopnex.state_machine.findings import Finding, StateFindings
from autopnex.agents.blackboard import Blackboard


def test_concurrent_writes_are_serialised(blackboard: Blackboard):
    """8+ threads adding findings simultaneously must not corrupt the list."""

    def _add_finding(idx: int):
        def mutate(f: StateFindings):
            f.add_finding(
                Finding(title=f"finding-{idx}", severity="MEDIUM", url=f"http://t/{idx}")
            )
        blackboard.write(mutate)
        return idx

    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = [pool.submit(_add_finding, i) for i in range(20)]
        results = [f.result() for f in as_completed(futures)]

    assert len(results) == 20
    findings = blackboard.full_findings().findings
    assert len(findings) == 20
    titles = {f.title for f in findings}
    assert titles == {f"finding-{i}" for i in range(20)}


def test_snapshot_isolation(blackboard: Blackboard):
    """Changes after snapshot should not appear in the earlier snapshot."""
    snap_before = blackboard.snapshot()

    blackboard.write(
        lambda f: f.add_finding(Finding(title="new-vuln", severity="HIGH"))
    )

    snap_after = blackboard.snapshot()
    assert len(snap_before["findings"]) == 0
    assert len(snap_after["findings"]) == 1


def test_subscribe_and_notify(blackboard: Blackboard):
    events = []

    def _on_event(event, **payload):
        events.append((event, payload))

    blackboard.subscribe(_on_event)
    blackboard.write(lambda f: f.add_path("/admin"))

    assert len(events) == 1
    assert events[0][0] == "write"


def test_subscriber_exception_does_not_propagate(blackboard: Blackboard):
    def _bad_cb(event, **payload):
        raise RuntimeError("boom")

    blackboard.subscribe(_bad_cb)
    blackboard.write(lambda f: f.add_path("/safe"))
    assert "/safe" in blackboard.full_findings().discovered_paths


def test_write_returns_mutation_result(blackboard: Blackboard):
    result = blackboard.write(lambda f: 42)
    assert result == 42


def test_write_returns_finding_object(blackboard: Blackboard):
    finding = blackboard.write(
        lambda f: f.add_finding(Finding(title="SQLi", severity="CRITICAL"))
    )
    assert finding.title == "SQLi"


def test_multiple_subscribers_all_called(blackboard: Blackboard):
    calls = {"a": 0, "b": 0}

    blackboard.subscribe(lambda ev, **kw: calls.__setitem__("a", calls["a"] + 1))
    blackboard.subscribe(lambda ev, **kw: calls.__setitem__("b", calls["b"] + 1))

    blackboard.write(lambda f: None)
    assert calls["a"] == 1
    assert calls["b"] == 1
