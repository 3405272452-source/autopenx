from __future__ import annotations

from autopnex.state_machine.findings import Finding, StateFindings, TaskItem


def test_add_finding_is_idempotent():
    sf = StateFindings(target="http://t")
    f = Finding(title="SQLi", url="http://t/x", parameter="id", severity="HIGH")
    sf.add_finding(f)
    sf.add_finding(Finding(title="SQLi", url="http://t/x", parameter="id", severity="HIGH"))
    assert len(sf.findings) == 1


def test_add_parameter_dedup():
    sf = StateFindings(target="http://t")
    sf.add_parameter("http://t/x", "id")
    sf.add_parameter("http://t/x", "id", "GET")
    sf.add_parameter("http://t/x", "id", "POST")
    assert len(sf.parameters) == 2


def test_sorted_findings_by_severity():
    sf = StateFindings(target="http://t")
    sf.add_finding(Finding(title="a", severity="LOW"))
    sf.add_finding(Finding(title="b", severity="CRITICAL"))
    sf.add_finding(Finding(title="c", severity="MEDIUM"))
    sevs = [f.severity for f in sf.sorted_findings()]
    assert sevs == ["CRITICAL", "MEDIUM", "LOW"]


def test_compact_snapshot_keys():
    sf = StateFindings(target="http://t")
    snap = sf.compact_snapshot()
    for k in (
        "target",
        "open_ports",
        "technologies",
        "subdomains",
        "discovered_paths",
        "forms_count",
        "parameters",
        "findings",
        "recent_tool_invocations",
        "phase_notes",
    ):
        assert k in snap


def test_add_finding_upgrades_status():
    sf = StateFindings(target="http://t")
    sf.add_finding(Finding(title="SQLi", url="http://t/x", parameter="id", severity="HIGH", status="suspected"))
    sf.add_finding(Finding(title="SQLi", url="http://t/x", parameter="id", severity="HIGH", status="confirmed"))
    assert len(sf.findings) == 1
    assert sf.findings[0].status == "confirmed"


def test_sync_and_mark_phase_tasks():
    sf = StateFindings(target="http://t")
    sf.sync_phase_tasks(
        "RECON",
        [
            TaskItem(
                ref="recon:tech_detect",
                phase="RECON",
                tool="tech_detect",
                title="Fingerprint",
                arguments={"target": "http://t"},
            )
        ],
    )
    sf.mark_task("RECON", "recon:tech_detect", "done", "captured headers")
    snapshot = sf.phase_task_snapshot("RECON")
    assert snapshot[0]["status"] == "done"
    assert snapshot[0]["note"] == "captured headers"
