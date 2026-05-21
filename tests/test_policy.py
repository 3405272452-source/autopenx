from __future__ import annotations

import pytest

from autopnex.policy import PolicyError, apply_scan_policy, create_approval
from config.settings import settings


def test_create_and_apply_active_scan_approval():
    approval = create_approval("http://example.com", ["passive", "active_scan"], 300)
    runtime = apply_scan_policy(
        settings.snapshot(),
        target="http://example.com",
        scan_mode="active",
        allow_external_tools=True,
        exploit_enabled=False,
        approval_token=approval.token,
    )
    assert runtime.allow_external_tools is True
    assert "active_scan" in runtime.approved_scopes


def test_exploit_requires_exploit_scope():
    approval = create_approval("http://example.com", ["passive", "active_scan"], 300)
    with pytest.raises(PolicyError):
        apply_scan_policy(
            settings.snapshot(),
            target="http://example.com",
            exploit_enabled=True,
            approval_token=approval.token,
        )
