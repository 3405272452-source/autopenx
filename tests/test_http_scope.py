from __future__ import annotations

import pytest

from config.settings import settings
from autopnex.tools._http import TargetScopeError, ensure_target_allowed


def test_scope_guard_blocks_loopback_by_default():
    with pytest.raises(TargetScopeError):
        ensure_target_allowed("http://127.0.0.1:8080", runtime_config=settings.snapshot(allow_local_targets=False))


def test_scope_guard_allows_loopback_when_enabled():
    allowed = ensure_target_allowed(
        "http://127.0.0.1:8080",
        runtime_config=settings.snapshot(allow_local_targets=True),
    )
    assert allowed == "http://127.0.0.1:8080"
