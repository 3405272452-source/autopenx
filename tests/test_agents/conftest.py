"""Common fixtures for agent tests."""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from autopnex import tools as _tools  # noqa: F401,E402
from autopnex.state_machine.findings import StateFindings
from autopnex.agents.blackboard import Blackboard
from config.settings import RuntimeConfig


@pytest.fixture()
def state_findings():
    return StateFindings(target="http://testhost")


@pytest.fixture()
def blackboard(state_findings):
    return Blackboard(state_findings)


@pytest.fixture()
def runtime_config():
    return RuntimeConfig(
        exploit_enabled=False,
        allow_external_tools=False,
        scan_mode="active",
    )


@pytest.fixture()
def exploit_runtime_config():
    return RuntimeConfig(
        exploit_enabled=True,
        allow_external_tools=True,
        approved_scopes=("passive", "active_scan", "exploit"),
        scan_mode="active",
    )


@pytest.fixture()
def mock_llm_client():
    return MagicMock()
