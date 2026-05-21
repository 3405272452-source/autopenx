"""Multi-agent infrastructure for AutoPenX."""

from .blackboard import Blackboard
from .base import (
    AgentResult,
    AgentStatus,
    BaseAgent,
    all_agent_classes,
    get_agent_class,
    register_agent,
)
from .coordinator import Coordinator, PHASE_AGENT_MAP

# Import specialist agents so @register_agent decorators fire on package load.
from . import recon_agent  # noqa: F401
from . import scan_agent  # noqa: F401
from . import vuln_agent  # noqa: F401
from . import exploit_agent  # noqa: F401
from . import report_agent  # noqa: F401
from . import browser_agent  # noqa: F401

# Re-export concrete classes for convenience.
from .recon_agent import ReconAgent
from .scan_agent import ScanAgent
from .vuln_agent import VulnDetectAgent
from .exploit_agent import ExploitAgent
from .report_agent import ReportAgent
from .browser_agent import BrowserAgent

__all__ = [
    "Blackboard",
    "AgentResult",
    "AgentStatus",
    "BaseAgent",
    "Coordinator",
    "PHASE_AGENT_MAP",
    "ReconAgent",
    "ScanAgent",
    "VulnDetectAgent",
    "ExploitAgent",
    "ReportAgent",
    "BrowserAgent",
    "all_agent_classes",
    "get_agent_class",
    "register_agent",
]
