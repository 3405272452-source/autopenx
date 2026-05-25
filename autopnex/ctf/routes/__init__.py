"""Routes package — re-exports all route state machines.

This package provides a modular structure for route state machines.
All machines are defined in autopnex.ctf.route_state_machine and
re-exported here for convenience.

Usage:
    from autopnex.ctf.routes import MACHINE_REGISTRY, create_machine, run_route
    from autopnex.ctf.routes.base import RouteStateMachine, RouteResult
"""
from autopnex.ctf.routes.base import (
    ProbeResult,
    StepStatus,
    EvidenceScore,
    StepRecord,
    MachineState,
    RouteResult,
    RouteStateMachine,
)
from autopnex.ctf.routes.registry import (
    MACHINE_REGISTRY,
    create_machine,
    run_route,
)

# Import new machines to trigger their registration in MACHINE_REGISTRY
from autopnex.ctf.routes.xxe import XXEMachine  # noqa: F401
from autopnex.ctf.routes.auth_logic import AuthLogicMachine  # noqa: F401
from autopnex.ctf.routes.nosql import NoSQLRouteStateMachine  # noqa: F401

__all__ = [
    "ProbeResult",
    "StepStatus",
    "EvidenceScore",
    "StepRecord",
    "MachineState",
    "RouteResult",
    "RouteStateMachine",
    "MACHINE_REGISTRY",
    "create_machine",
    "run_route",
    "XXEMachine",
    "AuthLogicMachine",
    "NoSQLRouteStateMachine",
]
