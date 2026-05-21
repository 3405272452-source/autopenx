"""Route machine registry and factory functions.

Re-exports MACHINE_REGISTRY, create_machine(), and run_route() from
the main route_state_machine module for backward compatibility.
"""
from autopnex.ctf.route_state_machine import (
    MACHINE_REGISTRY,
    create_machine,
    run_route,
)

__all__ = [
    "MACHINE_REGISTRY",
    "create_machine",
    "run_route",
]
