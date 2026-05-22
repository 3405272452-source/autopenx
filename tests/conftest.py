"""Shared pytest fixtures and path setup for AutoPenX.

Responsibilities:

1. Put the workspace root on ``sys.path`` so ``import autopnex`` works when
   tests are executed from the repo root without an editable install.
2. Register Hypothesis profiles — importantly a ``ci`` profile selectable via
   ``pytest --hypothesis-profile=ci`` — with deterministic seeding, a reduced
   example count, and a fixed deadline.
3. Import ``autopnex.tools`` for side-effects to register tools used across
   the AutoPenX test suite.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# ---------------------------------------------------------------------------
# Hypothesis profile registration.
# ---------------------------------------------------------------------------
try:  # pragma: no cover - guarded import
    from hypothesis import HealthCheck, Verbosity, settings

    settings.register_profile(
        "dev",
        max_examples=50,
        deadline=None,
        verbosity=Verbosity.normal,
        suppress_health_check=[HealthCheck.too_slow],
    )

    settings.register_profile(
        "ci",
        derandomize=True,
        max_examples=200,
        deadline=500,
        verbosity=Verbosity.normal,
    )

    settings.load_profile("dev")
except Exception:  # pragma: no cover - hypothesis optional in minimal envs
    pass

# Register AutoPenX tools (side-effect imports).
try:  # pragma: no cover - tools registration
    from autopnex import tools as _tools  # noqa: F401
except Exception:
    pass
