"""Shared pytest fixtures and path setup.

Covers both the legacy AutoPenX test suite and the cet4_app layered test
trees (tests/domain, tests/infrastructure, tests/application, tests/ui).

Responsibilities:

1. Put the workspace root on ``sys.path`` so ``import autopnex`` works when
   tests are executed from the repo root.
2. Put the ``src/`` directory on ``sys.path`` so ``import cet4_app`` works
   without requiring an editable install (CI still does ``pip install -e .[dev]``
   but local/partial runs should not require it).
3. Register Hypothesis profiles — importantly a ``ci`` profile selectable via
   ``pytest --hypothesis-profile=ci`` — with deterministic seeding, a reduced
   example count, and a fixed deadline.
4. Import ``autopnex.tools`` for side-effects to preserve existing AutoPenX
   test behavior.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"

for candidate in (ROOT, SRC):
    candidate_str = str(candidate)
    if candidate.exists() and candidate_str not in sys.path:
        sys.path.insert(0, candidate_str)

# ---------------------------------------------------------------------------
# Hypothesis profile registration.
#
# We register profiles unconditionally if Hypothesis is importable so that
# `pytest --hypothesis-profile=ci` works without requiring a second conftest
# under tests/domain. If Hypothesis is not installed (minimal CI image), we
# silently skip registration — tests that depend on hypothesis will fail at
# import time with a clear error, which is the desired behavior.
# ---------------------------------------------------------------------------
try:  # pragma: no cover - guarded import
    from hypothesis import HealthCheck, Verbosity, settings

    # Developer default: rich local feedback, default deadline.
    settings.register_profile(
        "dev",
        max_examples=50,
        deadline=None,
        verbosity=Verbosity.normal,
        suppress_health_check=[HealthCheck.too_slow],
    )

    # CI profile: deterministic, bounded examples, strict deadline.
    # This matches the tasks.md requirement for task 1.2.
    settings.register_profile(
        "ci",
        derandomize=True,
        max_examples=200,
        deadline=500,  # milliseconds
        verbosity=Verbosity.normal,
    )

    # Activate "dev" by default for local runs; CI explicitly selects "ci".
    settings.load_profile("dev")
except Exception:  # pragma: no cover - hypothesis optional in minimal envs
    pass

# Ensure legacy AutoPenX tools are registered for all tests.
try:  # pragma: no cover - legacy package optional in cet4_app-only runs
    from autopnex import tools as _tools  # noqa: F401,E402
except Exception:
    pass
