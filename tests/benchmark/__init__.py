"""M3: Web CTF Benchmark — 30 challenges with structured reporting.

Provides:
  - BenchmarkHarness: runs challenges and collects statistics
  - ChallengeTarget: abstract base for benchmark challenges
  - Report generation: JSON and Markdown formats
"""
from .harness import BenchmarkHarness, BenchmarkRun, BenchmarkReport
from .challenges import ChallengeTarget, ALL_CHALLENGES

__all__ = [
    "BenchmarkHarness",
    "BenchmarkRun",
    "BenchmarkReport",
    "ChallengeTarget",
    "ALL_CHALLENGES",
]
