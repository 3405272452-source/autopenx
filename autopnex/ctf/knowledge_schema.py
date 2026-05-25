"""Unified ctf_knowledge.json schema — migration and compatibility layer.

This module provides a single entry point (`load_knowledge` / `save_knowledge`)
for reading and writing the CTF knowledge base file.  It transparently handles:

  - **Old schema** (v1): top-level `solve_records` and `attempt_records` arrays
    written by `CTFKnowledgeBase._persist()`.
  - **New schema** (v2+): top-level `version`, `patterns`, `solve_history`,
    `route_weights`, `fast_payloads`, `fingerprint_route_map` written by
    `KnowledgeLearner` and `ExperienceWriter`.

Migration is **non-destructive**: old data is preserved in its original fields
and also normalized into the new unified structure.  Code that reads old fields
(`solve_records`, `attempt_records`) will continue to work because those fields
remain in the file.

Design principles:
  - Single source of truth for schema version and field definitions
  - Graceful degradation: corrupt/missing file → empty valid structure
  - Append-only migration: never removes data, only adds normalized copies
  - Thread-safe file I/O via atomic write pattern
"""

from __future__ import annotations

import json
import logging
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

log = logging.getLogger("autopnex.ctf.knowledge_schema")

# Current unified schema version
SCHEMA_VERSION = 3

# All top-level fields in the unified schema.
# See empty_knowledge() docstring for detailed type documentation of each field.
_UNIFIED_FIELDS = {
    "version",
    # Legacy fields (preserved for backward compatibility)
    "solve_records",       # List[Dict] — raw solve records
    "attempt_records",     # List[Dict] — raw attempt records
    # New fields (KnowledgeLearner / ExperienceWriter / ParallelRouteScan)
    "patterns",            # List[Dict] — extracted solving patterns (route, scenario, fingerprints, payload_family)
    "solve_history",       # List[Dict] — solve history entries (target_url, flag, route, scenario, timestamp)
    "route_weights",       # Dict[str, float] — route name → weight [0.0, 1.0] for dynamic priority
    "fast_payloads",       # Dict[str, List[Dict]] — route name → successful payload templates
    "fingerprint_route_map",  # Dict[str, List[str]] — target fingerprint/tech stack → successful routes
}


def empty_knowledge() -> Dict[str, Any]:
    """Return a valid empty knowledge structure with all unified fields.

    Field type documentation:

    Legacy fields (backward compat with CTFKnowledgeBase):
      - solve_records: List[Dict] — raw solve records from CTFKnowledgeBase._persist()
      - attempt_records: List[Dict] — raw attempt records from CTFKnowledgeBase._persist()

    New unified fields (KnowledgeLearner / ExperienceWriter / ParallelRouteScan):
      - patterns: List[Dict] — extracted solving patterns. Each entry contains:
            {route: str, scenario: str, fingerprints: List[str], payload_family: str}
      - solve_history: List[Dict] — solve history entries. Each entry contains:
            {target_url: str, flag: str, route: str, scenario: str, timestamp: float}
      - route_weights: Dict[str, float] — maps route names to float weights in [0.0, 1.0]
            for dynamic priority adjustment. Higher weight = higher priority.
      - fast_payloads: Dict[str, List[Dict]] — maps route names to lists of successful
            payload templates. Each template: {method, path, params, data, headers}.
      - fingerprint_route_map: Dict[str, List[str]] — maps target fingerprints/tech stacks
            to lists of historically successful routes for that fingerprint.
    """
    return {
        "version": SCHEMA_VERSION,
        # Legacy fields — kept for backward compat with CTFKnowledgeBase
        "solve_records": [],
        "attempt_records": [],
        # patterns: List of extracted solving patterns
        # Each entry: {route, scenario, fingerprints, payload_family}
        "patterns": [],
        # solve_history: List of solve history entries
        # Each entry: {target_url, flag, route, scenario, timestamp}
        "solve_history": [],
        # route_weights: Dict mapping route names to float weights [0.0, 1.0]
        # Used for dynamic priority adjustment in CoordinatorAgent and ParallelRouteScan
        "route_weights": {},
        # fast_payloads: Dict mapping route names to lists of successful payload templates
        # Each template: {method, path, params, data, headers}
        "fast_payloads": {},
        # fingerprint_route_map: Dict mapping target fingerprints/tech stacks to
        # lists of historically successful routes
        "fingerprint_route_map": {},
    }


def load_knowledge(path: Optional[Path] = None) -> Dict[str, Any]:
    """Load and migrate the knowledge base from disk.

    Handles three cases transparently:
      1. File does not exist → returns empty_knowledge()
      2. File has old schema (no "version" or version < SCHEMA_VERSION) → migrates
      3. File has current schema → returns as-is

    Migration is non-destructive: old fields are preserved, new fields are
    initialized with sensible defaults derived from old data.

    Args:
        path: Path to ctf_knowledge.json.  If None, uses the default
              project-root location.

    Returns:
        A dict conforming to the unified schema (version == SCHEMA_VERSION).
    """
    if path is None:
        path = _default_knowledge_path()

    if not path.exists():
        return empty_knowledge()

    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError, ValueError) as exc:
        log.warning("Failed to load knowledge base from %s: %s — starting fresh", path, exc)
        return empty_knowledge()

    if not isinstance(data, dict):
        log.warning("Knowledge base at %s is not a dict — starting fresh", path)
        return empty_knowledge()

    return _migrate(data)


def save_knowledge(data: Dict[str, Any], path: Optional[Path] = None) -> None:
    """Save the knowledge base to disk atomically.

    Writes to a temporary file first, then renames to avoid corruption
    on crash.  Preserves all fields (both old and new) so that legacy
    code reading `solve_records` / `attempt_records` continues to work.

    Args:
        data: The knowledge dict (should conform to unified schema).
        path: Target file path.  If None, uses the default project-root location.
    """
    if path is None:
        path = _default_knowledge_path()

    # Ensure version is current
    data["version"] = SCHEMA_VERSION

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        # Atomic write: write to temp file then rename
        fd = tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=str(path.parent),
            suffix=".tmp",
            delete=False,
        )
        try:
            json.dump(data, fd, ensure_ascii=False, indent=2)
            fd.flush()
            fd.close()
            # On Windows, target must not exist for rename
            tmp_path = Path(fd.name)
            if path.exists():
                path.unlink()
            tmp_path.rename(path)
        except BaseException:
            # Clean up temp file on failure
            fd.close()
            try:
                Path(fd.name).unlink(missing_ok=True)
            except OSError:
                pass
            raise
    except OSError as exc:
        log.error("Failed to save knowledge base to %s: %s", path, exc)


# ---------------------------------------------------------------------------
# Migration logic
# ---------------------------------------------------------------------------


def _migrate(data: Dict[str, Any]) -> Dict[str, Any]:
    """Migrate data from any older schema version to the current unified schema.

    Migration strategy:
      - Always preserve existing fields (non-destructive)
      - Initialize missing new fields with defaults
      - If old fields exist but new fields don't, derive new fields from old data
      - Bump version to SCHEMA_VERSION
    """
    version = data.get("version", 1)

    # --- Ensure all unified fields exist with correct types ---

    # Legacy fields: preserve if present, initialize if missing
    if "solve_records" not in data:
        data["solve_records"] = []
    if "attempt_records" not in data:
        data["attempt_records"] = []

    # New fields: initialize if missing
    if "patterns" not in data:
        data["patterns"] = []
    if "solve_history" not in data:
        data["solve_history"] = []
    if "route_weights" not in data:
        data["route_weights"] = {}
    if "fast_payloads" not in data:
        data["fast_payloads"] = {}
    if "fingerprint_route_map" not in data:
        data["fingerprint_route_map"] = {}

    # --- Version-specific migrations ---

    if version < 2:
        # v1 → v2: derive solve_history from solve_records if empty
        _migrate_v1_to_v2(data)

    if version < 3:
        # v2 → v3: ensure route_weights / fast_payloads / fingerprint_route_map exist
        # (already handled above by field initialization)
        _migrate_v2_to_v3(data)

    # Stamp current version
    data["version"] = SCHEMA_VERSION
    return data


def _migrate_v1_to_v2(data: Dict[str, Any]) -> None:
    """Migrate from v1 (only solve_records/attempt_records) to v2.

    Derives `solve_history` entries from existing `solve_records` if
    `solve_history` is empty.  Does NOT remove `solve_records` — they
    remain for backward compatibility with CTFKnowledgeBase.
    """
    if data.get("solve_history"):
        # Already has solve_history data — don't overwrite
        return

    solve_records: List[Dict[str, Any]] = data.get("solve_records", [])
    if not solve_records:
        return

    derived_history: List[Dict[str, Any]] = []
    for record in solve_records:
        entry = {
            "target_url": record.get("target", ""),
            "flag": (record.get("flag") or "")[:50],
            "route": _infer_route_from_strategy(record.get("strategy_used", "")),
            "scenario": record.get("sub_type", ""),
            "timestamp": record.get("timestamp", 0),
        }
        derived_history.append(entry)

    data["solve_history"] = derived_history
    log.info("Migrated %d solve_records → solve_history entries", len(derived_history))


def _migrate_v2_to_v3(data: Dict[str, Any]) -> None:
    """Migrate from v2 to v3 — ensure new parallel-AI fields exist.

    v3 adds: route_weights, fast_payloads, fingerprint_route_map.
    These are already initialized by the field-existence checks above,
    so this function only needs to derive initial route_weights from
    attempt_records if available.
    """
    if data.get("route_weights"):
        # Already has route weights — don't overwrite
        return

    # Derive initial route weights from attempt_records success/failure ratio
    attempt_records: List[Dict[str, Any]] = data.get("attempt_records", [])
    if not attempt_records:
        return

    route_stats: Dict[str, Dict[str, int]] = {}  # route → {success: N, total: N}
    for record in attempt_records:
        strategy = record.get("strategy_used", "")
        route = _infer_route_from_strategy(strategy)
        if not route:
            continue
        stats = route_stats.setdefault(route, {"success": 0, "total": 0})
        stats["total"] += 1
        if record.get("success"):
            stats["success"] += 1

    # Convert to weights [0.0, 1.0]
    weights: Dict[str, float] = {}
    for route, stats in route_stats.items():
        if stats["total"] > 0:
            # Base weight 0.5, adjusted by success rate
            success_rate = stats["success"] / stats["total"]
            weights[route] = round(0.3 + 0.4 * success_rate, 3)

    if weights:
        data["route_weights"] = weights
        log.info("Derived initial route_weights from %d attempt_records", len(attempt_records))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _infer_route_from_strategy(strategy: str) -> str:
    """Best-effort inference of the route name from a strategy string.

    Strategy strings look like:
      "GET / → deterministic_php_pop"
      "phar_pdo_chain → GET / → ..."
      "GET / → python: import urllib.parse → POST /"

    We look for known route keywords.
    """
    if not strategy:
        return ""

    strategy_lower = strategy.lower()

    # Known route keywords (from RouteStateMachine registry)
    route_keywords = {
        "sqli": "sqli",
        "sql_injection": "sqli",
        "blind_sqli": "sqli",
        "ssti": "ssti",
        "template_injection": "ssti",
        "lfi": "lfi",
        "file_inclusion": "lfi",
        "rce": "rce",
        "command_injection": "rce",
        "cmdi": "rce",
        "ssrf": "ssrf",
        "xxe": "xxe",
        "xss": "xss",
        "upload": "upload",
        "file_upload": "upload",
        "deserialization": "deserialization",
        "php_pop": "deserialization",
        "phar": "deserialization",
        "phar_pdo": "deserialization",
        "deterministic_php_pop": "deserialization",
        "phar_pdo_chain": "deserialization",
        "jwt": "jwt",
        "auth_bypass": "auth_bypass",
        "login_bypass": "auth_bypass",
        "path_traversal": "path_traversal",
        "directory_traversal": "path_traversal",
    }

    for keyword, route in route_keywords.items():
        if keyword in strategy_lower:
            return route

    return ""


def _default_knowledge_path() -> Path:
    """Return the default ctf_knowledge.json path (project root)."""
    return Path(__file__).resolve().parent.parent.parent / "ctf_knowledge.json"
