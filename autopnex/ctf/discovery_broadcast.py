"""DiscoveryBroadcast - thread-safe inter-worker discovery sharing channel.

Provides a short-lived, in-memory broadcast channel for Phase2 Workers to share
discoveries (source code leaks, credentials, DB structures, endpoints, etc.)
during a single Phase2Runner.run() call.

Design goals:
- Thread-safe (all public methods use threading.Lock)
- Deduplication via content hash
- Max capacity with oldest-first eviction
- Content length truncation
- Zero persistence (lives only for one run() invocation)
"""
from __future__ import annotations

import hashlib
import logging
import threading
import time
from dataclasses import dataclass, field
from typing import List

log = logging.getLogger("autopnex.ctf.discovery_broadcast")


# ---------------------------------------------------------------------------
# Discovery types
# ---------------------------------------------------------------------------

class DiscoveryType:
    """Constants for discovery type classification."""

    SOURCE_CODE = "source_code"
    DB_STRUCTURE = "db_structure"
    CREDENTIAL = "credential"
    ENDPOINT = "endpoint"
    FLAG_HINT = "flag_hint"
    ROUTE_HINT = "route_hint"

    ALL_TYPES = (
        SOURCE_CODE,
        DB_STRUCTURE,
        CREDENTIAL,
        ENDPOINT,
        FLAG_HINT,
        ROUTE_HINT,
    )


# ---------------------------------------------------------------------------
# Discovery dataclass
# ---------------------------------------------------------------------------

@dataclass
class Discovery:
    """A single discovery published by a worker."""

    worker_id: str
    discovery_type: str
    content: str
    timestamp: float = field(default_factory=time.time)
    content_hash: str = ""

    def __post_init__(self) -> None:
        if not self.content_hash:
            self.content_hash = hashlib.sha256(self.content.encode("utf-8", errors="replace")).hexdigest()


# ---------------------------------------------------------------------------
# DiscoveryBroadcast
# ---------------------------------------------------------------------------

class DiscoveryBroadcast:
    """Thread-safe broadcast channel for inter-worker discovery sharing.

    Designed to exist for the duration of one Phase2Runner.run() call.
    All workers share the same instance and can publish/read discoveries
    concurrently.

    Args:
        max_capacity: Maximum number of discoveries to retain. When full,
            oldest entries are dropped to make room.
        max_content_length: Maximum character length for a single discovery's
            content. Longer content is truncated.
    """

    def __init__(self, max_capacity: int = 100, max_content_length: int = 2000) -> None:
        self._max_capacity = max_capacity
        self._max_content_length = max_content_length
        self._discoveries: List[Discovery] = []
        self._seen_hashes: set = set()
        self._lock = threading.Lock()

    # -- Public API --------------------------------------------------------

    def publish(self, worker_id: str, discovery_type: str, content: str) -> bool:
        """Publish a discovery to the broadcast channel.

        Thread-safe. Returns False if the content is a duplicate (same content
        hash already exists, regardless of which worker published it).

        Args:
            worker_id: Identifier of the publishing worker.
            discovery_type: One of DiscoveryType constants.
            content: The discovery content (will be truncated if too long).

        Returns:
            True if the discovery was accepted, False if it was a duplicate.
        """
        # Truncate content before hashing so that the same long content
        # truncated differently doesn't bypass dedup.
        truncated_content = content[:self._max_content_length]

        content_hash = hashlib.sha256(
            truncated_content.encode("utf-8", errors="replace")
        ).hexdigest()

        with self._lock:
            # Deduplication check
            if content_hash in self._seen_hashes:
                return False

            # Evict oldest if at capacity
            if len(self._discoveries) >= self._max_capacity:
                evicted = self._discoveries.pop(0)
                self._seen_hashes.discard(evicted.content_hash)
                log.debug(
                    "Evicted oldest discovery (worker=%s, type=%s) due to capacity limit",
                    evicted.worker_id,
                    evicted.discovery_type,
                )

            discovery = Discovery(
                worker_id=worker_id,
                discovery_type=discovery_type,
                content=truncated_content,
                timestamp=time.time(),
                content_hash=content_hash,
            )
            self._discoveries.append(discovery)
            self._seen_hashes.add(content_hash)

        log.debug(
            "Published discovery: worker=%s, type=%s, len=%d",
            worker_id,
            discovery_type,
            len(truncated_content),
        )
        return True

    def get_since(self, timestamp: float) -> List[Discovery]:
        """Get all discoveries published after the given timestamp.

        Thread-safe. Returns a copy of matching discoveries sorted by
        timestamp ascending.

        Args:
            timestamp: Unix timestamp. Only discoveries with timestamp > this
                value are returned.

        Returns:
            List of Discovery objects published after the given timestamp.
        """
        with self._lock:
            return [d for d in self._discoveries if d.timestamp > timestamp]

    def get_all(self) -> List[Discovery]:
        """Get all discoveries currently in the channel.

        Thread-safe. Returns a copy of all discoveries sorted by timestamp
        ascending.

        Returns:
            List of all Discovery objects.
        """
        with self._lock:
            return list(self._discoveries)

    def clear(self) -> None:
        """Clear all discoveries from the channel.

        Thread-safe. Resets the channel to empty state.
        """
        with self._lock:
            self._discoveries.clear()
            self._seen_hashes.clear()

    # -- Properties --------------------------------------------------------

    @property
    def count(self) -> int:
        """Number of discoveries currently in the channel."""
        with self._lock:
            return len(self._discoveries)

    @property
    def is_full(self) -> bool:
        """Whether the channel has reached max capacity."""
        with self._lock:
            return len(self._discoveries) >= self._max_capacity
