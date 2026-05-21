"""CTF Artifact Store - record scripts, downloads, unpacks, logs, snapshots.

Prevents duplicate labour and provides reproducibility for the agent.
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

log = logging.getLogger("autopnex.ctf.artifact_store")


@dataclass
class ArtifactRecord:
    """A single artifact record."""

    kind: str  # script, download, unpack, log, snapshot, payload
    path: str
    source: str = ""  # URL, tool_name, or description
    checksum: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind,
            "path": self.path,
            "source": self.source,
            "checksum": self.checksum,
            "metadata": self.metadata,
            "timestamp": self.timestamp,
        }


class ArtifactStore:
    """Persistent in-memory + disk artifact registry for a CTF session."""

    def __init__(self, workspace_dir: str) -> None:
        self.workspace = Path(workspace_dir)
        self.artifacts_dir = self.workspace / "artifacts"
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        self._records: List[ArtifactRecord] = []
        self._checksum_index: Dict[str, ArtifactRecord] = {}

    # -- registration ------------------------------------------------------

    def register(
        self,
        kind: str,
        path: str,
        source: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ArtifactRecord:
        """Register an artifact, skipping if identical checksum exists."""
        record = ArtifactRecord(
            kind=kind,
            path=path,
            source=source,
            metadata=metadata or {},
        )

        # Compute checksum if file exists
        p = Path(path)
        if p.exists() and p.is_file():
            record.checksum = self._file_checksum(p)
            if record.checksum in self._checksum_index:
                existing = self._checksum_index[record.checksum]
                log.info("Artifact duplicate skipped: %s (same as %s)", path, existing.path)
                return existing

        self._records.append(record)
        if record.checksum:
            self._checksum_index[record.checksum] = record
        self._persist()
        return record

    def register_script(self, name: str, content: str, language: str = "python") -> ArtifactRecord:
        """Register a written script."""
        path = str(self.workspace / "scripts" / name)
        return self.register(
            kind="script",
            path=path,
            source="write_tool_script",
            metadata={"language": language, "size": len(content)},
        )

    def register_download(self, url: str, local_path: str) -> ArtifactRecord:
        """Register a downloaded file."""
        return self.register(
            kind="download",
            path=local_path,
            source=url,
        )

    def register_snapshot(self, label: str, data: Dict[str, Any]) -> ArtifactRecord:
        """Register a JSON snapshot."""
        snapshot_path = self.artifacts_dir / f"snapshot_{label}_{int(time.time())}.json"
        snapshot_path.write_text(json.dumps(data, ensure_ascii=False, default=str), encoding="utf-8")
        return self.register(
            kind="snapshot",
            path=str(snapshot_path),
            source="session_snapshot",
            metadata={"label": label},
        )

    # -- queries -----------------------------------------------------------

    def find(self, *, kind: Optional[str] = None, source: Optional[str] = None) -> List[ArtifactRecord]:
        """Find artifacts by filters."""
        results = []
        for r in self._records:
            if kind is not None and r.kind != kind:
                continue
            if source is not None and source not in r.source:
                continue
            results.append(r)
        return results

    def has_artifact(self, checksum: str) -> bool:
        return checksum in self._checksum_index

    def get_by_path(self, path: str) -> Optional[ArtifactRecord]:
        for r in self._records:
            if r.path == path:
                return r
        return None

    def to_list(self) -> List[Dict[str, Any]]:
        return [r.to_dict() for r in self._records]

    # -- persistence -------------------------------------------------------

    def _persist(self) -> None:
        try:
            index_path = self.artifacts_dir / "index.json"
            index_path.write_text(json.dumps(self.to_list(), ensure_ascii=False, default=str), encoding="utf-8")
        except OSError as e:
            log.warning("ArtifactStore persist failed: %s", e)

    @staticmethod
    def _file_checksum(path: Path, algorithm: str = "sha256") -> str:
        h = hashlib.new(algorithm)
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
