"""
AutoPenX RAG Knowledge Base & Vulnerability Intelligence Pipeline
=================================================================
Complete design proposal with data schemas, code designs, and integration points.

Author: Knowledge Enhancement Expert Agent
Target: autopnex/knowledge_base/ expansion
"""

# =============================================================================
# SECTION 0: DEPENDENCY ADDITIONS (requirements-kb.txt)
# =============================================================================
REQUIREMENTS_KB = """
# --- RAG / Embedding / Vector Store ---
fastembed>=0.3.0          # Local embedding, ~100MB model, no PyTorch dependency
faiss-cpu>=1.8.0          # Facebook AI vector similarity search (CPU-only, lightweight)

# --- Data formats ---
pyyaml>=6.0               # PoC knowledge base storage format
packaging>=24.0           # PEP-440 version comparison for CPE matching

# --- Optional: upgrade path ---
# chromadb>=0.5.0         # Richer metadata filtering (future, heavier)
# sentence-transformers   # Higher-quality embeddings (requires torch ~2GB)
"""

# =============================================================================
# SECTION 1: RAG PIPELINE ARCHITECTURE
# =============================================================================
"""
Architecture Overview
---------------------
                  ┌────────────────────────────┐
                  │   Document Sources          │
                  │  ┌──────┐ ┌──────┐ ┌─────┐ │
                  │  │ CVE  │ │Expl- │ │Sec  │ │
                  │  │ JSON │ │oit-DB│ │Adv. │ │
                  │  └──┬───┘ └──┬───┘ └──┬──┘ │
                  └─────┼────────┼────────┼────┘
                        ▼        ▼        ▼
              ┌──────────────────────────────────┐
              │      Document Ingestion          │
              │  chunk → embed → store in FAISS  │
              └──────────────┬───────────────────┘
                             ▼
              ┌──────────────────────────────────┐
              │        FAISS Vector Index         │
              │   + metadata sidecar (JSON)       │
              └──────────────┬───────────────────┘
                             ▼
    ┌─────────────┐    ┌─────────────────┐    ┌──────────────────┐
    │ tech_detect  │───▶│  RAG Retriever  │───▶│  Prompt Builder  │
    │   results    │    │  query + top-K  │    │  inject context  │
    └─────────────┘    └─────────────────┘    └───────┬──────────┘
                                                      ▼
                                              ┌──────────────────┐
                                              │   LLM (DeepSeek) │
                                              │ enriched prompt   │
                                              └──────────────────┘

File Layout Under knowledge_base/
----------------------------------
autopnex/knowledge_base/
├── __init__.py                  # existing (expanded exports)
├── vuln_patterns.py             # existing (unchanged)
├── rag/
│   ├── __init__.py
│   ├── embedder.py              # Embedding wrapper (fastembed)
│   ├── vector_store.py          # FAISS index + metadata sidecar
│   ├── retriever.py             # Query interface: tech→CVE→context
│   ├── ingester.py              # Document chunking + index building
│   └── prompt_injector.py       # Token-budget-aware prompt assembly
├── intel/
│   ├── __init__.py
│   ├── cpe_matcher.py           # Technology string → CPE → CVE lookup
│   ├── cve_db.py                # Local CVE database (SQLite)
│   └── tech_to_cve.py           # Version-range comparator
├── poc/
│   ├── __init__.py
│   ├── poc_registry.py          # PoC loader + query interface
│   └── payloads/                # YAML payload collections
│       ├── sqli.yaml
│       ├── xss.yaml
│       ├── ssrf.yaml
│       ├── rce.yaml
│       ├── lfi.yaml
│       └── cms_specific.yaml
├── history/
│   ├── __init__.py
│   ├── scan_history.py          # SQLite scan result storage
│   └── priority_learner.py      # History-based task reordering
├── wordlists/
│   ├── __init__.py              # existing
│   ├── common_paths.txt         # existing (kept as fallback)
│   ├── generator.py             # Dynamic wordlist generator
│   └── tech_paths/              # Per-technology path lists
│       ├── wordpress.txt
│       ├── django.txt
│       ├── laravel.txt
│       ├── spring.txt
│       ├── express.txt
│       ├── nextjs.txt
│       └── joomla.txt
└── data/                        # Runtime data (gitignored)
    ├── faiss_index/
    │   ├── vulns.index          # FAISS binary index
    │   └── vulns_meta.jsonl     # Metadata sidecar
    ├── cve_cache.db             # SQLite CVE cache
    └── scan_history.db          # SQLite scan history
"""


# =============================================================================
# SECTION 1A: EMBEDDING & VECTOR STORE
# =============================================================================

# --- autopnex/knowledge_base/rag/embedder.py ---

EMBEDDER_PY = '''
"""Lightweight embedding wrapper using fastembed (no PyTorch required)."""
from __future__ import annotations

import logging
from typing import List, Optional

import numpy as np

log = logging.getLogger("autopnex.kb.embedder")

_MODEL_NAME = "BAAI/bge-small-en-v1.5"   # 384-dim, ~33M params, ~130MB disk
_BATCH_SIZE = 64


class Embedder:
    """Lazy-loaded singleton embedding model."""

    _instance: Optional["Embedder"] = None

    def __init__(self, model_name: str = _MODEL_NAME):
        self._model_name = model_name
        self._model = None

    @classmethod
    def get(cls) -> "Embedder":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def _ensure_loaded(self) -> None:
        if self._model is not None:
            return
        from fastembed import TextEmbedding
        log.info("Loading embedding model: %s", self._model_name)
        self._model = TextEmbedding(model_name=self._model_name)

    def embed_documents(self, texts: List[str]) -> np.ndarray:
        self._ensure_loaded()
        embeddings = list(self._model.embed(texts, batch_size=_BATCH_SIZE))
        return np.array(embeddings, dtype=np.float32)

    def embed_query(self, text: str) -> np.ndarray:
        self._ensure_loaded()
        embeddings = list(self._model.embed([text]))
        return np.array(embeddings[0], dtype=np.float32)

    @property
    def dimension(self) -> int:
        return 384  # bge-small-en-v1.5 output dimension
'''


# --- autopnex/knowledge_base/rag/vector_store.py ---

VECTOR_STORE_PY = '''
"""FAISS-backed vector store with JSON metadata sidecar."""
from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import faiss
import numpy as np

from .embedder import Embedder

log = logging.getLogger("autopnex.kb.vector_store")

DEFAULT_INDEX_DIR = Path(__file__).resolve().parent.parent / "data" / "faiss_index"


@dataclass
class VectorDocument:
    """A chunk stored in the vector index."""
    doc_id: str                            # e.g. "CVE-2021-41773"
    text: str                              # the embedded chunk text
    source: str = ""                       # "nvd" | "exploit_db" | "poc" | "advisory"
    doc_type: str = ""                     # "cve" | "exploit" | "advisory" | "poc"
    metadata: Dict[str, Any] = field(default_factory=dict)
    # metadata may include: cve_id, cvss, affected_cpe, exploit_url, etc.


@dataclass
class SearchResult:
    document: VectorDocument
    score: float                           # L2 distance (lower = more similar)


class VectorStore:
    """FAISS IndexFlatIP with metadata stored in a parallel JSONL file."""

    def __init__(self, index_dir: Path = DEFAULT_INDEX_DIR, dimension: int = 384):
        self._index_dir = index_dir
        self._dimension = dimension
        self._index: Optional[faiss.IndexFlatIP] = None
        self._documents: List[VectorDocument] = []

    @property
    def index_path(self) -> Path:
        return self._index_dir / "vulns.index"

    @property
    def meta_path(self) -> Path:
        return self._index_dir / "vulns_meta.jsonl"

    @property
    def size(self) -> int:
        return len(self._documents)

    def _ensure_index(self) -> faiss.IndexFlatIP:
        if self._index is None:
            self._index = faiss.IndexFlatIP(self._dimension)
        return self._index

    def add(self, documents: List[VectorDocument], embeddings: np.ndarray) -> None:
        index = self._ensure_index()
        faiss.normalize_L2(embeddings)
        index.add(embeddings)
        self._documents.extend(documents)

    def search(
        self,
        query_embedding: np.ndarray,
        top_k: int = 10,
        filter_source: Optional[str] = None,
        filter_doc_type: Optional[str] = None,
    ) -> List[SearchResult]:
        if self._index is None or self._index.ntotal == 0:
            return []

        query = query_embedding.reshape(1, -1).copy()
        faiss.normalize_L2(query)

        search_k = min(top_k * 3, self._index.ntotal)  # over-fetch for filtering
        distances, indices = self._index.search(query, search_k)

        results = []
        for dist, idx in zip(distances[0], indices[0]):
            if idx < 0 or idx >= len(self._documents):
                continue
            doc = self._documents[idx]
            if filter_source and doc.source != filter_source:
                continue
            if filter_doc_type and doc.doc_type != filter_doc_type:
                continue
            results.append(SearchResult(document=doc, score=float(dist)))
            if len(results) >= top_k:
                break
        return results

    def save(self) -> None:
        self._index_dir.mkdir(parents=True, exist_ok=True)
        if self._index is not None:
            faiss.write_index(self._index, str(self.index_path))
        with open(self.meta_path, "w", encoding="utf-8") as f:
            for doc in self._documents:
                f.write(json.dumps(asdict(doc), ensure_ascii=False) + "\\n")
        log.info("Saved vector store: %d documents", len(self._documents))

    def load(self) -> bool:
        if not self.index_path.exists() or not self.meta_path.exists():
            return False
        self._index = faiss.read_index(str(self.index_path))
        self._documents = []
        with open(self.meta_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    data = json.loads(line)
                    self._documents.append(VectorDocument(**data))
        log.info("Loaded vector store: %d documents", len(self._documents))
        return True
'''


# --- autopnex/knowledge_base/rag/ingester.py ---
# (Note: this is the RAG document ingester, NOT the tool-result ingester)

RAG_INGESTER_PY = '''
"""Ingest CVE/exploit/advisory documents into the vector store."""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List

from .embedder import Embedder
from .vector_store import VectorDocument, VectorStore

log = logging.getLogger("autopnex.kb.rag.ingester")

MAX_CHUNK_CHARS = 800
CHUNK_OVERLAP = 100


def chunk_text(text: str, max_chars: int = MAX_CHUNK_CHARS, overlap: int = CHUNK_OVERLAP) -> List[str]:
    """Split text into overlapping chunks at sentence boundaries."""
    if len(text) <= max_chars:
        return [text]

    sentences = text.replace("\\n", " ").split(". ")
    chunks: List[str] = []
    current = ""

    for sentence in sentences:
        candidate = f"{current}. {sentence}" if current else sentence
        if len(candidate) > max_chars and current:
            chunks.append(current.strip())
            overlap_text = current[-overlap:] if len(current) > overlap else current
            current = f"{overlap_text} {sentence}"
        else:
            current = candidate

    if current.strip():
        chunks.append(current.strip())
    return chunks


def ingest_cve_json(cve_path: Path, store: VectorStore, embedder: Embedder) -> int:
    """Ingest NVD CVE JSON feed (one CVE item per line or full JSON array).

    Expected format per item:
    {
        "id": "CVE-2021-41773",
        "description": "...",
        "cvss_v3_score": 7.5,
        "affected_cpe": ["cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"],
        "references": ["https://..."],
        "published": "2021-10-05"
    }
    """
    raw = cve_path.read_text(encoding="utf-8")
    try:
        items = json.loads(raw)
        if isinstance(items, dict):
            items = [items]
    except json.JSONDecodeError:
        items = [json.loads(line) for line in raw.splitlines() if line.strip()]

    docs: List[VectorDocument] = []
    texts: List[str] = []

    for item in items:
        cve_id = item.get("id", "unknown")
        description = item.get("description", "")
        cvss = item.get("cvss_v3_score", 0)
        cpes = item.get("affected_cpe", [])

        enriched_text = (
            f"CVE: {cve_id} | CVSS: {cvss}\\n"
            f"Affected: {', '.join(cpes[:5])}\\n"
            f"Description: {description}"
        )

        for chunk in chunk_text(enriched_text):
            docs.append(VectorDocument(
                doc_id=cve_id,
                text=chunk,
                source="nvd",
                doc_type="cve",
                metadata={
                    "cve_id": cve_id,
                    "cvss": cvss,
                    "affected_cpe": cpes,
                    "published": item.get("published", ""),
                },
            ))
            texts.append(chunk)

    if texts:
        embeddings = embedder.embed_documents(texts)
        store.add(docs, embeddings)
        log.info("Ingested %d chunks from %d CVEs", len(docs), len(items))

    return len(docs)


def ingest_exploit_db(exploit_path: Path, store: VectorStore, embedder: Embedder) -> int:
    """Ingest Exploit-DB entries (JSONL format).

    Expected format per line:
    {
        "edb_id": "50383",
        "title": "Apache HTTP Server 2.4.49 - Path Traversal",
        "cve": "CVE-2021-41773",
        "type": "webapps",
        "platform": "multiple",
        "description": "...",
        "code": "curl ...",
        "verified": true
    }
    """
    docs: List[VectorDocument] = []
    texts: List[str] = []

    with open(exploit_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            item = json.loads(line)
            edb_id = item.get("edb_id", "unknown")
            enriched = (
                f"Exploit-DB {edb_id}: {item.get('title', '')}\\n"
                f"CVE: {item.get('cve', 'N/A')} | Type: {item.get('type', '')}\\n"
                f"Description: {item.get('description', '')}\\n"
                f"PoC: {item.get('code', '')[:500]}"
            )

            for chunk in chunk_text(enriched):
                docs.append(VectorDocument(
                    doc_id=f"EDB-{edb_id}",
                    text=chunk,
                    source="exploit_db",
                    doc_type="exploit",
                    metadata={
                        "edb_id": edb_id,
                        "cve": item.get("cve"),
                        "verified": item.get("verified", False),
                    },
                ))
                texts.append(chunk)

    if texts:
        embeddings = embedder.embed_documents(texts)
        store.add(docs, embeddings)
        log.info("Ingested %d chunks from Exploit-DB", len(docs))

    return len(docs)


def build_index(
    cve_paths: List[Path] | None = None,
    exploit_paths: List[Path] | None = None,
) -> VectorStore:
    """Full index build from all sources."""
    embedder = Embedder.get()
    store = VectorStore()
    total = 0

    for path in (cve_paths or []):
        total += ingest_cve_json(path, store, embedder)

    for path in (exploit_paths or []):
        total += ingest_exploit_db(path, store, embedder)

    store.save()
    log.info("Index built with %d total chunks", total)
    return store
'''


# =============================================================================
# SECTION 1B: RETRIEVER
# =============================================================================

RETRIEVER_PY = '''
"""RAG retriever: tech_detect output → vector query → ranked knowledge entries."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .embedder import Embedder
from .vector_store import SearchResult, VectorStore

log = logging.getLogger("autopnex.kb.rag.retriever")


@dataclass
class KnowledgeEntry:
    """A single piece of retrieved vulnerability intelligence."""
    source: str              # "nvd" | "exploit_db" | "poc" | "advisory"
    doc_id: str              # CVE ID or EDB ID
    text: str                # The relevant chunk
    relevance_score: float   # 0.0–1.0 (inner product similarity)
    metadata: Dict[str, Any] = field(default_factory=dict)


class RAGRetriever:
    """Query the knowledge base using technology fingerprints as context."""

    def __init__(self, store: Optional[VectorStore] = None):
        self._store = store
        self._embedder = Embedder.get()

    def _ensure_store(self) -> VectorStore:
        if self._store is None:
            self._store = VectorStore()
            if not self._store.load():
                log.warning("No vector index found; RAG retrieval will return empty results")
        return self._store

    def query_by_technologies(
        self,
        technologies: List[str],
        top_k: int = 8,
        min_score: float = 0.35,
    ) -> List[KnowledgeEntry]:
        """Build a natural-language query from detected technologies and retrieve."""
        if not technologies:
            return []

        query_text = (
            f"Known vulnerabilities and exploits for: {', '.join(technologies)}. "
            f"CVE advisories, proof of concept, attack vectors."
        )
        return self.query(query_text, top_k=top_k, min_score=min_score)

    def query_by_cve(self, cve_id: str, top_k: int = 5) -> List[KnowledgeEntry]:
        """Retrieve details about a specific CVE."""
        return self.query(f"CVE vulnerability {cve_id} exploit details affected versions", top_k=top_k)

    def query(
        self,
        text: str,
        top_k: int = 8,
        min_score: float = 0.30,
        filter_source: Optional[str] = None,
    ) -> List[KnowledgeEntry]:
        store = self._ensure_store()
        embedding = self._embedder.embed_query(text)
        results: List[SearchResult] = store.search(
            embedding, top_k=top_k, filter_source=filter_source
        )

        entries = []
        seen_doc_ids = set()
        for result in results:
            if result.score < min_score:
                continue
            doc = result.document
            if doc.doc_id in seen_doc_ids:
                continue
            seen_doc_ids.add(doc.doc_id)
            entries.append(KnowledgeEntry(
                source=doc.source,
                doc_id=doc.doc_id,
                text=doc.text,
                relevance_score=result.score,
                metadata=doc.metadata,
            ))

        return entries
'''


# =============================================================================
# SECTION 2: TECHNOLOGY-TO-CVE MAPPING
# =============================================================================

CPE_MATCHER_PY = '''
"""CPE-based technology-to-CVE mapping with version range comparison."""
from __future__ import annotations

import logging
import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple

from packaging.version import Version, InvalidVersion

log = logging.getLogger("autopnex.kb.intel.cpe_matcher")

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "cve_cache.db"

TECH_TO_CPE_PREFIX = {
    "Apache":        "cpe:2.3:a:apache:http_server",
    "Nginx":         "cpe:2.3:a:f5:nginx",
    "Microsoft IIS": "cpe:2.3:a:microsoft:internet_information_services",
    "PHP":           "cpe:2.3:a:php:php",
    "WordPress":     "cpe:2.3:a:wordpress:wordpress",
    "Drupal":        "cpe:2.3:a:drupal:drupal",
    "Joomla":        "cpe:2.3:a:joomla:joomla\\!",
    "Django":        "cpe:2.3:a:djangoproject:django",
    "Flask":         "cpe:2.3:a:palletsprojects:flask",
    "Laravel":       "cpe:2.3:a:laravel:laravel",
    "Express.js":    "cpe:2.3:a:expressjs:express",
    "Next.js":       "cpe:2.3:a:vercel:next.js",
    "Spring":        "cpe:2.3:a:vmware:spring_framework",
    "jQuery":        "cpe:2.3:a:jquery:jquery",
    "React":         "cpe:2.3:a:facebook:react",
    "Vue.js":        "cpe:2.3:a:vuejs:vue.js",
    "AngularJS":     "cpe:2.3:a:angularjs:angular.js",
    "ASP.NET":       "cpe:2.3:a:microsoft:asp.net",
    "phpMyAdmin":    "cpe:2.3:a:phpmyadmin:phpmyadmin",
    "OpenResty":     "cpe:2.3:a:openresty:openresty",
    "LiteSpeed":     "cpe:2.3:a:litespeedtech:litespeed_web_server",
    "Caddy":         "cpe:2.3:a:caddyserver:caddy",
    "CodeIgniter":   "cpe:2.3:a:codeigniter:codeigniter",
    "Ghost":         "cpe:2.3:a:ghost:ghost",
    "Bootstrap":     "cpe:2.3:a:getbootstrap:bootstrap",
}


@dataclass
class CVEMatch:
    cve_id: str
    cvss: float
    description: str
    affected_cpe: str
    version_start: str
    version_end: str
    published: str


def parse_tech_version(tech_string: str) -> Tuple[str, Optional[str]]:
    """Extract technology name and version from tech_detect output.

    Examples:
        "Apache"       -> ("Apache", None)
        "PHP 8.1.2"   -> ("PHP", "8.1.2")
        "Apache/2.4.49" -> ("Apache", "2.4.49")
    """
    tech_string = tech_string.strip()
    m = re.match(r"^(.+?)[/ ](\\d[\\d.]*\\d?)$", tech_string)
    if m:
        return m.group(1).strip(), m.group(2)
    return tech_string, None


def version_in_range(
    version: str,
    start_incl: Optional[str] = None,
    end_incl: Optional[str] = None,
    end_excl: Optional[str] = None,
) -> bool:
    """Check if a version falls within an affected range."""
    try:
        v = Version(version)
    except InvalidVersion:
        return False

    if start_incl:
        try:
            if v < Version(start_incl):
                return False
        except InvalidVersion:
            pass

    if end_incl:
        try:
            if v > Version(end_incl):
                return False
        except InvalidVersion:
            pass

    if end_excl:
        try:
            if v >= Version(end_excl):
                return False
        except InvalidVersion:
            pass

    return True


class CPEMatcher:
    """Matches tech_detect output to known CVEs via CPE prefix + version range."""

    def __init__(self, db_path: Path = DB_PATH):
        self._db_path = db_path
        self._conn: Optional[sqlite3.Connection] = None

    def _ensure_db(self) -> sqlite3.Connection:
        if self._conn is not None:
            return self._conn
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._db_path))
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS cve_entries (
                cve_id TEXT PRIMARY KEY,
                cvss REAL DEFAULT 0,
                description TEXT DEFAULT '',
                affected_cpe TEXT DEFAULT '',
                version_start TEXT DEFAULT '',
                version_end TEXT DEFAULT '',
                version_end_excl TEXT DEFAULT '',
                published TEXT DEFAULT '',
                source TEXT DEFAULT 'nvd'
            )
        """)
        self._conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_cve_cpe ON cve_entries(affected_cpe)
        """)
        self._conn.commit()
        return self._conn

    def populate_from_json(self, cve_items: list) -> int:
        """Bulk-load CVE entries. Each item: {id, cvss_v3_score, description, affected_cpe, ...}"""
        conn = self._ensure_db()
        count = 0
        for item in cve_items:
            for cpe in item.get("affected_cpe", []):
                conn.execute("""
                    INSERT OR REPLACE INTO cve_entries
                    (cve_id, cvss, description, affected_cpe, version_start, version_end, published)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    item["id"],
                    item.get("cvss_v3_score", 0),
                    item.get("description", "")[:2000],
                    cpe,
                    item.get("version_start_including", ""),
                    item.get("version_end_including", ""),
                    item.get("published", ""),
                ))
                count += 1
        conn.commit()
        return count

    def match_technology(self, tech_string: str) -> List[CVEMatch]:
        """Find CVEs matching a detected technology string."""
        name, version = parse_tech_version(tech_string)
        cpe_prefix = TECH_TO_CPE_PREFIX.get(name)
        if cpe_prefix is None:
            return []

        conn = self._ensure_db()
        cursor = conn.execute(
            "SELECT cve_id, cvss, description, affected_cpe, version_start, version_end, published "
            "FROM cve_entries WHERE affected_cpe LIKE ? ORDER BY cvss DESC LIMIT 50",
            (f"{cpe_prefix}%",),
        )

        matches = []
        for row in cursor:
            cve_id, cvss, desc, cpe, v_start, v_end, published = row
            if version and v_start and v_end:
                if not version_in_range(version, start_incl=v_start, end_incl=v_end):
                    continue
            matches.append(CVEMatch(
                cve_id=cve_id,
                cvss=cvss,
                description=desc[:500],
                affected_cpe=cpe,
                version_start=v_start,
                version_end=v_end,
                published=published,
            ))

        matches.sort(key=lambda m: m.cvss, reverse=True)
        return matches[:20]

    def match_all_technologies(self, technologies: List[str]) -> List[CVEMatch]:
        """Match all detected technologies, deduplicate, sort by CVSS."""
        seen = set()
        all_matches = []
        for tech in technologies:
            for match in self.match_technology(tech):
                if match.cve_id not in seen:
                    seen.add(match.cve_id)
                    all_matches.append(match)
        all_matches.sort(key=lambda m: m.cvss, reverse=True)
        return all_matches
'''


# =============================================================================
# SECTION 3: PoC KNOWLEDGE BASE
# =============================================================================

POC_YAML_SCHEMA = """
# --- PoC Payload Schema (YAML) ---
# File: autopnex/knowledge_base/poc/payloads/sqli.yaml

payloads:
  - id: sqli-mysql-union-001
    vuln_type: sqli
    sub_type: union_based
    cve: null                           # null = generic, or specific CVE
    cvss: 8.6
    tech_stack:
      - PHP
      - MySQL
    waf_bypass: false
    description: "MySQL UNION-based injection with information_schema enumeration"
    affected_versions: "*"
    payload: "' UNION SELECT 1,@@version,3,4-- -"
    detection_payload: "' AND 1=1-- -"
    expected_response:
      contains: ["5.7", "8.0", "MariaDB"]  # any substring match = success
      status_code: 200
    cleanup: null
    references:
      - "https://owasp.org/www-community/attacks/SQL_Injection"

  - id: sqli-mssql-stacked-001
    vuln_type: sqli
    sub_type: stacked_queries
    cve: null
    cvss: 9.0
    tech_stack:
      - ASP.NET
      - MSSQL
    waf_bypass: false
    description: "MSSQL stacked queries for command execution"
    payload: "'; EXEC xp_cmdshell('whoami')-- -"
    expected_response:
      contains: ["nt authority", "iis apppool"]
    references:
      - "https://book.hacktricks.xyz/pentesting-web/sql-injection/mssql-injection"

  - id: sqli-mysql-time-blind-waf
    vuln_type: sqli
    sub_type: time_blind
    tech_stack:
      - PHP
      - MySQL
    waf_bypass: true
    waf_bypass_technique: "inline comment obfuscation"
    description: "Time-based blind SQLi with WAF bypass using inline comments"
    payload: "1'/*!50000AND*/(/*!50000SLEEP*/(5))-- -"
    expected_response:
      min_response_time_ms: 4500
"""

POC_REGISTRY_PY = '''
"""PoC payload registry: load, query, and select payloads by context."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

log = logging.getLogger("autopnex.kb.poc")

PAYLOADS_DIR = Path(__file__).resolve().parent / "payloads"


@dataclass
class PoCPayload:
    id: str
    vuln_type: str                          # sqli, xss, ssrf, rce, lfi, ...
    sub_type: str = ""                      # union_based, time_blind, reflected, ...
    cve: Optional[str] = None
    cvss: float = 0.0
    tech_stack: List[str] = field(default_factory=list)
    waf_bypass: bool = False
    waf_bypass_technique: str = ""
    description: str = ""
    affected_versions: str = "*"
    payload: str = ""
    detection_payload: str = ""
    expected_response: Dict[str, Any] = field(default_factory=dict)
    cleanup: Optional[str] = None
    references: List[str] = field(default_factory=list)


class PoCRegistry:
    """Loads and queries PoC payloads from YAML files."""

    def __init__(self, payloads_dir: Path = PAYLOADS_DIR):
        self._dir = payloads_dir
        self._payloads: List[PoCPayload] = []
        self._loaded = False

    def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        if not self._dir.exists():
            log.warning("PoC payloads directory not found: %s", self._dir)
            return
        for yaml_file in sorted(self._dir.glob("*.yaml")):
            try:
                data = yaml.safe_load(yaml_file.read_text(encoding="utf-8"))
                for item in data.get("payloads", []):
                    self._payloads.append(PoCPayload(**{
                        k: v for k, v in item.items()
                        if k in PoCPayload.__dataclass_fields__
                    }))
            except Exception:
                log.warning("Failed to load PoC file: %s", yaml_file, exc_info=True)
        log.info("Loaded %d PoC payloads from %s", len(self._payloads), self._dir)

    def query(
        self,
        vuln_type: Optional[str] = None,
        tech_stack: Optional[List[str]] = None,
        waf_bypass: Optional[bool] = None,
        cve: Optional[str] = None,
        limit: int = 10,
    ) -> List[PoCPayload]:
        """Find matching PoC payloads by vulnerability type and technology stack."""
        self._ensure_loaded()
        results = []

        for poc in self._payloads:
            if vuln_type and poc.vuln_type != vuln_type:
                continue
            if cve and poc.cve != cve:
                continue
            if waf_bypass is not None and poc.waf_bypass != waf_bypass:
                continue

            tech_score = 0
            if tech_stack and poc.tech_stack:
                tech_lower = {t.lower() for t in tech_stack}
                poc_lower = {t.lower() for t in poc.tech_stack}
                tech_score = len(tech_lower & poc_lower)

            results.append((tech_score, poc.cvss, poc))

        results.sort(key=lambda x: (x[0], x[1]), reverse=True)
        return [poc for _, _, poc in results[:limit]]

    def get_payloads_for_context(
        self,
        vuln_type: str,
        technologies: List[str],
    ) -> List[str]:
        """Return just the payload strings, ranked by tech-stack relevance."""
        matches = self.query(vuln_type=vuln_type, tech_stack=technologies, limit=5)
        return [m.payload for m in matches if m.payload]

    @property
    def all_payloads(self) -> List[PoCPayload]:
        self._ensure_loaded()
        return list(self._payloads)
'''


# =============================================================================
# SECTION 4: LLM CONTEXT ENHANCEMENT — PROMPT INJECTION
# =============================================================================

PROMPT_INJECTOR_PY = '''
"""Token-budget-aware RAG context injection into LLM prompts."""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from .retriever import KnowledgeEntry, RAGRetriever
from ..intel.cpe_matcher import CPEMatcher, CVEMatch
from ..poc.poc_registry import PoCPayload, PoCRegistry


TOKEN_BUDGET_RAG = 1500
TOKEN_BUDGET_CVE = 800
TOKEN_BUDGET_POC = 500
CHARS_PER_TOKEN = 3.5  # conservative estimate for English text


def _estimate_tokens(text: str) -> int:
    return int(len(text) / CHARS_PER_TOKEN)


def build_rag_context(
    technologies: List[str],
    findings_snapshot: Dict[str, Any],
    state: str,
    *,
    retriever: Optional[RAGRetriever] = None,
    cpe_matcher: Optional[CPEMatcher] = None,
    poc_registry: Optional[PoCRegistry] = None,
) -> str:
    """Assemble RAG-enriched context block for prompt injection.

    Returns a formatted string that fits within the combined token budget.
    """
    sections: List[str] = []
    remaining_budget = TOKEN_BUDGET_RAG + TOKEN_BUDGET_CVE + TOKEN_BUDGET_POC

    # --- 1. CVE matches from CPE database ---
    if cpe_matcher and technologies:
        cve_matches = cpe_matcher.match_all_technologies(technologies)
        if cve_matches:
            cve_lines = ["## Known CVEs for Detected Technologies"]
            for match in cve_matches[:8]:
                line = f"- {match.cve_id} (CVSS {match.cvss}): {match.description[:120]}"
                cve_lines.append(line)
            cve_block = "\\n".join(cve_lines)
            tokens = _estimate_tokens(cve_block)
            if tokens <= TOKEN_BUDGET_CVE:
                sections.append(cve_block)
                remaining_budget -= tokens

    # --- 2. RAG-retrieved knowledge entries ---
    if retriever and technologies:
        entries = retriever.query_by_technologies(technologies, top_k=6)
        if entries:
            rag_lines = ["## Vulnerability Intelligence (RAG)"]
            budget_left = min(remaining_budget, TOKEN_BUDGET_RAG)
            for entry in entries:
                line = f"- [{entry.source}] {entry.doc_id}: {entry.text[:200]}"
                line_tokens = _estimate_tokens(line)
                if budget_left - line_tokens < 0:
                    break
                rag_lines.append(line)
                budget_left -= line_tokens
            if len(rag_lines) > 1:
                rag_block = "\\n".join(rag_lines)
                sections.append(rag_block)
                remaining_budget -= _estimate_tokens(rag_block)

    # --- 3. PoC suggestions (only during VULN_DETECT and EXPLOIT phases) ---
    if poc_registry and state in ("VULN_DETECT", "EXPLOIT"):
        vuln_types_in_findings = _extract_vuln_types(findings_snapshot)
        if vuln_types_in_findings:
            poc_lines = ["## Suggested PoC Payloads"]
            budget_left = min(remaining_budget, TOKEN_BUDGET_POC)
            for vtype in vuln_types_in_findings[:3]:
                payloads = poc_registry.query(vuln_type=vtype, tech_stack=technologies, limit=3)
                for poc in payloads:
                    line = f"- [{vtype}] {poc.payload[:100]}"
                    if poc.waf_bypass:
                        line += " (WAF bypass)"
                    line_tokens = _estimate_tokens(line)
                    if budget_left - line_tokens < 0:
                        break
                    poc_lines.append(line)
                    budget_left -= line_tokens
            if len(poc_lines) > 1:
                sections.append("\\n".join(poc_lines))

    if not sections:
        return ""

    return "\\n\\n".join(sections)


def _extract_vuln_types(findings_snapshot: Dict[str, Any]) -> List[str]:
    """Pull vulnerability categories from the findings snapshot."""
    categories = set()
    for finding in findings_snapshot.get("findings", []):
        cat = finding.get("category", "")
        if cat in ("sqli", "xss", "ssrf", "cmdi", "rce", "lfi"):
            categories.add(cat)
    return sorted(categories)
'''


# =============================================================================
# SECTION 4B: MODIFIED build_user_prompt — INTEGRATION POINT
# =============================================================================

MODIFIED_PROMPTS_PY = '''
# This shows the MODIFIED version of autopnex/orchestrator/prompts.py
# Changes marked with ### NEW ###

"""Prompt templates for AutoPenX state-machine handlers."""
from __future__ import annotations


SYSTEM_PROMPT = """You are AutoPenX, a senior offensive security engineer acting as the brain of an
automated penetration testing pipeline. You operate strictly within the scope of the user's
authorised target. Follow PTES stages (recon → scan → vuln detect → exploit → report) and
use the provided tools to gather and validate evidence.

Core rules:
1. Think step-by-step but keep internal reasoning concise in your `content` field.
2. When you need data, CALL A TOOL via the function calling interface. You may only choose
   tasks listed under `phase_tasks`; do not invent new tools, arguments or targets.
3. When enough evidence has been gathered for the current phase, respond with a short JSON
   object in `content`:
   {"action": "advance" | "stay" | "done", "reason": "...", "task_ref": "...", "rationale": "..."}
   * "advance" moves to the next state.
   * "stay" keeps the current state (another tool call will happen next iteration).
   * "done" is only used during REPORT to terminate.
4. Never fabricate findings — only record what tool outputs prove.
5. Be efficient: avoid redundant scans, respect the max iterations per state, and prefer
   confirmed evidence over speculative actions.
6. When vulnerability intelligence is provided below, use it to PRIORITIZE which parameters
   and attack vectors to test first. Match known CVEs to the target's technology stack.
"""


STATE_PROMPTS = {
    "RECON": """Phase: RECON.
Goal: understand the target surface — reachable host, open ports, tech stack, subdomains.
Available tools (typical usage):
- port_scan: TCP scan of the target host.
- tech_detect: fingerprint the HTTP server / frameworks / libs.
- subdomain_find: query crt.sh for related FQDNs.
When you have enough context to move on, advance.""",
    "SCAN": """Phase: SCAN.
Goal: enumerate the web attack surface — sensitive files, directories, pages, forms, params.
Available tools: web_scan (Nikto-style), dir_buster (wordlist), crawl (BFS crawler).
Advance when you have a list of candidate URLs / parameters to fuzz.""",
    "VULN_DETECT": """Phase: VULN_DETECT.
Goal: for each discovered parameter, check SQLi, XSS, SSRF, command injection.
Focus on the most promising parameters first (query string params, form inputs). Record
only parameters the detectors confirm as vulnerable.
IMPORTANT: If vulnerability intelligence below mentions specific CVEs affecting the detected
technology stack, prioritize testing for those specific vulnerability patterns.""",
    "EXPLOIT": """Phase: EXPLOIT.
Goal: for each confirmed vulnerability, run a benign proof-of-concept to collect evidence.
Currently you have sqli_exploit. For other findings, simply advance once PoC data or a clear
summary is captured.
Use PoC payloads from the knowledge base when available for the target technology stack.""",
    "REPORT": """Phase: REPORT.
No more tools should be called here. Return {"action": "done", "reason": "ready"}.""",
}


def build_user_prompt(
    state: str,
    findings_snapshot: dict,
    iteration: int,
    max_iter: int,
    *,
    rag_context: str = "",                  ### NEW ###
) -> str:
    import json

    parts = [
        f"Current state: {state} (iteration {iteration}/{max_iter})",
        STATE_PROMPTS.get(state, ""),
    ]

    ### NEW: inject RAG context before findings ###
    if rag_context:
        parts.append(
            "--- Vulnerability Intelligence (auto-retrieved) ---\\n"
            f"{rag_context}\\n"
            "--- End Intelligence ---"
        )

    parts.append(
        f"Findings snapshot:\\n{json.dumps(findings_snapshot, ensure_ascii=False, indent=2)}"
    )

    parts.append(
        "Decide the next action. If a tool call is useful, request exactly one tool that "
        "matches one pending phase task. If no tool call is needed, return strict JSON only."
    )

    return "\\n\\n".join(parts)
'''


# =============================================================================
# SECTION 4C: ORCHESTRATOR INTEGRATION — WHERE RAG GETS CALLED
# =============================================================================

ORCHESTRATOR_INTEGRATION = '''
# In autopnex/orchestrator/orchestrator.py, modify the `step` method:
# The key change is building RAG context before calling build_user_prompt.

def step(self, state: str, findings_snapshot: Dict[str, Any], iteration: int, max_iter: int) -> ReActStep:
    # ### NEW: Build RAG context from detected technologies ###
    rag_context = ""
    if self._rag_retriever is not None:
        technologies = findings_snapshot.get("technologies", [])
        from ..knowledge_base.rag.prompt_injector import build_rag_context
        rag_context = build_rag_context(
            technologies=technologies,
            findings_snapshot=findings_snapshot,
            state=state,
            retriever=self._rag_retriever,
            cpe_matcher=self._cpe_matcher,
            poc_registry=self._poc_registry,
        )

    user_prompt = build_user_prompt(
        state, findings_snapshot, iteration, max_iter,
        rag_context=rag_context,                      # ### NEW ###
    )
    # ... rest of step() unchanged ...


# In __init__, add optional knowledge-base components:
def __init__(
    self,
    *,
    mock: bool = False,
    client: Optional[LLMClient] = None,
    runtime_config: Optional[RuntimeConfig] = None,
    rag_retriever=None,        # ### NEW ###
    cpe_matcher=None,          # ### NEW ###
    poc_registry=None,         # ### NEW ###
):
    # ... existing init ...
    self._rag_retriever = rag_retriever
    self._cpe_matcher = cpe_matcher
    self._poc_registry = poc_registry
'''


# =============================================================================
# SECTION 5: SCAN HISTORY LEARNING
# =============================================================================

SCAN_HISTORY_PY = '''
"""Lightweight scan history storage using SQLite."""
from __future__ import annotations

import json
import logging
import sqlite3
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger("autopnex.kb.history")

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "scan_history.db"


class ScanHistory:
    """Records and queries past scan results for learning."""

    def __init__(self, db_path: Path = DB_PATH):
        self._db_path = db_path
        self._conn: Optional[sqlite3.Connection] = None

    def _ensure_db(self) -> sqlite3.Connection:
        if self._conn is not None:
            return self._conn
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._db_path))
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                technologies TEXT DEFAULT '[]',
                findings_count INTEGER DEFAULT 0,
                findings_json TEXT DEFAULT '[]'
            );

            CREATE TABLE IF NOT EXISTS tool_outcomes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                phase TEXT NOT NULL,
                tool TEXT NOT NULL,
                arguments_json TEXT DEFAULT '{}',
                success INTEGER NOT NULL,
                found_vuln INTEGER DEFAULT 0,
                duration_ms INTEGER DEFAULT 0,
                tech_stack TEXT DEFAULT '[]',
                FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
            );

            CREATE INDEX IF NOT EXISTS idx_tool_outcomes_tool
                ON tool_outcomes(tool, tech_stack);
        """)
        self._conn.commit()
        return self._conn

    def record_scan(
        self,
        scan_id: str,
        target: str,
        technologies: List[str],
        findings: List[Dict[str, Any]],
        tool_invocations: List[Dict[str, Any]],
    ) -> None:
        conn = self._ensure_db()
        now = datetime.utcnow().isoformat() + "Z"

        conn.execute(
            "INSERT OR REPLACE INTO scans VALUES (?, ?, ?, ?, ?, ?, ?)",
            (scan_id, target, now, now,
             json.dumps(technologies), len(findings), json.dumps(findings[:50])),
        )

        vuln_tools = set()
        for finding in findings:
            if finding.get("tool"):
                vuln_tools.add((finding["tool"], finding.get("url"), finding.get("parameter")))

        for inv in tool_invocations:
            found = 1 if (inv.get("tool"), inv.get("url"), inv.get("parameter")) in vuln_tools else 0
            conn.execute(
                "INSERT INTO tool_outcomes (scan_id, phase, tool, arguments_json, success, found_vuln, duration_ms, tech_stack) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (scan_id, inv.get("state", ""), inv.get("tool", ""),
                 json.dumps(inv.get("arguments", {})),
                 1 if inv.get("success") else 0,
                 found,
                 inv.get("duration_ms", 0),
                 json.dumps(technologies)),
            )
        conn.commit()
        log.info("Recorded scan %s: %d findings, %d invocations", scan_id, len(findings), len(tool_invocations))

    def tool_success_rate(self, tool: str, tech_stack: Optional[List[str]] = None) -> Tuple[int, int, float]:
        """Return (total_runs, vuln_found_count, success_rate) for a tool."""
        conn = self._ensure_db()
        if tech_stack:
            tech_pattern = f"%{tech_stack[0]}%" if tech_stack else "%"
            cursor = conn.execute(
                "SELECT COUNT(*), SUM(found_vuln) FROM tool_outcomes WHERE tool = ? AND tech_stack LIKE ?",
                (tool, tech_pattern),
            )
        else:
            cursor = conn.execute(
                "SELECT COUNT(*), SUM(found_vuln) FROM tool_outcomes WHERE tool = ?",
                (tool,),
            )
        row = cursor.fetchone()
        total = row[0] or 0
        found = row[1] or 0
        rate = found / total if total > 0 else 0.0
        return total, found, rate

    def suggest_tool_priority(self, phase: str, technologies: List[str]) -> List[Tuple[str, float]]:
        """Return tools sorted by historical vuln-discovery rate for the given tech stack."""
        conn = self._ensure_db()
        tech_filter = f"%{technologies[0]}%" if technologies else "%"
        cursor = conn.execute(
            "SELECT tool, COUNT(*) as runs, SUM(found_vuln) as found "
            "FROM tool_outcomes WHERE phase = ? AND tech_stack LIKE ? "
            "GROUP BY tool ORDER BY (CAST(found AS REAL) / runs) DESC",
            (phase, tech_filter),
        )
        return [(row[0], row[2] / row[1] if row[1] > 0 else 0.0) for row in cursor]
'''


PRIORITY_LEARNER_PY = '''
"""Reorder phase tasks based on historical scan data."""
from __future__ import annotations

from typing import Any, Dict, List

from .scan_history import ScanHistory


class PriorityLearner:
    """Uses scan history to reorder tasks for maximum early discovery."""

    def __init__(self, history: ScanHistory):
        self._history = history

    def reorder_tasks(
        self,
        phase: str,
        tasks: List[Dict[str, Any]],
        technologies: List[str],
    ) -> List[Dict[str, Any]]:
        """Reorder tasks so historically productive tools run first."""
        tool_scores = dict(self._history.suggest_tool_priority(phase, technologies))

        def sort_key(task: Dict[str, Any]) -> float:
            tool = task.get("tool", "")
            return -(tool_scores.get(tool, 0.0))

        return sorted(tasks, key=sort_key)
'''


# =============================================================================
# SECTION 6: DYNAMIC WORDLIST GENERATION
# =============================================================================

WORDLIST_GENERATOR_PY = '''
"""Generate target-specific wordlists based on technology stack detection."""
from __future__ import annotations

import logging
from pathlib import Path
from typing import List, Set

log = logging.getLogger("autopnex.kb.wordlists")

TECH_PATHS_DIR = Path(__file__).resolve().parent / "tech_paths"

COMMON_BASE = [
    "admin", "login", "dashboard", "api", "robots.txt", "sitemap.xml",
    ".git/config", ".env", "backup", "uploads", "debug", "test",
    "config", "status", "health", "version", "info",
]

TECH_WORDLISTS = {
    "WordPress": [
        "wp-admin/", "wp-login.php", "wp-content/", "wp-includes/",
        "wp-json/wp/v2/users", "wp-json/wp/v2/posts", "xmlrpc.php",
        "wp-config.php", "wp-config.php.bak", "wp-cron.php",
        "wp-content/uploads/", "wp-content/plugins/", "wp-content/themes/",
        "readme.html", "license.txt",
    ],
    "Drupal": [
        "user/login", "admin/", "node/1", "sites/default/files/",
        "CHANGELOG.txt", "core/install.php", "user/register",
        "sites/default/settings.php", "update.php",
    ],
    "Joomla": [
        "administrator/", "administrator/index.php",
        "configuration.php", "language/en-GB/en-GB.xml",
        "media/", "modules/", "plugins/", "templates/",
    ],
    "Django": [
        "admin/", "admin/login/", "api/", "api/v1/", "api/v2/",
        "static/", "media/", "accounts/login/", "accounts/signup/",
        "__debug__/", "graphql",
    ],
    "Flask": [
        "admin/", "api/", "api/v1/", "static/", "debug/",
        "swagger/", "docs/", "health", "metrics",
    ],
    "Laravel": [
        "admin/", "login", "register", "api/", "storage/",
        "public/", "telescope/", "horizon/", "nova/",
        "_debugbar/", ".env", "artisan", "composer.json",
    ],
    "Spring": [
        "actuator/", "actuator/env", "actuator/health", "actuator/beans",
        "actuator/mappings", "actuator/configprops", "actuator/trace",
        "actuator/heapdump", "actuator/threaddump", "actuator/loggers",
        "swagger-ui.html", "swagger-ui/", "v2/api-docs", "v3/api-docs",
        "api/", "admin/", "console/", "h2-console/",
    ],
    "Express.js": [
        "api/", "api/v1/", "graphql", "health", "status",
        "docs/", "swagger/", "debug/", "metrics",
        ".env", "package.json", "node_modules/",
    ],
    "Next.js": [
        "_next/", "api/", "api/auth/", "_next/data/",
        "404", "500", "_next/static/", "sitemap.xml",
    ],
    "ASP.NET": [
        "web.config", "elmah.axd", "trace.axd", "admin/",
        "api/", "swagger/", "hangfire/", "signalr/",
    ],
    "PHP": [
        "phpinfo.php", "phpmyadmin/", "adminer.php", "info.php",
        "config.php", "config.php.bak", ".htaccess", "composer.json",
    ],
    "Java EE / Servlet": [
        "WEB-INF/web.xml", "META-INF/", "manager/html",
        "status/", "jmx-console/", "admin-console/",
    ],
    "phpMyAdmin": [
        "phpmyadmin/", "pma/", "mysql/", "dbadmin/",
        "myadmin/", "phpMyAdmin/", "phpmyadmin/setup/",
    ],
}


def generate_wordlist(technologies: List[str], include_common: bool = True) -> List[str]:
    """Generate a deduplicated wordlist based on detected technologies."""
    paths: List[str] = []
    seen: Set[str] = set()

    if include_common:
        for p in COMMON_BASE:
            if p not in seen:
                paths.append(p)
                seen.add(p)

    for tech in technologies:
        tech_paths = TECH_WORDLISTS.get(tech, [])
        for p in tech_paths:
            if p not in seen:
                paths.append(p)
                seen.add(p)

        ext_file = TECH_PATHS_DIR / f"{tech.lower().replace(' ', '_').replace('.', '')}.txt"
        if ext_file.exists():
            for line in ext_file.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#") and line not in seen:
                    paths.append(line)
                    seen.add(line)

    log.info("Generated wordlist: %d paths for technologies %s", len(paths), technologies)
    return paths


def wordlist_for_cms(cms_name: str) -> List[str]:
    """Return CMS-specific paths only."""
    return TECH_WORDLISTS.get(cms_name, [])
'''


# =============================================================================
# SECTION 7: INTEGRATION SUMMARY — HOW EVERYTHING CONNECTS
# =============================================================================

INTEGRATION_POINTS = """
Integration Points Into Existing AutoPenX Code
===============================================

1. autopnex/orchestrator/orchestrator.py — LLMOrchestrator.__init__()
   ─────────────────────────────────────────────────────────────────
   ADD optional parameters: rag_retriever, cpe_matcher, poc_registry
   In step(), call build_rag_context() and pass result to build_user_prompt()

   WHY: This is the single point where LLM context is assembled. Injecting
   RAG results here means every LLM decision benefits from external knowledge.

2. autopnex/orchestrator/prompts.py — build_user_prompt()
   ─────────────────────────────────────────────────────────
   ADD `rag_context: str = ""` keyword parameter
   Insert RAG context block between STATE_PROMPT and findings_snapshot

   WHY: The rag_context goes BEFORE findings so the LLM can use vulnerability
   intelligence to interpret what it sees in findings.

3. autopnex/state_machine/machine.py — PenTestStateMachine.__init__()
   ─────────────────────────────────────────────────────────────────
   Initialize knowledge base components:
     - RAGRetriever (loads vector store)
     - CPEMatcher (opens SQLite)
     - PoCRegistry (loads YAML)
     - ScanHistory (opens SQLite)
   Pass them to LLMOrchestrator.

   In _prepare_phase(), call PriorityLearner.reorder_tasks() before sync.

4. autopnex/state_machine/machine.py — PenTestStateMachine.run() (end)
   ─────────────────────────────────────────────────────────────────
   After "DONE", call ScanHistory.record_scan() to persist the results.

5. autopnex/state_machine/ingester.py — ingest_tool_result(), tech_detect branch
   ─────────────────────────────────────────────────────────────────
   AFTER recording technologies, trigger CPEMatcher.match_all_technologies()
   and auto-generate additional VULN_DETECT tasks for matched CVEs.

6. autopnex/tools/scan/dir_buster.py — DirBusterTool._run()
   ─────────────────────────────────────────────────────────────────
   Replace static wordlist loading with:
     from ...knowledge_base.wordlists.generator import generate_wordlist
     paths = generate_wordlist(technologies)
   Fall back to common_paths.txt if technologies list is empty.

7. autopnex/knowledge_base/__init__.py — Expand exports
   ─────────────────────────────────────────────────────
   Add: RAGRetriever, CPEMatcher, PoCRegistry, ScanHistory, generate_wordlist
"""


# =============================================================================
# SECTION 8: DATA SCHEMAS
# =============================================================================

DATA_SCHEMAS = """
CVE Cache SQLite Schema (cve_cache.db)
========================================
CREATE TABLE cve_entries (
    cve_id TEXT PRIMARY KEY,
    cvss REAL DEFAULT 0,
    description TEXT DEFAULT '',
    affected_cpe TEXT DEFAULT '',       -- full CPE 2.3 URI
    version_start TEXT DEFAULT '',      -- versionStartIncluding
    version_end TEXT DEFAULT '',        -- versionEndIncluding
    version_end_excl TEXT DEFAULT '',   -- versionEndExcluding
    published TEXT DEFAULT '',
    source TEXT DEFAULT 'nvd'           -- 'nvd' | 'exploit_db' | 'advisory'
);
CREATE INDEX idx_cve_cpe ON cve_entries(affected_cpe);


Scan History SQLite Schema (scan_history.db)
=============================================
CREATE TABLE scans (
    scan_id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    technologies TEXT DEFAULT '[]',     -- JSON array
    findings_count INTEGER DEFAULT 0,
    findings_json TEXT DEFAULT '[]'     -- JSON array (trimmed)
);

CREATE TABLE tool_outcomes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    phase TEXT NOT NULL,                -- RECON | SCAN | VULN_DETECT | EXPLOIT
    tool TEXT NOT NULL,
    arguments_json TEXT DEFAULT '{}',
    success INTEGER NOT NULL,           -- 0/1
    found_vuln INTEGER DEFAULT 0,       -- 0/1: did this invocation discover a vuln?
    duration_ms INTEGER DEFAULT 0,
    tech_stack TEXT DEFAULT '[]',        -- JSON array of detected technologies
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
);
CREATE INDEX idx_tool_outcomes_tool ON tool_outcomes(tool, tech_stack);


Vector Store Layout (faiss_index/)
===================================
vulns.index       — FAISS IndexFlatIP binary, 384-dimensional vectors
vulns_meta.jsonl  — one JSON object per line, parallel to FAISS row indices:
  {
    "doc_id": "CVE-2021-41773",
    "text": "chunk text...",
    "source": "nvd",
    "doc_type": "cve",
    "metadata": {"cve_id": "...", "cvss": 7.5, "affected_cpe": [...]}
  }


PoC Payload YAML Schema
=========================
payloads:
  - id: string             # unique identifier
    vuln_type: string      # sqli | xss | ssrf | rce | lfi | cmdi
    sub_type: string       # union_based | time_blind | reflected | stored | ...
    cve: string | null     # specific CVE or null for generic
    cvss: float
    tech_stack: [string]   # ["PHP", "MySQL"]
    waf_bypass: bool
    waf_bypass_technique: string
    description: string
    affected_versions: string   # "*" or ">=2.4.49,<2.4.50"
    payload: string
    detection_payload: string
    expected_response:
      contains: [string]
      status_code: int
      min_response_time_ms: int
    cleanup: string | null
    references: [string]
"""


# =============================================================================
# SECTION 9: REQUIREMENTS DELTA
# =============================================================================

REQUIREMENTS_DELTA = """
New pip dependencies to add to requirements.txt:
=================================================

fastembed>=0.3.0          # ~130MB download, no PyTorch, uses ONNX Runtime
                          # Provides BAAI/bge-small-en-v1.5 (384-dim embeddings)
                          # Alternative: `sentence-transformers` (better quality
                          #   but requires PyTorch ~2GB)

faiss-cpu>=1.8.0          # Facebook AI Similarity Search, CPU-only build
                          # ~15MB, C++ core with Python bindings
                          # Alternative: `chromadb` (richer metadata filtering,
                          #   but adds SQLite + DuckDB + heavier deps)

pyyaml>=6.0               # Already likely a transitive dep; needed for
                          # PoC payload YAML files

packaging>=24.0           # PEP-440 version parsing and comparison
                          # Used by CPE matcher for version range checks
                          # ~500KB, pure Python

Total additional disk footprint: ~150MB (dominated by fastembed ONNX model)

NOT added (rationale):
- chromadb: Heavier (~200MB+), requires DuckDB. FAISS + JSONL sidecar is
  sufficient for <100K documents. Upgrade path exists if needed.
- sentence-transformers: Requires PyTorch (~2GB). fastembed uses ONNX
  Runtime which is 10x lighter with comparable quality for retrieval.
- neo4j: Knowledge graph would be powerful (like PentAGI) but violates
  "lightweight, no heavy infrastructure" constraint. SQLite handles
  the relationship queries we need.
- langchain: Too heavy/opinionated for what we need. Direct FAISS +
  fastembed is simpler and more transparent.
"""


# =============================================================================
# SECTION 10: INITIALIZATION / BOOTSTRAP FLOW
# =============================================================================

BOOTSTRAP_FLOW = '''
"""Bootstrap script: build the knowledge base from raw data feeds."""
# Usage: python -m autopnex.knowledge_base.bootstrap

from pathlib import Path
from .rag.ingester import build_index
from .intel.cpe_matcher import CPEMatcher


DATA_DIR = Path(__file__).resolve().parent / "data"
RAW_DIR = DATA_DIR / "raw"  # user places CVE JSON + exploit JSONL here


def bootstrap():
    """One-time index build from raw vulnerability data."""

    cve_files = sorted(RAW_DIR.glob("cve_*.json"))
    exploit_files = sorted(RAW_DIR.glob("exploitdb_*.jsonl"))

    print(f"Building vector index from {len(cve_files)} CVE files, "
          f"{len(exploit_files)} Exploit-DB files...")

    store = build_index(cve_paths=cve_files, exploit_paths=exploit_files)
    print(f"Vector index built: {store.size} chunks")

    # Also populate the CPE SQLite cache
    import json
    matcher = CPEMatcher()
    total_cpe = 0
    for cve_file in cve_files:
        items = json.loads(cve_file.read_text())
        if isinstance(items, dict):
            items = [items]
        total_cpe += matcher.populate_from_json(items)
    print(f"CPE database populated: {total_cpe} entries")


if __name__ == "__main__":
    bootstrap()
'''


# =============================================================================
# FINAL SUMMARY
# =============================================================================

SUMMARY = """
╔══════════════════════════════════════════════════════════════════════╗
║           AutoPenX RAG Knowledge Base — Design Summary             ║
╠══════════════════════════════════════════════════════════════════════╣
║                                                                    ║
║  Component              │ Technology        │ Storage               ║
║  ───────────────────────┼───────────────────┼──────────────────── ║
║  Embeddings             │ fastembed (ONNX)  │ In-memory at query  ║
║  Vector Store           │ FAISS (IndexIP)   │ vulns.index ~50MB   ║
║  CVE Database           │ SQLite            │ cve_cache.db ~20MB  ║
║  PoC Payloads           │ YAML files        │ payloads/*.yaml     ║
║  Scan History           │ SQLite            │ scan_history.db     ║
║  Dynamic Wordlists      │ Python + .txt     │ tech_paths/*.txt    ║
║                                                                    ║
║  New Dependencies: 4 packages, ~150MB total disk                   ║
║  Infrastructure: Zero servers, all local files                     ║
║                                                                    ║
║  Key Integration Points:                                           ║
║  1. orchestrator.py  — RAG context injection into LLM prompt       ║
║  2. prompts.py       — New rag_context parameter in prompt builder ║
║  3. machine.py       — KB initialization + history recording       ║
║  4. ingester.py      — Auto-generate tasks from CVE matches        ║
║  5. dir_buster.py    — Dynamic wordlist from tech detection        ║
║                                                                    ║
║  Expected Impact (based on AiScan-N research):                     ║
║  • Reduced false positives through CVE-validated testing           ║
║  • Technology-aware payload selection                              ║
║  • Progressive learning from scan history                          ║
║  • 3-5x larger attack surface coverage via dynamic wordlists       ║
║                                                                    ║
╚══════════════════════════════════════════════════════════════════════╝
"""
