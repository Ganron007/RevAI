"""reveng_rag.py — CADRE-RevAI RAG (RAGSearcher + InMemoryVectorStore + Embedder)

STATUS: public-release build. RemoteEmbedder (FastAPI-compatible embedding service,
defaulting to localhost) is the production embedder. Fallback chain:
Remote → SentenceTransformer (MiniLM, offline) → Hash (no external deps).
See RAG-ARCHITECTURE.md (this folder) for the full design.

ARCHITECTURE: borrowed from DFIR-Nexus RAG (CADRE/tools/dfir-nexus/src/dfir_nexus/rag/)
  - RAGSearcher orchestrator
  - InMemoryVectorStore (brute-force cosine)
  - RemoteEmbedder (default, BAAI/bge-m3 via FastAPI-compatible service) OR
    SentenceTransformerEmbedder (MiniLM, offline) OR HashEmbedder (very weak)
  - JSONL corpus loader
  - 3 MCP-equivalent tools: rag_search / rag_list_sources / rag_stats

Corpus: /opt/cadre-v3-tools/rag/corpus/*.jsonl
  - malpedia.jsonl: 16,917 (BibTeX export from malpedia.caad.fkie.fraunhofer.de/library/download)
  - yara-rules.jsonl: 12,863 (Yara-Rules/rules GitHub)
  - mitre-attack.jsonl: 1,923 (STIX 2.1 from mitre/cti)
  - capa.jsonl: 1,042 (mandiant/capa-rules)
  - capec.jsonl: 615 (STIX 2.1 from mitre/cti)
  - mbc.jsonl: 243 (MBCProject/mbc-markdown)
  - aptnotes.jsonl: 5 (kbandla/APTnotes)
  - courseware.jsonl: CADRE-Courses txt/html/md extracts
  - Total: ~35K records

Usage:
  python3 reveng_rag.py --search "AsyncRAT" --top-k 5
  python3 reveng_rag.py --search "T1059.001" --top-k 3
  python3 reveng_rag.py --list-sources
  python3 reveng_rag.py --stats
  python3 reveng_rag.py --serve    # expose via stdio MCP (future)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import struct
import sys
import time
import unicodedata
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

# ===========================================================================
# Constants
# ===========================================================================
CORPUS_DIR = Path(os.environ.get("REVENG_RAG_CORPUS_DIR", "/opt/cadre-v3-tools/rag/corpus"))
# Default model: all-MiniLM-L6-v2 (22M params, 384d, fast on CPU, good enough for our corpus)
# Alternative: BAAI/bge-base-en-v1.5 (438M params, 768d, better quality but slower on CPU)
# Set via REVENG_RAG_MODEL env var or --model CLI flag
import os as _os
DEFAULT_EMBED_MODEL = _os.environ.get("REVENG_RAG_MODEL", "sentence-transformers/all-MiniLM-L6-v2")
HASH_EMBED_DIM = 384                              # HashEmbedder fallback
# Score thresholds (mirror DFIR-Nexus defaults)
EXCELLENT_THRESHOLD = 0.85
GOOD_THRESHOLD = 0.75
TOP_K_DEFAULT = 5
EMBED_BATCH_SIZE = 64                              # batch size for encoding
# MITRE T-code regex (T1234 or T1234.001)
TCODE_RE = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b")


# ===========================================================================
# Data class
# ===========================================================================
@dataclass
class RagHit:
    id: str
    text: str
    source: str
    technique_id: str = ""
    platform: str = "all"
    title: str = ""
    score: float = 0.0
    quality: str = "WEAK"      # EXCELLENT / GOOD / WEAK
    metadata: dict = field(default_factory=dict)

    def asdict(self) -> dict:
        return asdict(self)


# ===========================================================================
# Embedder (ABC + 2 impls)
# ===========================================================================
class Embedder:
    """Abstract base class for embedding models."""
    def encode(self, text: str) -> List[float]:
        raise NotImplementedError

    def encode_batch(self, texts: List[str]) -> List[List[float]]:
        """Default: per-doc encode. Override for fast batch encoding."""
        return [self.encode(t) for t in texts]

    @property
    def dim(self) -> int:
        raise NotImplementedError


class HashEmbedder(Embedder):
    """Offline, deterministic hash-based embedder. No ML deps.

    Not a real semantic embedding — uses hashing trick to project text into a
    384-dim space. Cosine similarity still works (it preserves the hash
    distribution). Use as a fallback when sentence-transformers is not installed.
    """
    def __init__(self, dim: int = HASH_EMBED_DIM):
        self._dim = dim

    @property
    def dim(self) -> int:
        return self._dim

    def encode(self, text: str) -> List[float]:
        # Normalize
        t = unicodedata.normalize("NFKD", text.lower()).encode("ascii", "ignore").decode()
        tokens = re.findall(r"[a-z0-9]{2,}", t)
        vec = [0.0] * self._dim
        for tok in tokens:
            h = int(hashlib.md5(tok.encode()).hexdigest()[:8], 16)
            idx = h % self._dim
            sign = 1.0 if (h >> 31) & 1 == 0 else -1.0
            vec[idx] += sign
        # L2 normalize
        norm = sum(x * x for x in vec) ** 0.5
        if norm > 0:
            vec = [x / norm for x in vec]
        return vec


class SentenceTransformerEmbedder(Embedder):
    """Real semantic embedder using sentence-transformers.

    Default model: sentence-transformers/all-MiniLM-L6-v2 (22M params, 384d, fast on CPU)
    Alternative: BAAI/bge-base-en-v1.5 (438M params, 768d, slower on CPU)
    Requires: pip install sentence-transformers
    """
    def __init__(self, model_name: str = DEFAULT_EMBED_MODEL):
        from sentence_transformers import SentenceTransformer
        self._model = SentenceTransformer(model_name)
        self._dim = self._model.get_sentence_embedding_dimension()

    @property
    def dim(self) -> int:
        return self._dim

    def encode(self, text: str) -> List[float]:
        v = self._model.encode(text, convert_to_numpy=True)
        return v.tolist() if hasattr(v, "tolist") else list(v)

    def encode_batch(self, texts: List[str], batch_size: int = EMBED_BATCH_SIZE) -> List[List[float]]:
        # sentence-transformers handles batching internally
        vecs = self._model.encode(texts, batch_size=batch_size, convert_to_numpy=True, show_progress_bar=False)
        return [v.tolist() for v in vecs]


# ===========================================================================
# Vector store (ABC + 1 in-memory impl)
# ===========================================================================
class VectorStore:
    """Abstract base class for vector stores."""
    def add(self, ids: List[str], vectors: List[List[float]], metadatas: List[dict]) -> None:
        raise NotImplementedError

    def search(self, query_vector: List[float], top_k: int = 5) -> List[Tuple[str, float]]:
        raise NotImplementedError


class InMemoryVectorStore(VectorStore):
    """Brute-force cosine similarity. Default in DFIR-Nexus.

    Fast for ~50K records (33K will be sub-100ms). No persistence.
    For larger corpora, use ChromaVectorStore (DFIR-Nexus also ships one).
    """
    def __init__(self):
        import numpy as _np
        self._ids: List[str] = []
        self._vectors = None  # numpy 2D array (n, dim), populated lazily
        self._metadatas: List[dict] = []
        self._np = _np

    def add(self, ids, vectors, metadatas):
        import numpy as _np
        self._ids.extend(ids)
        # Accept either list-of-lists or numpy 2D array; store as numpy for fast cosine
        if self._vectors is None:
            self._vectors = _np.asarray(vectors, dtype=_np.float32)
        else:
            self._vectors = _np.vstack([self._vectors, _np.asarray(vectors, dtype=_np.float32)])
        self._metadatas.extend(metadatas)

    def search(self, query_vector, top_k=5):
        import numpy as _np
        if self._vectors is None or len(self._ids) == 0:
            return []
        # Vectorized cosine (vectors are L2-normalized so dot product = cosine)
        q = _np.asarray(query_vector, dtype=_np.float32)
        scores = self._vectors @ q  # (n,) — single matmul, no Python loop
        # Argsort descending, take top_k
        top_idx = _np.argsort(-scores)[:top_k]
        return [(self._ids[i], float(scores[i])) for i in top_idx]

    def metadata_for(self, doc_id: str) -> Optional[dict]:
        for i, d in enumerate(self._ids):
            if d == doc_id:
                return self._metadatas[i]
        return None

    def __len__(self):
        return len(self._ids)


# ===========================================================================
# Document loader (JSONL)
# ===========================================================================
def load_documents(corpus_dir: Path) -> List[dict]:
    """Load all *.jsonl files from corpus_dir. Returns list of documents (dict)."""
    docs = []
    for jsonl in sorted(corpus_dir.glob("*.jsonl")):
        with jsonl.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    doc = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if "id" not in doc or "text" not in doc:
                    continue
                docs.append(doc)
    return docs


# ===========================================================================
# RAG Searcher (orchestrator)
# ===========================================================================
class RAGSearcher:
    """Main entry point. Borrowed from DFIR-Nexus RAGSearcher shape."""

    def __init__(self, embedder: Embedder = None, corpus_dir: Path = CORPUS_DIR):
        self.embedder = embedder or HashEmbedder()  # safe default
        self.corpus_dir = corpus_dir
        self.store = InMemoryVectorStore()
        self._documents: dict = {}   # id -> doc
        self._indexed = False

    def _try_load_index(self) -> bool:
        """Try to load a pre-computed index from disk (saves re-embedding).

        Returns True if loaded successfully, False if no index found or dim mismatch.
        Vectors are kept as numpy 2D array (no .tolist() → no 35M-float slowdown).
        """
        index_dir = self.corpus_dir.parent / "index"
        if not index_dir.exists():
            return False
        embed_name = type(self.embedder).__name__.lower().replace("embedder", "")
        candidates = [
            index_dir / f"dense_{embed_name}.npy",
            index_dir / "dense_tei.npy",          # legacy name from reindex_with_tei.py
            index_dir / "dense.npy",              # legacy name
        ]
        ids_candidates = [
            index_dir / f"dense_{embed_name}.ids.json",
            index_dir / "dense_tei.ids.json",
            index_dir / "dense.ids.json",
        ]
        dense_file = next((p for p in candidates if p.exists()), None)
        ids_file = next((p for p in ids_candidates if p.exists()), None)
        if not dense_file or not ids_file:
            return False
        try:
            import numpy as np
            import json as _json
            vectors = np.load(dense_file)
            with ids_file.open(encoding="utf-8") as f:
                ids = _json.load(f)
            if vectors.shape[0] != len(ids):
                print(f"  WARNING: index size mismatch ({vectors.shape[0]} vs {len(ids)} ids) — will re-embed")
                return False
            if vectors.shape[1] != self.embedder.dim:
                print(f"  WARNING: index dim mismatch ({vectors.shape[1]} vs embedder dim {self.embedder.dim}) — will re-embed")
                return False
            metadatas = [{"id": _id, "source": "unknown"} for _id in ids]
            self.store.add(ids, vectors, metadatas)  # store keeps as numpy
            docs = load_documents(self.corpus_dir)
            for d in docs:
                self._documents[d["id"]] = d
            self._indexed = True
            print(f"  Loaded {len(ids)} pre-computed vectors from {dense_file.name} (dim={vectors.shape[1]})")
            return True
        except Exception as e:
            print(f"  WARNING: failed to load pre-computed index: {e}")
            return False

    def index(self) -> None:
        """Load all JSONL docs from corpus_dir, embed (in batches), add to store."""
        if self._indexed:
            return
        # Try pre-computed index first (saves 13+ min re-embed)
        if self._try_load_index():
            return
        t0 = time.time()
        docs = load_documents(self.corpus_dir)
        if not docs:
            raise RuntimeError(f"No documents found in {self.corpus_dir}")
        ids = [d["id"] for d in docs]
        texts = [d["text"] for d in docs]
        # BATCH encoding (much faster than per-doc on CPU)
        if hasattr(self.embedder, "encode_batch"):
            vectors = self.embedder.encode_batch(texts)
        else:
            vectors = [self.embedder.encode(t) for t in texts]
        metadatas = [d for d in docs]
        self.store.add(ids, vectors, metadatas)
        for d in docs:
            self._documents[d["id"]] = d
        self._indexed = True
        elapsed = time.time() - t0
        print(f"  Indexed {len(docs)} documents in {elapsed:.1f}s (embedder={type(self.embedder).__name__}, dim={self.embedder.dim})")

    def search(self, query: str, top_k: int = TOP_K_DEFAULT,
               source: Optional[str] = None,
               technique: Optional[str] = None) -> List[RagHit]:
        """Top-k semantic search over the corpus.

        Args:
          query: free-text query (e.g. "AsyncRAT trojan C2", "T1059.001", "Mimikatz credential dump")
          top_k: number of hits to return
          source: filter by source (e.g. "malpedia", "yara-rules", "mitre-attack")
          technique: filter by MITRE technique ID (e.g. "T1059.001")
        """
        if not self._indexed:
            self.index()
        # Extract MITRE T-codes from the query (e.g. "T1059.001" or "T1059")
        t_codes = TCODE_RE.findall(query)
        # Also match the technique filter if explicitly passed
        if technique:
            t_codes = [technique] + t_codes
        # Encode the query
        query_vec = self.embedder.encode(query)
        scored = self.store.search(query_vec, top_k=top_k * 3)  # over-fetch for filter+boost
        # Build (doc_id, base_score) list
        scored_dict = {doc_id: score for doc_id, score in scored}
        # T-code boost: any doc whose technique_id matches a T-code from the query gets +0.15
        for doc_id, doc in self._documents.items():
            tid = doc.get("technique_id", "")
            for tc in t_codes:
                if tid == tc or (tid and tid.startswith(tc.split(".")[0])):
                    scored_dict[doc_id] = scored_dict.get(doc_id, 0.0) + 0.15
                    break
            # Also check metadata.technique_ids list
            if doc_id not in scored_dict or scored_dict[doc_id] < 0.15:
                tids = doc.get("metadata", {}).get("technique_ids", [])
                for tc in t_codes:
                    if tc in tids or any(t.startswith(tc.split(".")[0]) for t in tids if t):
                        scored_dict[doc_id] = scored_dict.get(doc_id, 0.0) + 0.15
                        break
        # Re-sort by score
        sorted_hits = sorted(scored_dict.items(), key=lambda x: -x[1])
        hits = []
        for doc_id, score in sorted_hits:
            doc = self._documents.get(doc_id)
            if not doc:
                continue
            # Apply filters
            if source and doc.get("source") != source:
                continue
            if technique and doc.get("technique_id") != technique:
                tids = doc.get("metadata", {}).get("technique_ids", [])
                if technique not in tids and technique != doc.get("technique_id"):
                    continue
            quality = "EXCELLENT" if score >= EXCELLENT_THRESHOLD else \
                      "GOOD"      if score >= GOOD_THRESHOLD      else "WEAK"
            hits.append(RagHit(
                id=doc["id"],
                text=doc.get("text", ""),
                source=doc.get("source", ""),
                technique_id=doc.get("technique_id", ""),
                platform=doc.get("platform", "all"),
                title=doc.get("title", ""),
                score=round(float(score), 4),
                quality=quality,
                metadata=doc.get("metadata", {}),
            ))
            if len(hits) >= top_k:
                break
        return hits

    def list_sources(self) -> dict:
        """List all sources in the corpus with counts."""
        if not self._indexed:
            self.index()
        counts = Counter()
        for d in self._documents.values():
            counts[d.get("source", "unknown")] += 1
        return dict(counts)

    def stats(self) -> dict:
        """RAG statistics."""
        if not self._indexed:
            self.index()
        sources = self.list_sources()
        return {
            "document_count": len(self._documents),
            "indexed_sources": sorted(sources.keys()),
            "source_counts": sources,
            "embed_model": type(self.embedder).__name__,
            "embed_dim": self.embedder.dim,
            "score_thresholds": {
                "EXCELLENT": EXCELLENT_THRESHOLD,
                "GOOD": GOOD_THRESHOLD,
            },
        }

    def format_hits_for_prompt(self, hits: List[RagHit], max_chars: int = 4000) -> str:
        """Format hits as a context block to inject into the LLM prompt.

        Output format (compatible with quick_scan_v2.py::llm_judge augmentation):
            <rag_context source="malpedia" id="malpedia:foo">
                text...
            </rag_context>
            ...
        """
        lines = ["<rag_context>"]
        total = len("<rag_context>\n</rag_context>")
        for h in hits:
            block = (
                f'  <rag_hit source="{h.source}" id="{h.id}" '
                f'technique_id="{h.technique_id}" score="{h.score}" quality="{h.quality}">\n'
                f'    <title>{h.title}</title>\n'
                f'    <text>{h.text}</text>\n'
                f'  </rag_hit>'
            )
            if total + len(block) + 2 > max_chars:
                break
            lines.append(block)
            total += len(block) + 2
        lines.append("</rag_context>")
        return "\n".join(lines)


# ===========================================================================
# Convenience: a global searcher for CLI use
# ===========================================================================
_searcher = None
def get_searcher() -> RAGSearcher:
    """Get or create the global RAG searcher using the unified RemoteEmbedder."""
    global _searcher
    if _searcher is not None:
        return _searcher
    try:
        from remote_embedder import RemoteEmbedder
        embedder = RemoteEmbedder()
    except Exception as e:
        raise RuntimeError(
            f"RAG embedder failed: {e}\n"
            f"Start the embedding/reranker host service and set REVENG_REMOTE_EMBED_URL."
        ) from e
    _searcher = RAGSearcher(embedder=embedder)  # type: ignore[arg-type]
    _searcher.index()
    return _searcher


# ===========================================================================
# CLI
# ===========================================================================
def main() -> int:
    ap = argparse.ArgumentParser(description="CADRE-RevAI RAG - search across public RE knowledge")
    ap.add_argument("--search", help="Search query (e.g. 'AsyncRAT trojan C2')")
    ap.add_argument("--top-k", type=int, default=TOP_K_DEFAULT, help=f"Number of hits (default {TOP_K_DEFAULT})")
    ap.add_argument("--source", help="Filter by source (malpedia, yara-rules, etc.)")
    ap.add_argument("--technique", help="Filter by MITRE technique ID (T1059.001)")
    ap.add_argument("--list-sources", action="store_true", help="List all sources + counts")
    ap.add_argument("--stats", action="store_true", help="Show RAG statistics")
    ap.add_argument("--serve", action="store_true", help="Start stdio MCP server (future)")
    args = ap.parse_args()

    if args.list_sources:
        s = get_searcher()
        counts = s.list_sources()
        print("Sources in corpus:")
        for src, cnt in sorted(counts.items(), key=lambda x: -x[1]):
            print(f"  {src:20s}  {cnt:6d} docs")
        return 0

    if args.stats:
        s = get_searcher()
        print(json.dumps(s.stats(), indent=2))
        return 0

    if args.search:
        s = get_searcher()
        hits = s.search(args.search, top_k=args.top_k, source=args.source, technique=args.technique)
        print(f"Top {len(hits)} hits for '{args.search}':\n")
        for i, h in enumerate(hits, 1):
            print(f"--- [{i}] {h.id} (score={h.score}, quality={h.quality}) ---")
            print(f"  source:      {h.source}")
            print(f"  technique:   {h.technique_id or '(none)'}")
            print(f"  title:       {h.title[:100]}")
            print(f"  text:        {h.text[:300]}...")
            print()
        return 0

    ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
