#!/usr/bin/env python3
r"""faiss_searcher.py — FAISS HNSW approximate-nearest-neighbour search for CADRE-RevAI RAG.

Requires: faiss-cpu (or faiss-gpu)
Install:  uv pip install faiss-cpu
          # or on Remnux: pip install faiss-cpu --break-system-packages

No re-embedding needed: uses the existing bge-m3 vectors from dense_ollama.npy.

Usage:
    from faiss_searcher import FAISSSearcher
    searcher = FAISSSearcher()
    hits = searcher.search("AsyncRAT", top_k=5)

Scores are converted from L2 distance to cosine similarity so they are
comparable with the dense searcher.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

import numpy as np

RAG_ROOT = Path(os.environ.get("REVENG_RAG_ROOT", "/opt/cadre-v3-tools/rag"))
INDEX_DIR = Path(os.environ.get("REVENG_RAG_INDEX_DIR", RAG_ROOT / "index"))

DENSE_FILE = "dense_ollama.npy"
IDS_FILE = "dense_ollama.ids.json"
FAISS_FILE = "faiss_hnsw.index"


def _require_faiss():
    try:
        import faiss  # noqa: F401
        return faiss
    except ImportError as e:
        raise RuntimeError(
            "faiss is not installed. Install with: uv pip install faiss-cpu"
        ) from e


class FAISSSearcher:
    """Drop-in ANN replacement for the dense vector store.

    Build the index once with `build_index()`; subsequent loads use the saved
    FAISS HNSW index file.
    """

    def __init__(self, index_dir: Path | None = None):
        self.index_dir = index_dir or INDEX_DIR
        self.faiss = _require_faiss()

        dense_path = self.index_dir / DENSE_FILE
        ids_path = self.index_dir / IDS_FILE
        faiss_path = self.index_dir / FAISS_FILE

        if not dense_path.exists():
            raise FileNotFoundError(f"Dense vectors not found: {dense_path}")
        if not ids_path.exists():
            raise FileNotFoundError(f"ID file not found: {ids_path}")

        self.vectors = np.load(dense_path).astype("float32")
        with ids_path.open("r", encoding="utf-8") as f:
            self.ids = json.load(f)

        if faiss_path.exists():
            print(f"Loading FAISS HNSW index from {faiss_path}...")
            self.index = self.faiss.read_index(str(faiss_path))
        else:
            print(f"FAISS index not found; building HNSW index from {dense_path}...")
            self.index = self._build_index(self.vectors)
            self.faiss.write_index(self.index, str(faiss_path))
            print(f"  Saved FAISS index to {faiss_path}")

        sys.path.insert(0, str(RAG_ROOT))
        from remote_embedder import RemoteEmbedder

        self.embedder = RemoteEmbedder()
        self._documents: dict[str, dict[str, Any]] = {}
        self._load_corpus()

    def _build_index(self, vectors: np.ndarray) -> Any:
        """Build a FAISS HNSW index on L2-normalized vectors.

        Vectors are L2-normalized by bge-m3, so inner product equals cosine
        similarity. We use METRIC_INNER_PRODUCT for scores in [-1, 1].
        """
        faiss = self.faiss
        dim = vectors.shape[1]
        # HNSW parameters: 32 neighbours, efConstruction 200
        index = faiss.IndexHNSWFlat(dim, 32, faiss.METRIC_INNER_PRODUCT)
        index.hnsw.efConstruction = 200
        index.add(vectors)
        index.hnsw.efSearch = 128
        return index

    def _load_corpus(self) -> None:
        corpus_dir = RAG_ROOT / "corpus"
        for path in sorted(corpus_dir.glob("*.jsonl")):
            with path.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    doc_id = rec.get("id")
                    if doc_id:
                        self._documents[str(doc_id)] = rec

    def search(self, query: str, top_k: int = 5) -> list[Any]:
        """Search the FAISS HNSW index and return RagHit-like objects."""
        q = np.asarray(self.embedder.encode(query), dtype="float32").reshape(1, -1)
        return self.search_vec(q, top_k)

    def search_vec(self, query_vec: np.ndarray, top_k: int = 5) -> list[Any]:
        """Search the FAISS HNSW index with a pre-computed vector."""
        q = np.asarray(query_vec, dtype="float32").reshape(1, -1)
        # Inner-product index: larger score = more similar
        scores, indices = self.index.search(q, top_k)

        hits = []
        for rank, idx in enumerate(indices[0]):
            if idx < 0 or idx >= len(self.ids):
                continue
            doc_id = self.ids[idx]
            rec = self._documents.get(doc_id, {})
            score = float(scores[0][rank])
            hits.append(
                type(
                    "FAISSHit",
                    (),
                    {
                        "id": doc_id,
                        "text": rec.get("text", "")[:500],
                        "source": rec.get("source", ""),
                        "technique_id": rec.get("technique_id", ""),
                        "title": rec.get("title", "") or doc_id,
                        "score": score,
                    },
                )()
            )
        return hits

    def format_hits_for_prompt(self, hits: list[Any], max_chars: int = 4000) -> str:
        """Format hits for prompt injection (compatible with pipeline)."""
        lines = ["<rag_context>"]
        total = len("<rag_context>\n</rag_context>")
        for h in hits:
            quality = "EXCELLENT" if h.score >= 0.85 else ("GOOD" if h.score >= 0.75 else "WEAK")
            block = (
                f'  <rag_hit source="{h.source}" id="{h.id}" '
                f'technique_id="{h.technique_id}" score="{h.score:.4f}" quality="{quality}">\n'
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


def build_index(index_dir: Path | None = None) -> None:
    """CLI helper: build and save the FAISS HNSW index."""
    searcher = FAISSSearcher(index_dir=index_dir)
    print(f"Index ready: {searcher.index.ntotal} vectors, dim={searcher.vectors.shape[1]}")


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="Build FAISS HNSW index")
    ap.add_argument("--index-dir", type=Path, default=INDEX_DIR)
    args = ap.parse_args()
    build_index(args.index_dir)
