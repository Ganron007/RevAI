#!/usr/bin/env python3
"""rag_hybrid.py — Hybrid RAG search (dense + BM25 + RRF) for CADRE-RevAI.

Uses the existing Ollama/bge-m3 dense index and a BM25Okapi sparse index.
No index rebuild needed; both indexes are read-only at query time.

Usage:
    from rag_hybrid import HybridSearcher
    searcher = HybridSearcher()
    hits = searcher.search("AsyncRAT C2 beacon", top_k=5)
"""
from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

import numpy as np

sys.path.insert(0, str(Path(__file__).parent))

from remote_embedder import RemoteEmbedder

DEFAULT_INDEX_DIR = Path("/opt/cadre-v3-tools/rag/index")
DEFAULT_CORPUS_DIR = Path("/opt/cadre-v3-tools/rag/corpus")
DENSE_FILE = "dense_ollama.npy"
IDS_FILE = "dense_ollama.ids.json"
BM25_FILE = "bm25_ollama.pkl"
FAISS_FILE = "faiss_hnsw.index"

TCODE_RE = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b")
RRF_K = 60  # common RRF constant


@dataclass
class HybridHit:
    id: str
    text: str
    source: str
    technique_id: str
    platform: str
    title: str
    dense_score: float
    bm25_score: float
    rrf_score: float
    metadata: dict[str, Any]


class HybridSearcher:
    """Hybrid RAG search (dense + BM25 + RRF) with optional ANN + optional reranker."""

    def __init__(
        self,
        index_dir: Path | None = None,
        corpus_dir: Path | None = None,
        use_ann: bool | None = None,
        use_reranker: bool | None = None,
    ):
        self.index_dir = index_dir or DEFAULT_INDEX_DIR
        self.corpus_dir = corpus_dir or DEFAULT_CORPUS_DIR
        self.use_ann = use_ann if use_ann is not None else os.environ.get("REVENG_RAG_ANN", "0") == "1"
        self.use_reranker = use_reranker if use_reranker is not None else bool(os.environ.get("REVENG_RERANKER_URL"))

        # Load dense index
        dense_path = self.index_dir / DENSE_FILE
        ids_path = self.index_dir / IDS_FILE
        bm25_path = self.index_dir / BM25_FILE

        if not dense_path.exists():
            raise FileNotFoundError(f"Dense index not found: {dense_path}")
        if not ids_path.exists():
            raise FileNotFoundError(f"ID file not found: {ids_path}")
        if not bm25_path.exists():
            raise FileNotFoundError(
                f"BM25 index not found: {bm25_path}\n"
                "Build it with: python3 bm25_index.py"
            )

        print(f"Loading dense index from {dense_path}...")
        self.vectors = np.load(dense_path)
        with ids_path.open("r", encoding="utf-8") as f:
            self.ids = json.load(f)
        self.id_to_idx = {doc_id: i for i, doc_id in enumerate(self.ids)}
        print(f"  {len(self.ids)} vectors, dim={self.vectors.shape[1]}")

        print(f"Loading BM25 index from {bm25_path}...")
        from bm25_index import load_bm25

        self.bm25_index = load_bm25(bm25_path)
        self.bm25 = self.bm25_index["bm25"]
        self.bm25_doc_ids = self.bm25_index["doc_ids"]
        self.bm25_id_to_idx = {doc_id: i for i, doc_id in enumerate(self.bm25_doc_ids)}
        print(f"  {len(self.bm25_doc_ids)} BM25 documents")

        # Build doc_id -> corpus record map
        self._documents: dict[str, dict[str, Any]] = {}
        self._load_corpus()

        # Remote FastAPI embedder (default: localhost; can be a separate GPU host)
        self.embedder = RemoteEmbedder()
        self.backend = "remote"
        print(f"  Embedder ready ({self.backend}): {self.embedder}")

        # Optional ANN retriever
        self.ann_searcher = None
        if self.use_ann:
            self._load_ann()

        # Optional cross-encoder reranker
        self.reranker = None
        if self.use_reranker:
            self._load_reranker()

    def _load_ann(self) -> None:
        try:
            from faiss_searcher import FAISSSearcher
            self.ann_searcher = FAISSSearcher(index_dir=self.index_dir)
            print(f"  ANN (FAISS) ready: {self.ann_searcher.index.ntotal} vectors")
        except Exception as e:
            print(f"  WARNING: could not load ANN (FAISS) index: {e}")
            self.use_ann = False
            self.ann_searcher = None

    def _load_reranker(self) -> None:
        try:
            from reranker import Reranker
            self.reranker = Reranker()
            print(f"  Reranker ready: {self.reranker}")
        except Exception as e:
            print(f"  WARNING: could not load reranker: {e}")
            self.use_reranker = False
            self.reranker = None

    def _load_corpus(self) -> None:
        for path in sorted(self.corpus_dir.glob("*.jsonl")):
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

    def _dense_search(self, query_vec: list[float], top_k: int) -> list[tuple[str, float]]:
        """Return top-k (doc_id, cosine_score) from dense index."""
        q = np.asarray(query_vec, dtype=np.float32)
        # vectors are already L2-normalized in bge-m3 output
        scores = self.vectors @ q  # (n,)
        top_idx = np.argsort(-scores)[:top_k]
        return [(self.ids[i], float(scores[i])) for i in top_idx]

    def _bm25_search(self, query: str, top_k: int) -> list[tuple[str, float]]:
        """Return top-k (doc_id, bm25_score) from BM25 index."""
        from bm25_index import tokenize

        tokenized_query = tokenize(query)
        scores = self.bm25.get_scores(tokenized_query)
        top_idx = np.argsort(-scores)[:top_k]
        return [(self.bm25_doc_ids[i], float(scores[i])) for i in top_idx]

    def _rrf_fuse(
        self,
        dense_ranking: list[tuple[str, float]],
        bm25_ranking: list[tuple[str, float]],
    ) -> dict[str, float]:
        """Fuse two rankings with Reciprocal Rank Fusion."""
        rrf: dict[str, float] = {}
        for rank, (doc_id, _) in enumerate(dense_ranking, start=1):
            rrf[doc_id] = rrf.get(doc_id, 0.0) + 1.0 / (RRF_K + rank)
        for rank, (doc_id, _) in enumerate(bm25_ranking, start=1):
            rrf[doc_id] = rrf.get(doc_id, 0.0) + 1.0 / (RRF_K + rank)
        return rrf

    def _t_code_boost(self, query: str, rrf_scores: dict[str, float]) -> dict[str, float]:
        """Boost documents matching MITRE T-codes from the query."""
        t_codes = TCODE_RE.findall(query)
        if not t_codes:
            return rrf_scores
        boosted = dict(rrf_scores)
        for doc_id, rec in self._documents.items():
            if doc_id not in boosted:
                continue
            tid = rec.get("technique_id", "")
            tids = rec.get("metadata", {}).get("technique_ids", [])
            for tc in t_codes:
                if tid == tc or tid.startswith(tc.split(".")[0]):
                    boosted[doc_id] += 0.15
                    break
                if any(t == tc or (t and t.startswith(tc.split(".")[0])) for t in tids):
                    boosted[doc_id] += 0.15
                    break
        return boosted

    def _ann_search(self, query_vec: list[float], top_k: int) -> list[tuple[str, float]]:
        """Return top-k (doc_id, cosine_score) from FAISS HNSW index."""
        if not self.ann_searcher:
            return []
        hits = self.ann_searcher.search_vec(np.asarray(query_vec), top_k)
        return [(h.id, float(h.score)) for h in hits]

    def _rerank_results(self, query: str, candidates: list[HybridHit], top_k: int) -> list[HybridHit]:
        """Rerank candidates with the cross-encoder and return top-k."""
        if not self.reranker or not candidates:
            return candidates[:top_k]
        reranked = self.reranker.rerank(query, candidates, top_k=top_k)
        # Convert reranked hits back to HybridHit if possible
        out: list[HybridHit] = []
        for h in reranked:
            if isinstance(h, HybridHit):
                out.append(h)
                continue
            out.append(HybridHit(
                id=h.id,
                text=h.text,
                source=h.source,
                technique_id=h.technique_id,
                platform="all",
                title=h.title,
                dense_score=getattr(h, "dense_score", 0.0),
                bm25_score=getattr(h, "bm25_score", 0.0),
                rrf_score=getattr(h, "rrf_score", getattr(h, "score", 0.0)),
                metadata=getattr(h, "metadata", {}),
            ))
        return out

    def search(
        self,
        query: str,
        top_k: int = 5,
        *,
        retrieve_k: int = 50,
        source: str | None = None,
        technique: str | None = None,
    ) -> list[HybridHit]:
        """Hybrid search: dense/ANN + BM25 + RRF + T-code boost + optional reranker + filters."""
        # Embed query once
        query_vec = self.embedder.encode(query)

        # Retrieve from dense/ANN and BM25
        if self.use_ann and self.ann_searcher:
            ann_k = max(retrieve_k * 3, top_k * 4)
            dense_ranking = self._ann_search(query_vec, ann_k)
        else:
            dense_ranking = self._dense_search(query_vec, retrieve_k)
        bm25_ranking = self._bm25_search(query, retrieve_k)

        # Fuse
        rrf_scores = self._rrf_fuse(dense_ranking, bm25_ranking)
        rrf_scores = self._t_code_boost(query, rrf_scores)

        # Build score lookups
        dense_lookup = dict(dense_ranking)
        bm25_lookup = dict(bm25_ranking)

        # Filter and sort
        candidates: list[HybridHit] = []
        for doc_id, score in rrf_scores.items():
            rec = self._documents.get(doc_id)
            if not rec:
                continue
            if source and rec.get("source") != source:
                continue
            if technique:
                tid = rec.get("technique_id", "")
                tids = rec.get("metadata", {}).get("technique_ids", [])
                if technique != tid and technique not in tids:
                    continue
            candidates.append(
                HybridHit(
                    id=doc_id,
                    text=rec.get("text", "")[:500],
                    source=rec.get("source", ""),
                    technique_id=rec.get("technique_id", ""),
                    platform=rec.get("platform", "all"),
                    title=rec.get("title", "") or doc_id,
                    dense_score=dense_lookup.get(doc_id, 0.0),
                    bm25_score=bm25_lookup.get(doc_id, 0.0),
                    rrf_score=score,
                    metadata=rec.get("metadata", {}),
                )
            )

        candidates.sort(key=lambda h: h.rrf_score, reverse=True)

        # Optional reranker pass
        if self.use_reranker and self.reranker:
            rerank_pool_size = max(top_k * 3, retrieve_k)
            return self._rerank_results(query, candidates, top_k)

        return candidates[:top_k]

    def format_hits_for_prompt(self, hits: list[HybridHit], max_chars: int = 4000) -> str:
        """Format hits as a context block to inject into the LLM prompt.

        Output format (compatible with quick_scan_v2.py augmentation):
            <rag_context>
              <rag_hit source="malpedia" id="malpedia:foo" technique_id="T1059.001"
                        score="0.95" quality="GOOD">
                <title>...</title>
                <text>...</text>
              </rag_hit>
            </rag_context>
        """
        lines = ["<rag_context>"]
        total = len("<rag_context>\n</rag_context>")
        for h in hits:
            quality = "EXCELLENT" if h.rrf_score >= 0.40 else ("GOOD" if h.rrf_score >= 0.25 else "WEAK")
            block = (
                f'  <rag_hit source="{h.source}" id="{h.id}" '
                f'technique_id="{h.technique_id}" score="{h.rrf_score:.4f}" quality="{quality}">\n'
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


def main() -> int:
    import argparse

    ap = argparse.ArgumentParser(description="Hybrid RAG search (dense + BM25 + RRF)")
    ap.add_argument("query", help="Search query")
    ap.add_argument("--top-k", type=int, default=5)
    ap.add_argument("--retrieve-k", type=int, default=50)
    ap.add_argument("--source", default=None)
    ap.add_argument("--technique", default=None)
    args = ap.parse_args()

    searcher = HybridSearcher()
    hits = searcher.search(
        args.query,
        top_k=args.top_k,
        retrieve_k=args.retrieve_k,
        source=args.source,
        technique=args.technique,
    )
    print(f"Top {len(hits)} hits for '{args.query}':\n")
    for i, h in enumerate(hits, 1):
        print(f"--- [{i}] {h.id} ---")
        print(f"  source:      {h.source}")
        print(f"  technique:   {h.technique_id or '(none)'}")
        print(f"  rrf_score:   {h.rrf_score:.4f}")
        print(f"  dense_score: {h.dense_score:.4f}")
        print(f"  bm25_score:  {h.bm25_score:.4f}")
        print(f"  title:       {h.title[:100]}")
        print(f"  text:        {h.text[:300]}...")
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
