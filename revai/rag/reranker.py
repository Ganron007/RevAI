#!/usr/bin/env python3
"""reranker.py — Cross-encoder reranker for CADRE-RevAI RAG.

Two modes:
  1. Local (default): loads `BAAI/bge-reranker-v2-m3` on Remnux CPU/RAM.
  2. Remote: calls the FastAPI reranker service running on a GPU host.

Usage:
    from reranker import Reranker
    from rag_hybrid import HybridSearcher

    searcher = HybridSearcher()
    reranker = Reranker()
    hits = searcher.search("AsyncRAT", top_k=50)
    reranked = reranker.rerank("AsyncRAT", hits, top_k=5)

Env:
  REVENG_RERANKER_URL      default: unset (local mode)
                           Set to e.g. http://<host>:8000 to use a remote GPU/CPU service.
  REVENG_RERANKER_MODEL    default: BAAI/bge-reranker-v2-m3
"""
from __future__ import annotations

import os
from typing import Any

DEFAULT_RERANKER_URL = os.environ.get("REVENG_RERANKER_URL")
DEFAULT_RERANKER_MODEL = os.environ.get(
    "REVENG_RERANKER_MODEL", "BAAI/bge-reranker-v2-m3"
)


class Reranker:
    """Cross-encoder reranker. Local or remote GPU via FastAPI service."""

    def __init__(self, model_name: str | None = None, base_url: str | None = None):
        self.model_name = model_name or DEFAULT_RERANKER_MODEL
        self.base_url = base_url or DEFAULT_RERANKER_URL

        if self.base_url:
            from reranker_client import RerankerClient

            self.client = RerankerClient(base_url=self.base_url)
            print(f"Reranker remote mode: {self.client}")
        else:
            self.client = None
            try:
                from sentence_transformers import CrossEncoder
            except ImportError as e:
                raise RuntimeError(
                    "sentence-transformers is not installed. "
                    "Install with: pip install sentence-transformers"
                ) from e
            print(f"Loading reranker model {self.model_name} locally...")
            self.model = CrossEncoder(self.model_name)
            print("  Reranker ready")

    def rerank(
        self,
        query: str,
        hits: list[Any],
        top_k: int = 5,
        max_input_length: int = 512,
    ) -> list[Any]:
        """Score and re-sort hits by cross-encoder relevance."""
        if not hits:
            return []

        if self.client is not None:
            return self._rerank_remote(query, hits, top_k, max_input_length)
        return self._rerank_local(query, hits, top_k, max_input_length)

    def _rerank_remote(
        self,
        query: str,
        hits: list[Any],
        top_k: int,
        max_input_length: int,
    ) -> list[Any]:
        texts = [(h.text or "")[:max_input_length] for h in hits]
        result = self.client.rerank(query, texts, top_k=top_k)
        indices = result.get("indices", [])
        scores = result.get("scores", [])

        reranked = []
        for idx, score in zip(indices, scores):
            if idx < 0 or idx >= len(hits):
                continue
            h = hits[idx]
            reranked.append(self._wrap_hit(h, float(score)))
        return reranked

    def _rerank_local(
        self,
        query: str,
        hits: list[Any],
        top_k: int,
        max_input_length: int,
    ) -> list[Any]:
        pairs = [(query, (h.text or "")[:max_input_length]) for h in hits]
        scores = self.model.predict(pairs)

        scored = sorted(zip(hits, scores), key=lambda x: x[1], reverse=True)
        reranked = []
        for h, score in scored[:top_k]:
            reranked.append(self._wrap_hit(h, float(score)))
        return reranked

    def _wrap_hit(self, h: Any, score: float) -> Any:
        return type(
            "RerankedHit",
            (),
            {
                "id": h.id,
                "text": h.text,
                "source": h.source,
                "technique_id": h.technique_id,
                "title": h.title,
                "original_score": getattr(h, "score", getattr(h, "rrf_score", 0.0)),
                "reranker_score": score,
                "score": score,
                "rrf_score": score,
                "metadata": getattr(h, "metadata", {}),
            },
        )()

    def format_hits_for_prompt(self, hits: list[Any], max_chars: int = 4000) -> str:
        """Format reranked hits for prompt injection."""
        lines = ["<rag_context>"]
        total = len("<rag_context>\n</rag_context>")
        for h in hits:
            score = getattr(h, "reranker_score", getattr(h, "score", 0.0))
            quality = "EXCELLENT" if score >= 0.5 else ("GOOD" if score >= 0.0 else "WEAK")
            block = (
                f'  <rag_hit source="{h.source}" id="{h.id}" '
                f'technique_id="{h.technique_id}" score="{score:.4f}" quality="{quality}">\n'
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


if __name__ == "__main__":
    import sys

    # Smoke test: requires a searcher and a query
    print("reranker.py: import OK. Set REVENG_RERANKER_URL to use remote GPU.")
    sys.exit(0)
