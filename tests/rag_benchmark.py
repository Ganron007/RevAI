#!/usr/bin/env python3
"""rag_benchmark.py — A/B benchmark for CADRE-RevAI RAG retrieval backends.

Backends implemented:
  - dense    : reveng_rag.RAGSearcher (brute-force cosine on bge-m3)
  - hybrid   : rag_hybrid.HybridSearcher (BM25 + dense + RRF + T-code boost)

Backends planned (stubbed so the harness already supports them):
  - ann      : FAISS HNSW approximate nearest neighbours (to be implemented)
  - reranker : hybrid + cross-encoder reranker (to be implemented)

Usage:
  # Built-in query suite
  python3 rag_benchmark.py --backends dense,hybrid --top-k 5 --output report.json

  # Custom queries
  python3 rag_benchmark.py --backends dense,hybrid \
      --queries "AsyncRAT C2" "Emotet banking trojan" "T1059.001 PowerShell"

  # From a JSONL file
  python3 rag_benchmark.py --backends dense,hybrid --queries-file queries.jsonl

  # With hybrid on/off in the v3 pipeline context
  export REVENG_RAG=1
  python3 rag_benchmark.py --backends dense,hybrid

Environment:
  REVENG_RAG_BACKEND      default: remote
  REVENG_REMOTE_EMBED_URL default: http://localhost:8000
  REVENG_RERANKER_URL     default: http://localhost:8000
  REVENG_EMBED_MODEL      default: BAAI/bge-m3
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Callable

RAG_ROOT = Path(os.environ.get("REVENG_RAG_ROOT", "/opt/cadre-v3-tools/rag"))
if str(RAG_ROOT) not in sys.path:
    sys.path.insert(0, str(RAG_ROOT))

os.environ.setdefault("REVENG_RAG_BACKEND", "remote")
os.environ.setdefault("REVENG_REMOTE_EMBED_URL", "http://localhost:8000")
os.environ.setdefault("REVENG_RERANKER_URL", "http://localhost:8000")
os.environ.setdefault("REVENG_EMBED_MODEL", "BAAI/bge-m3")

DEFAULT_QUERIES = [
    "AsyncRAT C2 beacon",
    "Emotet banking trojan",
    "Cobalt Strike Malleable C2",
    "T1059.001 PowerShell execution",
    "T1003 LSASS credential dumping",
    "process hollowing injection",
    "SekurLsa LogonPasswords",
    "GodPotato privilege escalation",
    "MiniDumpWriteDump LSASS",
    "delete shadow copies vssadmin",
]


def _indexes_available() -> bool:
    index_dir = Path(os.environ.get("REVENG_RAG_INDEX_DIR", RAG_ROOT / "index"))
    return (
        (index_dir / "dense_ollama.npy").exists()
        and (index_dir / "dense_ollama.ids.json").exists()
    )


def _load_queries(args: argparse.Namespace) -> list[str]:
    if args.queries_file:
        queries = []
        with open(args.queries_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                    q = rec.get("query") or rec.get("text", "")
                except json.JSONDecodeError:
                    q = line
                if q:
                    queries.append(str(q))
        return queries
    if args.queries:
        return list(args.queries)
    return DEFAULT_QUERIES


# ---------------------------------------------------------------------------
# Backend factory registry
# ---------------------------------------------------------------------------
BackendFactory = Callable[[], Any]

_BACKEND_FACTORIES: dict[str, BackendFactory] = {}


def register_backend(name: str, factory: BackendFactory) -> None:
    _BACKEND_FACTORIES[name] = factory


def _backend_dense():
    import reveng_rag

    return reveng_rag.get_searcher()


def _backend_hybrid():
    from rag_hybrid import HybridSearcher

    return HybridSearcher()


def _backend_ann():
    from faiss_searcher import FAISSSearcher

    return FAISSSearcher()


def _backend_reranker():
    from reranker import Reranker
    from rag_hybrid import HybridSearcher

    class _RerankerBackend:
        def __init__(self):
            self.searcher = HybridSearcher()
            self.reranker = Reranker()

        def search(self, query: str, top_k: int = 5) -> list[Any]:
            # Retrieve more candidates so the reranker has a meaningful pool
            candidates = self.searcher.search(query, top_k=max(top_k * 10, 50))
            return self.reranker.rerank(query, candidates, top_k=top_k)

        def format_hits_for_prompt(self, hits: list[Any], max_chars: int = 4000) -> str:
            return self.reranker.format_hits_for_prompt(hits, max_chars=max_chars)

    return _RerankerBackend()


register_backend("dense", _backend_dense)
register_backend("hybrid", _backend_hybrid)
register_backend("ann", _backend_ann)
register_backend("reranker", _backend_reranker)


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------
class Metrics:
    def __init__(self, query: str, hits: list[Any], latency_ms: float):
        self.query = query
        self.hits = hits
        self.latency_ms = latency_ms

    def to_dict(self) -> dict[str, Any]:
        sources = list({h.source for h in self.hits})
        tids = list({h.technique_id for h in self.hits if h.technique_id})
        raw_scores = [float(getattr(h, "score", getattr(h, "rrf_score", 0.0))) for h in self.hits]
        norm_scores = self._min_max_norm(raw_scores)
        texts = " ".join(h.text.lower() for h in self.hits)
        all_text = " ".join(h.text.lower() for h in self.hits)

        return {
            "query": self.query,
            "latency_ms": round(self.latency_ms, 2),
            "num_hits": len(self.hits),
            "sources": sources,
            "num_sources": len(sources),
            "technique_ids": tids,
            "raw_scores": [round(s, 4) for s in raw_scores],
            "normalized_scores": [round(s, 4) for s in norm_scores],
            "top_score": round(raw_scores[0], 4) if raw_scores else 0.0,
            "top_normalized_score": round(norm_scores[0], 4) if norm_scores else 0.0,
            "avg_score": round(sum(raw_scores) / len(raw_scores), 4) if raw_scores else 0.0,
            "has_token_match": self._has_token_match(all_text),
            "has_exact_phrase_match": self._has_exact_phrase_match(all_text),
            "hit_ids": [h.id for h in self.hits],
            "hit_titles": [h.title[:80] for h in self.hits],
        }

    def _has_token_match(self, texts: str) -> bool:
        """Rough proxy: do any query tokens appear verbatim in retrieved text?"""
        query_tokens = [t for t in self.query.lower().split() if len(t) > 3]
        if not query_tokens:
            return False
        return any(tok in texts for tok in query_tokens)

    def _has_exact_phrase_match(self, texts: str) -> bool:
        """Does the full query phrase (minus punctuation) appear verbatim?"""
        phrase = self.query.lower().strip()
        return phrase in texts

    def _min_max_norm(self, scores: list[float]) -> list[float]:
        if not scores or len(scores) == 1:
            return [1.0] * len(scores)
        lo, hi = min(scores), max(scores)
        if hi == lo:
            return [1.0] * len(scores)
        return [(s - lo) / (hi - lo) for s in scores]


# ---------------------------------------------------------------------------
# Benchmark runner
# ---------------------------------------------------------------------------
def _search_one(searcher: Any, query: str, top_k: int) -> list[Any]:
    return searcher.search(query, top_k=top_k)


def run_benchmark(
    backends: list[str],
    queries: list[str],
    top_k: int,
    warm: bool = True,
) -> dict[str, Any]:
    results: dict[str, Any] = {
        "backends": backends,
        "top_k": top_k,
        "num_queries": len(queries),
        "queries": [],
    }

    backend_searchers: dict[str, Any] = {}
    for backend in backends:
        if backend not in _BACKEND_FACTORIES:
            raise ValueError(f"Unknown backend: {backend}")
        print(f"[{backend}] initializing searcher...")
        backend_searchers[backend] = _BACKEND_FACTORIES[backend]()
        if warm:
            _ = _search_one(backend_searchers[backend], "warmup", top_k=1)

    per_backend: dict[str, list[dict[str, Any]]] = {b: [] for b in backends}

    for query in queries:
        print(f"\nQuery: {query}")
        query_row: dict[str, Any] = {"query": query, "backend_results": {}}
        for backend in backends:
            searcher = backend_searchers[backend]
            t0 = time.perf_counter()
            hits = _search_one(searcher, query, top_k)
            elapsed_ms = (time.perf_counter() - t0) * 1000

            metrics = Metrics(query, hits, elapsed_ms)
            d = metrics.to_dict()
            query_row["backend_results"][backend] = d
            per_backend[backend].append(d)
            print(
                f"  [{backend}] {len(hits)} hits, "
                f"top_norm_score={d['top_normalized_score']}, "
                f"sources={d['num_sources']}, "
                f"token_match={d['has_token_match']}, "
                f"phrase_match={d['has_exact_phrase_match']}, "
                f"latency={d['latency_ms']:.1f}ms"
            )

        # Pairwise overlap between backends
        overlap: dict[str, float] = {}
        for i, a in enumerate(backends):
            for b in backends[i + 1 :]:
                a_ids = set(query_row["backend_results"][a]["hit_ids"])
                b_ids = set(query_row["backend_results"][b]["hit_ids"])
                union = a_ids | b_ids
                jaccard = len(a_ids & b_ids) / len(union) if union else 0.0
                overlap[f"{a}_vs_{b}"] = round(jaccard, 2)
        query_row["overlap"] = overlap
        results["queries"].append(query_row)

    # Aggregate summary per backend
    summary: dict[str, dict[str, Any]] = {}
    for backend in backends:
        rows = per_backend[backend]
        summary[backend] = {
            "avg_latency_ms": round(sum(r["latency_ms"] for r in rows) / len(rows), 2),
            "p95_latency_ms": round(
                sorted(r["latency_ms"] for r in rows)[int(len(rows) * 0.95)] if len(rows) > 1 else rows[0]["latency_ms"], 2
            ),
            "avg_top_normalized_score": round(sum(r["top_normalized_score"] for r in rows) / len(rows), 4),
            "avg_num_sources": round(sum(r["num_sources"] for r in rows) / len(rows), 2),
            "token_match_rate": round(sum(r["has_token_match"] for r in rows) / len(rows), 2),
            "exact_phrase_match_rate": round(sum(r["has_exact_phrase_match"] for r in rows) / len(rows), 2),
        }

    # Average overlap across queries
    if len(backends) > 1:
        overlap_keys = list(results["queries"][0]["overlap"].keys())
        summary["overlap"] = {
            key: round(sum(q["overlap"][key] for q in results["queries"]) / len(queries), 2)
            for key in overlap_keys
        }
    results["summary"] = summary
    return results


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
def write_json_report(results: dict[str, Any], path: Path) -> None:
    with path.open("w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"\nJSON report written: {path}")


def write_markdown_summary(results: dict[str, Any], path: Path) -> None:
    backends = results["backends"]
    lines = ["# CADRE-RevAI RAG Benchmark Report\n"]
    lines.append(f"- Date: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"- Top-k: {results['top_k']}")
    lines.append(f"- Queries: {results['num_queries']}\n")

    lines.append("## Summary\n")
    lines.append("| Backend | Avg Latency (ms) | P95 Latency (ms) | Avg Top Norm Score | Avg Sources | Token Match Rate | Exact Phrase Rate |")
    lines.append("|---------|------------------|------------------|--------------------|-------------|------------------|-------------------|")
    for backend in backends:
        s = results["summary"][backend]
        lines.append(
            f"| {backend} | {s['avg_latency_ms']} | {s['p95_latency_ms']} | "
            f"{s['avg_top_normalized_score']} | {s['avg_num_sources']} | "
            f"{s['token_match_rate']} | {s['exact_phrase_match_rate']} |"
        )
    lines.append("")

    if "overlap" in results["summary"]:
        lines.append("## Top-k overlap between backends (Jaccard)\n")
        lines.append("| Pair | Avg overlap |")
        lines.append("|------|-------------|")
        for pair, val in results["summary"]["overlap"].items():
            lines.append(f"| {pair} | {val} |")
        lines.append("")

    lines.append("## Per-query results\n")
    for qr in results["queries"]:
        lines.append(f"### Query: `{qr['query']}`\n")
        lines.append("| Backend | Hits | Top Norm Score | Sources | Technique IDs | Latency (ms) | Token | Phrase |")
        lines.append("|---------|------|----------------|---------|---------------|--------------|-------|--------|")
        for backend in backends:
            r = qr["backend_results"][backend]
            tids = ", ".join(r["technique_ids"]) or "—"
            lines.append(
                f"| {backend} | {r['num_hits']} | {r['top_normalized_score']} | {r['num_sources']} | {tids} | "
                f"{r['latency_ms']} | {r['has_token_match']} | {r['has_exact_phrase_match']} |"
            )
        if qr.get("overlap"):
            lines.append("")
            lines.append("Top-k overlap: " + "; ".join(f"{k}={v}" for k, v in qr["overlap"].items()))
        lines.append("")

    with path.open("w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"Markdown summary written: {path}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description="A/B benchmark CADRE-RevAI RAG backends")
    ap.add_argument(
        "--backends",
        default="dense,hybrid",
        help="Comma-separated backends to benchmark (dense,hybrid,ann,reranker)",
    )
    ap.add_argument("--queries", nargs="+", help="Custom query strings")
    ap.add_argument("--queries-file", type=Path, help="JSONL file with queries")
    ap.add_argument("--top-k", type=int, default=5)
    ap.add_argument("--output", type=Path, default=Path("rag_benchmark_report.json"))
    ap.add_argument("--md-output", type=Path, default=Path("rag_benchmark_report.md"))
    ap.add_argument("--no-warm", action="store_true", help="Skip warmup query")
    args = ap.parse_args()

    if not _indexes_available():
        print("ERROR: RAG indexes not available.", file=sys.stderr)
        return 1

    backends = [b.strip() for b in args.backends.split(",") if b.strip()]
    queries = _load_queries(args)

    results = run_benchmark(backends, queries, args.top_k, warm=not args.no_warm)
    write_json_report(results, args.output)
    write_markdown_summary(results, args.md_output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
