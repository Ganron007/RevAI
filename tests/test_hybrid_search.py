"""test_hybrid_search.py — Test HybridSearcher (dense + BM25 + RRF) integration.

Run with pytest (if available):
    python3 -m pytest tests/test_hybrid_search.py -v

Or self-run without pytest:
    python3 tests/test_hybrid_search.py
"""
import os
import sys
import traceback
from pathlib import Path

# Allow running against local checkout or /opt/cadre-v3-tools/rag
RAG_ROOT = Path(os.environ.get("REVENG_RAG_ROOT", "/opt/cadre-v3-tools/rag"))
if str(RAG_ROOT) not in sys.path:
    sys.path.insert(0, str(RAG_ROOT))

os.environ.setdefault("REVENG_RAG_BACKEND", "remote")
os.environ.setdefault("REVENG_REMOTE_EMBED_URL", "http://localhost:8000")
os.environ.setdefault("REVENG_RERANKER_URL", "http://localhost:8000")
os.environ.setdefault("REVENG_EMBED_MODEL", "BAAI/bge-m3")

from rag_hybrid import HybridSearcher


def _indexes_available() -> bool:
    index_dir = Path(os.environ.get("REVENG_RAG_INDEX_DIR", RAG_ROOT / "index"))
    return (
        (index_dir / "dense_ollama.npy").exists()
        and (index_dir / "dense_ollama.ids.json").exists()
        and (index_dir / "bm25_ollama.pkl").exists()
    )


class TestHybridSearch:
    @classmethod
    def setup_class(cls):
        if not _indexes_available():
            raise RuntimeError("RAG indexes not available; skipping tests")
        cls.searcher = HybridSearcher()

    def test_search_returns_hits(self):
        hits = self.searcher.search("AsyncRAT C2 beacon", top_k=5)
        assert len(hits) == 5, f"expected 5 hits, got {len(hits)}"
        for h in hits:
            assert h.id, "hit missing id"
            assert h.text, "hit missing text"
            assert h.source, "hit missing source"
            assert h.rrf_score >= 0.0, "hit rrf_score negative"

    def test_technique_filter(self):
        hits = self.searcher.search("PowerShell execution", top_k=5, technique="T1059.001")
        for h in hits:
            tid = h.technique_id
            tids = h.metadata.get("technique_ids", [])
            assert tid == "T1059.001" or "T1059.001" in tids, f"technique mismatch: {tid} / {tids}"

    def test_source_filter(self):
        hits = self.searcher.search("Cobalt Strike", top_k=3, source="mitre-attack")
        for h in hits:
            assert h.source == "mitre-attack", f"expected source mitre-attack, got {h.source}"

    def test_format_hits_for_prompt(self):
        hits = self.searcher.search("Emotet banking trojan", top_k=3)
        context = self.searcher.format_hits_for_prompt(hits, max_chars=4000)
        assert context.startswith("<rag_context>"), "context missing opening tag"
        assert context.endswith("</rag_context>"), "context missing closing tag"
        assert "<rag_hit" in context, "context missing rag_hit"


if __name__ == "__main__":
    if not _indexes_available():
        print("Indexes not available; skipping tests.")
        sys.exit(0)
    t = TestHybridSearch()
    t.setup_class()
    failures = 0
    for name in dir(t):
        if not name.startswith("test_"):
            continue
        print(f"Running {name} ...")
        try:
            getattr(t, name)()
            print(f"  OK")
        except AssertionError as e:
            print(f"  FAIL: {e}")
            failures += 1
        except Exception as e:
            print(f"  ERROR: {e}")
            traceback.print_exc()
            failures += 1
    print(f"\n{failures} failure(s)")
    sys.exit(0 if failures == 0 else 1)
