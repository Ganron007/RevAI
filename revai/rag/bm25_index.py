#!/usr/bin/env python3
"""bm25_index.py — Build and load a BM25Okapi index from CADRE-RevAI RAG corpus JSONL.

The index is a plain pickle of {
    "doc_ids": list[str],            # aligned with corpus order
    "tokenized": list[list[str]],    # tokenized documents
    "bm25": rank_bm25.BM25Okapi,     # the BM25 model
}

Usage:
    python3 bm25_index.py --corpus-dir /opt/cadre-v3-tools/rag/corpus \
                         --output /opt/cadre-v3-tools/rag/index/bm25_ollama.pkl

    python3 bm25_index.py --corpus-dir /opt/cadre-v3-tools/rag/corpus \
                         --output /opt/cadre-v3-tools/rag/index/bm25_ollama.pkl \
                         --dry-run
"""
from __future__ import annotations

import argparse
import json
import pickle
import re
import sys
from pathlib import Path
from typing import Any

TOKEN_RE = re.compile(r"[a-zA-Z0-9_+/]{2,}")


def tokenize(text: str) -> list[str]:
    """Simple alphanumeric tokenizer for BM25."""
    return [t.lower() for t in TOKEN_RE.findall(text)]


def load_corpus(corpus_dir: Path) -> tuple[list[str], list[str]]:
    """Load all JSONL files and return (doc_ids, texts)."""
    doc_ids: list[str] = []
    texts: list[str] = []
    for path in sorted(corpus_dir.glob("*.jsonl")):
        with path.open("r", encoding="utf-8") as f:
            for lineno, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError as e:
                    print(f"  WARNING: skipping invalid JSONL line {lineno} in {path}: {e}")
                    continue
                doc_id = rec.get("id")
                text = rec.get("text")
                if not doc_id or not text:
                    continue
                doc_ids.append(str(doc_id))
                texts.append(str(text))
    return doc_ids, texts


def build_bm25(
    corpus_dir: Path,
    output: Path,
    *,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Build BM25 index from corpus JSONL."""
    print(f"Loading corpus from {corpus_dir}...")
    doc_ids, texts = load_corpus(corpus_dir)
    print(f"  {len(texts)} documents loaded")

    print("Tokenizing...")
    tokenized = [tokenize(t) for t in texts]

    print("Building BM25Okapi...")
    from rank_bm25 import BM25Okapi

    bm25 = BM25Okapi(tokenized)

    index = {"doc_ids": doc_ids, "tokenized": tokenized, "bm25": bm25}

    if dry_run:
        print(f"DRY RUN: would write {len(doc_ids)} docs to {output}")
        return index

    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("wb") as f:
        pickle.dump(index, f, protocol=pickle.HIGHEST_PROTOCOL)
    print(f"Wrote BM25 index to {output} ({len(doc_ids)} docs)")
    return index


def load_bm25(index_path: Path) -> dict[str, Any]:
    """Load a previously built BM25 index."""
    with index_path.open("rb") as f:
        return pickle.load(f)


def main() -> int:
    ap = argparse.ArgumentParser(description="Build BM25 index from CADRE-RevAI RAG corpus")
    ap.add_argument(
        "--corpus-dir",
        type=Path,
        default=Path("/opt/cadre-v3-tools/rag/corpus"),
        help="Directory containing corpus JSONL files",
    )
    ap.add_argument(
        "--output",
        type=Path,
        default=Path("/opt/cadre-v3-tools/rag/index/bm25_ollama.pkl"),
        help="Output pickle path",
    )
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="Build in memory but do not write",
    )
    args = ap.parse_args()

    build_bm25(args.corpus_dir, args.output, dry_run=args.dry_run)
    return 0


if __name__ == "__main__":
    sys.exit(main())
