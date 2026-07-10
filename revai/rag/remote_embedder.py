"""remote_embedder.py — Client for the unified FastAPI embedding + reranker service.

        Used when REVENG_RAG_BACKEND=remote. Talks to a FastAPI-compatible
embedding + reranking service (often hosted on a GPU box; localhost works too).

Server side:
  - Endpoint: POST http://<host>:<port>/embed
  - Request:  {"inputs": ["text1", "text2", ...]}
  - Response: {"embeddings": [[...], [...]], "model": ..., "dim": ..., "device": ...}

Env:
  REVENG_REMOTE_EMBED_URL  default: http://localhost:8000
  OLLAMA_EMBED_MODEL       default: BAAI/bge-m3 (kept for naming consistency)
"""
from __future__ import annotations

import os
from typing import List, Optional

try:
    import httpx
except ImportError as e:
    raise ImportError(
        "RemoteEmbedder requires httpx. Install with: pip install httpx"
    ) from e

# Embedder base class lives in the same package
from reveng_rag import Embedder

DEFAULT_REMOTE_URL = os.environ.get("REVENG_REMOTE_EMBED_URL", "http://localhost:8000")
DEFAULT_MODEL = os.environ.get("REVENG_EMBED_MODEL", "BAAI/bge-m3")


class RemoteEmbedder(Embedder):
    """Embedding client to the unified FastAPI embedding + reranker service.

    Drop-in replacement for the old OllamaEmbedder in the reveng_rag.py interface.
    """
    def __init__(self, base_url: Optional[str] = None,
                 model_name: Optional[str] = None,
                 timeout: int = 300):
        self._base_url = (base_url or os.environ.get("REVENG_REMOTE_EMBED_URL", DEFAULT_REMOTE_URL)).rstrip("/")
        self._embed_url = self._base_url + "/embed"
        self._info_url = self._base_url + "/info"
        self._model = model_name or os.environ.get("REVENG_EMBED_MODEL", DEFAULT_MODEL)
        self._client = httpx.Client(timeout=timeout)
        # Probe dim on init
        try:
            r = self._client.get(self._info_url)
            r.raise_for_status()
            data = r.json()
            self._dim = int(data.get("dim", 0))
            if not self._dim:
                raise RuntimeError(f"/info returned no dim: {data!r}")
        except Exception as e:
            raise RuntimeError(
                f"Remote embedder probe failed at {self._base_url}: {e}\n"
                f"Is the unified server running? Set REVENG_REMOTE_EMBED_URL or start the host service."
            ) from e

    @property
    def dim(self) -> int:
        return self._dim

    @property
    def model_name(self) -> str:
        return self._model

    @property
    def url(self) -> str:
        return self._embed_url

    def encode(self, text: str) -> List[float]:
        r = self._client.post(self._embed_url, json={"inputs": [text], "normalize": True})
        r.raise_for_status()
        embeddings = r.json().get("embeddings")
        if not embeddings or not embeddings[0]:
            raise RuntimeError(f"Remote embed /embed returned empty embeddings")
        return embeddings[0]

    def encode_batch(self, texts: List[str], batch_size: int = 64) -> List[List[float]]:
        out: List[List[float]] = []
        for i in range(0, len(texts), batch_size):
            chunk = texts[i:i + batch_size]
            r = self._client.post(self._embed_url, json={"inputs": chunk, "normalize": True})
            r.raise_for_status()
            embeddings = r.json().get("embeddings")
            if not embeddings:
                raise RuntimeError(f"Remote embed /embed returned empty embeddings for batch")
            out.extend(embeddings)
        return out

    def __repr__(self) -> str:
        return f"RemoteEmbedder(model={self._model}, url={self._embed_url}, dim={self._dim})"


def _selftest() -> int:
    print(f"RemoteEmbedder self-test (REVENG_REMOTE_EMBED_URL={os.environ.get('REVENG_REMOTE_EMBED_URL', DEFAULT_REMOTE_URL)})")
    try:
        emb = RemoteEmbedder()
    except Exception as e:
        print(f"  FAIL: {e}")
        return 1
    print(f"  probe ok: dim={emb.dim}, model={emb.model_name}")
    v = emb.encode("AsyncRAT remote access trojan")
    print(f"  encode ok: {len(v)}-dim vector, first 5 values = {[round(x, 4) for x in v[:5]]}")
    batch = emb.encode_batch(["Hello world", "C2 beacon", "WMI lateral movement"], batch_size=2)
    print(f"  batch encode ok: {len(batch)} vectors, dims = {[len(b) for b in batch]}")
    print(f"  PASS")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(_selftest())

