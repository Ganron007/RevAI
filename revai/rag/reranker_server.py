#!/usr/bin/env python3
r"""reranker_server.py — Unified FastAPI embedding + reranker service for CADRE-RevAI RAG.

Runs on the host with the GPU (or CPU) and exposes:
  POST /embed   → encode a list of texts with bge-m3
  POST /rerank  → score (query, document) pairs with bge-reranker-v2-m3
  GET  /info    → embedding model info (dim, max_length, device)
  GET  /health  → service status

Install:
  pip install fastapi uvicorn sentence-transformers

Run:
  python3 reranker_server.py

Env:
  REVENG_RERANKER_MODEL  default: BAAI/bge-reranker-v2-m3
  REVENG_EMBED_MODEL     default: BAAI/bge-m3
  REVENG_RERANKER_HOST   default: 0.0.0.0
  REVENG_RERANKER_PORT   default: 8000
  REVENG_RERANKER_DEVICE default: auto (cuda if available, else cpu)
  REVENG_RERANKER_MAX_LENGTH default: 512
  REVENG_RERANKER_BATCH_SIZE default: 32
  REVENG_EMBED_BATCH_SIZE    default: 64
"""
from __future__ import annotations

import os
import signal
import time
from contextlib import asynccontextmanager
from typing import Any

import asyncio
from fastapi import FastAPI, BackgroundTasks
from pydantic import BaseModel, Field
from sentence_transformers import CrossEncoder, SentenceTransformer

DEFAULT_RERANKER_MODEL = os.environ.get("REVENG_RERANKER_MODEL", "BAAI/bge-reranker-v2-m3")
DEFAULT_EMBED_MODEL = os.environ.get("REVENG_EMBED_MODEL", "BAAI/bge-m3")
HOST = os.environ.get("REVENG_RERANKER_HOST", "0.0.0.0")
PORT = int(os.environ.get("REVENG_RERANKER_PORT", "8000"))
DEVICE = os.environ.get("REVENG_RERANKER_DEVICE", "auto")
RERANKER_MAX_LENGTH = int(os.environ.get("REVENG_RERANKER_MAX_LENGTH", "512"))
RERANKER_BATCH_SIZE = int(os.environ.get("REVENG_RERANKER_BATCH_SIZE", "32"))
EMBED_BATCH_SIZE = int(os.environ.get("REVENG_EMBED_BATCH_SIZE", "64"))


# ---------------------------------------------------------------------------
# Model lifecycle
# ---------------------------------------------------------------------------
_reranker: CrossEncoder | None = None
_embedder: SentenceTransformer | None = None
_load_times: dict[str, float] = {}


def get_device() -> str:
    if DEVICE != "auto":
        return DEVICE
    try:
        import torch

        return "cuda" if torch.cuda.is_available() else "cpu"
    except ImportError:
        return "cpu"


def load_embedder() -> SentenceTransformer:
    global _embedder, _load_times
    if _embedder is not None:
        return _embedder

    device = get_device()
    print(f"Loading embedding model {DEFAULT_EMBED_MODEL} on device={device}...")
    t0 = time.perf_counter()
    _embedder = SentenceTransformer(DEFAULT_EMBED_MODEL, device=device)
    _load_times["embed"] = (time.perf_counter() - t0) * 1000
    print(f"  Embedding ready ({_load_times['embed']:.0f} ms).")
    return _embedder


def load_reranker() -> CrossEncoder:
    global _reranker, _load_times
    if _reranker is not None:
        return _reranker

    device = get_device()
    print(f"Loading reranker model {DEFAULT_RERANKER_MODEL} on device={device}...")
    t0 = time.perf_counter()
    _reranker = CrossEncoder(DEFAULT_RERANKER_MODEL, device=device)
    _load_times["reranker"] = (time.perf_counter() - t0) * 1000
    print(f"  Reranker ready ({_load_times['reranker']:.0f} ms).")
    return _reranker


@asynccontextmanager
async def lifespan(app: FastAPI):
    load_embedder()
    load_reranker()
    yield
    # cleanup if needed


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------
app = FastAPI(
    title="CADRE-RevAI Embedding + Reranker",
    description="GPU-hosted embedding (bge-m3) and cross-encoder reranker (bge-reranker-v2-m3) for CADRE-RevAI RAG",
    version="2.0.0",
    lifespan=lifespan,
)


class EmbedRequest(BaseModel):
    inputs: list[str] = Field(..., min_length=1, description="Texts to embed")
    normalize: bool = Field(True, description="L2-normalize embeddings (bge-m3 expects True)")
    batch_size: int | None = Field(None, description="Override embedding batch size")


class EmbedResponse(BaseModel):
    embeddings: list[list[float]]
    model: str
    device: str
    dim: int
    latency_ms: float


class RerankRequest(BaseModel):
    query: str = Field(..., min_length=1, description="The search query")
    texts: list[str] = Field(..., min_length=1, description="Documents to rerank")
    top_k: int | None = Field(None, description="If set, return only top-k indices")


class RerankResponse(BaseModel):
    scores: list[float]
    indices: list[int]
    model: str
    device: str
    latency_ms: float


class InfoResponse(BaseModel):
    status: str
    embed_model: str
    reranker_model: str
    device: str
    dim: int
    max_length: int
    load_times_ms: dict[str, float]


class HealthResponse(BaseModel):
    status: str
    embed_model: str
    reranker_model: str
    device: str
    load_times_ms: dict[str, float]


class ShutdownResponse(BaseModel):
    status: str


def _shutdown_worker() -> None:
    """Give the HTTP response time to finish, then ask uvicorn to shut down."""
    time.sleep(0.5)
    try:
        os.kill(os.getpid(), signal.SIGTERM)
    except Exception:
        os._exit(0)


@app.get("/info", response_model=InfoResponse)
async def info() -> dict[str, Any]:
    embedder = load_embedder()
    return {
        "status": "ok",
        "embed_model": DEFAULT_EMBED_MODEL,
        "reranker_model": DEFAULT_RERANKER_MODEL,
        "device": get_device(),
        "dim": embedder.get_sentence_embedding_dimension(),
        "max_length": embedder.max_seq_length,
        "load_times_ms": _load_times,
    }


@app.get("/health", response_model=HealthResponse)
async def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "embed_model": DEFAULT_EMBED_MODEL,
        "reranker_model": DEFAULT_RERANKER_MODEL,
        "device": get_device(),
        "load_times_ms": _load_times,
    }


@app.post("/shutdown", response_model=ShutdownResponse)
async def shutdown(background_tasks: BackgroundTasks) -> dict[str, Any]:
    background_tasks.add_task(_shutdown_worker)
    return {"status": "shutting down"}


@app.post("/embed", response_model=EmbedResponse)
async def embed(req: EmbedRequest) -> dict[str, Any]:
    model = load_embedder()
    texts = [t[:model.max_seq_length] for t in req.inputs]
    batch_size = req.batch_size or EMBED_BATCH_SIZE

    t0 = time.perf_counter()
    embeddings = model.encode(texts, batch_size=batch_size, normalize_embeddings=req.normalize, show_progress_bar=False)
    latency_ms = (time.perf_counter() - t0) * 1000

    return {
        "embeddings": embeddings.tolist() if hasattr(embeddings, "tolist") else embeddings,
        "model": DEFAULT_EMBED_MODEL,
        "device": get_device(),
        "dim": model.get_sentence_embedding_dimension(),
        "latency_ms": round(latency_ms, 2),
    }


@app.post("/rerank", response_model=RerankResponse)
async def rerank(req: RerankRequest) -> dict[str, Any]:
    model = load_reranker()
    texts = [t[:RERANKER_MAX_LENGTH] for t in req.texts]
    pairs = [(req.query, t) for t in texts]

    t0 = time.perf_counter()
    scores = model.predict(pairs, batch_size=RERANKER_BATCH_SIZE, show_progress_bar=False)
    latency_ms = (time.perf_counter() - t0) * 1000

    indexed = sorted(enumerate(scores), key=lambda x: x[1], reverse=True)
    if req.top_k:
        indexed = indexed[: req.top_k]

    return {
        "scores": [float(s) for _, s in indexed],
        "indices": [int(i) for i, _ in indexed],
        "model": DEFAULT_RERANKER_MODEL,
        "device": get_device(),
        "latency_ms": round(latency_ms, 2),
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn

    print(f"Starting CADRE-RevAI unified embedding + reranker server on http://{HOST}:{PORT}")
    print(f"Embed model:   {DEFAULT_EMBED_MODEL}")
    print(f"Rerank model:  {DEFAULT_RERANKER_MODEL}")
    uvicorn.run(app, host=HOST, port=PORT, log_level="info")
