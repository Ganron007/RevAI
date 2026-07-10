"""embed_server.py - Lightweight OpenAI-compatible embedding server.

Alternative to Docker TEI. No WSL2, no Docker, no containers. Just Python.
Runs gte-Qwen2-1.5B-instruct on the local host GPU/CPU.

Usage (host with the GPU/CPU):
    pip install fastapi uvicorn transformers torch
    python embed_server.py
    # Server binds on 0.0.0.0:<port> (default 8080)

Endpoints:
    GET  /health -> {"status": "ok", "model": ..., "device": ...}
    GET  /info   -> {"model": ..., "dim": 1536, "max_length": 32768, ...}
    POST /embed  -> {"inputs": ["text1", "text2"]} -> [[0.012, ...], ...]

Firewall (one-time, allow inbound on the listening port):
"""
from __future__ import annotations
import argparse
import sys

import torch
import torch.nn.functional as F
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from transformers import AutoModel, AutoTokenizer
import uvicorn


DEFAULT_MODEL = "Alibaba-NLP/gte-Qwen2-1.5B-instruct"
MAX_LENGTH = 32768
EMBED_DIM = 1536


def last_token_pool(last_hidden_states: torch.Tensor, attention_mask: torch.Tensor) -> torch.Tensor:
    """gte-Qwen2 pooling: take the last non-pad token's hidden state.

    Source: official gte-Qwen2 README pooling snippet.
    """
    left_padding = (attention_mask[:, -1].sum() == attention_mask.shape[0])
    if left_padding:
        return last_hidden_states[:, -1]
    sequence_lengths = attention_mask.sum(dim=1) - 1
    batch_size = last_hidden_states.shape[0]
    return last_hidden_states[torch.arange(batch_size, device=last_hidden_states.device), sequence_lengths]


def encode_query(model, tokenizer, texts, max_length, device):
    """Encode with the gte-Qwen2 query instruction (for retrieval)."""
    instruction = (
        "Given a web search query, retrieve relevant passages that answer the query\n"
    )
    prefixed = [f"{instruction}{t}" for t in texts]
    batch = tokenizer(
        prefixed,
        padding=True,
        truncation=True,
        max_length=max_length,
        return_tensors="pt",
    ).to(device)
    with torch.no_grad():
        outputs = model(**batch)
    embeddings = last_token_pool(outputs.last_hidden_state, batch["attention_mask"])
    return F.normalize(embeddings, p=2, dim=1)


app = FastAPI(title="CADRE Embed Server", version="1.0.0")
state = {"model": None, "tokenizer": None, "device": None, "model_name": None}


def _load(model_name: str):
    """Load model + tokenizer into memory."""
    device = "cuda" if torch.cuda.is_available() else "cpu"
    print(f"Loading {model_name} on {device}...", flush=True)
    tokenizer = AutoTokenizer.from_pretrained(model_name, trust_remote_code=True)
    if device == "cuda":
        model = AutoModel.from_pretrained(
            model_name, trust_remote_code=True, torch_dtype=torch.float16
        ).to(device)
    else:
        model = AutoModel.from_pretrained(model_name, trust_remote_code=True)
    model.eval()
    state["model"] = model
    state["tokenizer"] = tokenizer
    state["device"] = device
    state["model_name"] = model_name
    print(f"Model loaded: {model_name} on {device}", flush=True)
    if device == "cuda":
        print(f"  GPU: {torch.cuda.get_device_name(0)}", flush=True)
        print(f"  VRAM allocated: {torch.cuda.memory_allocated() / 1e9:.2f} GB", flush=True)
        print(f"  VRAM total: {torch.cuda.get_device_properties(0).total_memory / 1e9:.2f} GB", flush=True)


@app.on_event("startup")
def _startup():
    """Load on startup. Use --no-load and call /admin/load to load lazily."""
    if not getattr(app.state, "lazy_load", False):
        _load(DEFAULT_MODEL)


@app.get("/health")
def health():
    if state["model"] is None:
        raise HTTPException(503, "Model not loaded")
    return {
        "status": "ok",
        "model": state["model_name"],
        "device": state["device"],
    }


@app.get("/info")
def info():
    return {
        "model": state["model_name"] or "(not loaded)",
        "dim": EMBED_DIM,
        "max_length": MAX_LENGTH,
        "device": state["device"] or "(not loaded)",
    }


class EmbedRequest(BaseModel):
    inputs: list[str]


@app.post("/embed")
def embed(req: EmbedRequest):
    if state["model"] is None:
        raise HTTPException(503, "Model not loaded")
    if not req.inputs:
        raise HTTPException(400, "inputs cannot be empty")
    if not all(isinstance(i, str) for i in req.inputs):
        raise HTTPException(400, "all inputs must be strings")
    try:
        device = state["device"]
        # Process in chunks of 64 to bound memory + give progress granularity
        out = []
        BATCH = 64
        for i in range(0, len(req.inputs), BATCH):
            chunk = req.inputs[i:i + BATCH]
            vecs = encode_query(state["model"], state["tokenizer"], chunk, MAX_LENGTH, device)
            out.extend(vecs.cpu().tolist())
        return out
    except torch.cuda.OutOfMemoryError as e:
        raise HTTPException(507, f"GPU OOM: {e}. Try smaller batch or shorter texts.")
    except Exception as e:
        raise HTTPException(500, f"Embedding failed: {e}")


def main():
    global DEFAULT_MODEL
    ap = argparse.ArgumentParser(description="CADRE Embed Server (gte-Qwen2-1.5B on local GPU)")
    ap.add_argument("--host", default="0.0.0.0", help="Host to bind (default 0.0.0.0)")
    ap.add_argument("--port", type=int, default=8080, help="Port to bind (default 8080)")
    ap.add_argument("--model", default=DEFAULT_MODEL, help=f"Model name (default {DEFAULT_MODEL})")
    ap.add_argument("--lazy-load", action="store_true", help="Don't load model on startup (load via /admin/load)")
    args = ap.parse_args()

    app.state.lazy_load = args.lazy_load
    if args.model != DEFAULT_MODEL:
        DEFAULT_MODEL = args.model

    print(f"Starting CADRE Embed Server on http://{args.host}:{args.port}", flush=True)
    print(f"  Model: {args.model}", flush=True)
    print(f"  Endpoints:", flush=True)
    print(f"    GET  /health", flush=True)
    print(f"    GET  /info", flush=True)
    print(f"    POST /embed  (OpenAI-compatible)", flush=True)
    print(f"", flush=True)
    print(f"Test from this host:", flush=True)
    print(f"  curl http://localhost:{args.port}/health", flush=True)
    print(f"", flush=True)
    print(f"Test from a remote client:", flush=True)
    print(f"  curl http://\u003chost\u003e:{args.port}/health", flush=True)

    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
