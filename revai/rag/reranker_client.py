#!/usr/bin/env python3
"""reranker_client.py — Client for the remote FastAPI reranker service.

Used by Remnux to call the remote FastAPI reranker service.

Env:
  REVENG_RERANKER_URL   default: http://localhost:8000
"""
from __future__ import annotations

import os
from typing import Any

import requests

DEFAULT_URL = os.environ.get("REVENG_RERANKER_URL", "http://localhost:8000")
TIMEOUT = int(os.environ.get("REVENG_RERANKER_TIMEOUT", "60"))


class RerankerClient:
    """Talks to the remote FastAPI reranker service."""

    def __init__(self, base_url: str | None = None):
        self.base_url = (base_url or DEFAULT_URL).rstrip("/")

    def health(self) -> dict[str, Any]:
        r = requests.get(f"{self.base_url}/health", timeout=10)
        r.raise_for_status()
        return r.json()

    def rerank(self, query: str, texts: list[str], top_k: int | None = None) -> dict[str, Any]:
        payload = {"query": query, "texts": texts}
        if top_k is not None:
            payload["top_k"] = top_k
        r = requests.post(f"{self.base_url}/rerank", json=payload, timeout=TIMEOUT)
        r.raise_for_status()
        return r.json()

    def __repr__(self) -> str:
        return f"RerankerClient({self.base_url})"
