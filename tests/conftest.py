#!/usr/bin/env python3
"""Keep the test session hermetic against REVAI_* environment leakage.

Found 2026-10-02 on the VM: `tests/test_llm_streaming.py` failed in the full
suite but passed in isolation, in 0.02s. The cause was not the streaming code.

`v2_lib.ensure_pipeline_runtime_env()` calls `load_env_file`, which uses
`setdefault` to inject every key from /opt/revai/config/llm.env into
`os.environ` -- including the real 51-character `REVAI_LLM_API_KEY`. Whatever
test calls it therefore leaves the operator's LIVE API KEY in the process
environment for every test that runs afterwards in the same session.

Two tests then change behaviour, because `llm_judge` takes a different path
depending on whether a key is configured. Neither failure had anything to do
with the code under test.

The fix is at the session level rather than per-file: any future test that reads
the config can leak the same way, and patching the one file that noticed today
would leave the trap armed. Each test now gets the environment it started with.

Two things this deliberately does NOT do:

* It does not delete pre-existing REVAI_* variables. A developer who exports
  REVAI_LLM_MAX_TOKENS to run one test deliberately should see it honoured, and
  silently clearing it would make a different test's failure even harder to
  explain. Only keys ADDED during the test are rolled back.
* It does not touch non-REVAI variables (PATH, HOME, TMPDIR, ...). Those are the
  developer's business and pytest's own fixtures already manage what it needs.
"""
from __future__ import annotations

import os

import pytest

_PREFIX = "REVAI_"


@pytest.fixture(autouse=True)
def _isolate_revai_env():
    """Roll back any REVAI_* key a test adds to the process environment.

    `monkeypatch` already undoes its own changes, but a test that writes
    `os.environ[...] = ...` directly bypasses it entirely -- and several code
    paths (ensure_pipeline_runtime_env, load_env_file) do exactly that by
    design, because in production the config file IS meant to populate the
    environment.
    """
    before = {k: v for k, v in os.environ.items() if k.startswith(_PREFIX)}
    try:
        yield
    finally:
        for key in [k for k in os.environ if k.startswith(_PREFIX)]:
            if key not in before:
                del os.environ[key]
        for key, value in before.items():
            if os.environ.get(key) != value:
                os.environ[key] = value