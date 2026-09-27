#!/usr/bin/env python3
"""artifact_gen.py - #11 verifiable artifact generation (opt-in stage).

The LLM writes a small, sample-specific Python script (config extractor, static
unpacker, deobfuscator); this stage runs it and then **re-derives every value the
script claims, deterministically, from the sample bytes**. That inversion is the
whole point: a report asserts, a script can be executed, and code can check the
script's output against the file it claims to have read. The LLM authors; it never
verifies itself.

G DATA's lesson behind #11: "create scripts, not just reports" - a script has a
built-in feedback loop (run -> works or fails), a report has none. Their anti-cheat
warning is implemented literally, as three measured checks (not claims):

  1. input_read          - the script must take the sample path from argv, so it
                           cannot have been written against a pre-extracted answer.
  2. source_literal      - a claimed value that also appears as a literal in the
                           generated source is flagged: the script may be printing,
                           not extracting.
  3. pre_seeded_in_prompt- a claimed value that already appeared verbatim in the
                           generation prompt (e.g. shown by the decompiler) is
                           flagged: extraction is then not independent, and the
                           artifact says so.

Stage contract:
  - Opt-in: REVAI_ENABLE_ARTIFACT_GEN=1 (Console: run config). Off => skip, rc=0.
  - Never gates the verdict. Any failure is recorded honestly
    (status: ran | not_applicable | failed | skipped) and the run continues.
  - Artifacts: <case>/artifact_gen/01-evidence.json, 02-prompt.txt,
    03-generated.py, 04-execution.json, 05-verification.json, artifact-gen.json.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.environ.get("REVAI_SCRIPTS_DIR", "/opt/scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from v2_lib import (  # noqa: E402
    case_dir,
    ensure_pipeline_runtime_env,
    get_llm_model,
    hitl_checkpoint,
    llm_call_metadata,
    llm_judge,
    load_session,
    revai_provenance,
)

SCHEMA = "revai.artifact_gen/1"
STAGE_DIRNAME = "artifact_gen"
SUMMARY_NAME = "artifact-gen.json"

# Stage limits (bounded by design: this is an analyst convenience, not a sandbox
# for hostile code - the sandbox facts are recorded honestly in the summary).
GEN_TIMEOUT_S = int(os.environ.get("REVAI_ARTIFACT_GEN_TIMEOUT", "180") or 180)
RUN_TIMEOUT_S = int(os.environ.get("REVAI_ARTIFACT_GEN_RUN_TIMEOUT", "60") or 60)
MEM_LIMIT_BYTES = int(os.environ.get("REVAI_ARTIFACT_GEN_MEM_MB", "1024") or 1024) * 1024 * 1024
FS_LIMIT_BYTES = int(os.environ.get("REVAI_ARTIFACT_GEN_FS_MB", "32") or 32) * 1024 * 1024
OUT_CAP = 64 * 1024

# Derivation methods this stage can independently re-verify. Anything else is
# reported as method_unsupported - kept in the output, never counted as verified.
SUPPORTED_METHODS = ("raw", "utf16le", "xor", "base64", "hex")
_MIN_LITERAL_LEN = 6


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _enabled() -> bool:
    return (os.environ.get("REVAI_ENABLE_ARTIFACT_GEN") or "").strip().lower() in (
        "1", "true", "yes", "on",
    )


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")


def _read_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return {}


# --------------------------------------------------------------------------
# evidence pack (structural; what the script author is allowed to see)
# --------------------------------------------------------------------------


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    import math

    return -sum((c / n) * math.log2(c / n) for c in counts if c)


def high_entropy_regions(data: bytes, block: int = 4096, top: int = 12) -> list[dict]:
    """Top-N high-entropy blocks, with offsets - a map of where to look."""
    regions = []
    for off in range(0, len(data), block):
        chunk = data[off:off + block]
        ent = _entropy(chunk)
        if ent >= 7.0:
            regions.append({"offset": off, "size": len(chunk), "entropy": round(ent, 3)})
    regions.sort(key=lambda r: -r["entropy"])
    return regions[:top]


def pe_sections(sample: Path) -> list[dict]:
    """Section table when pefile is importable; fail-open to []."""
    try:
        import pefile  # type: ignore
    except Exception:
        return []
    try:
        pe = pefile.PE(str(sample), fast_load=True)
        out = []
        for s in getattr(pe, "sections", []) or []:
            name = (s.Name or b"").rstrip(b"\x00").decode("latin-1", "replace")
            out.append({
                "name": name,
                "virtual_address": hex(int(s.VirtualAddress)),
                "raw_offset": int(s.PointerToRawData),
                "raw_size": int(s.SizeOfRawData),
                "virtual_size": int(s.Misc_VirtualSize),
                "entropy": round(float(s.get_entropy()), 3),
            })
        return out
    except Exception:
        return []


_GENERIC_STRINGS = {
    "kernel32.dll", "user32.dll", "advapi32.dll", "ntdll.dll", "msvcrt.dll",
    "this program cannot be run in dos mode", "richsignature", "pe..l",
}


def candidate_strings(data: bytes, limit: int = 40) -> list[dict]:
    """ASCII/UTF-16LE strings with offsets. Offsets matter: a script needs them."""
    out: list[dict] = []
    seen: set[tuple[str, str]] = set()

    for m in re.finditer(rb"[\x20-\x7e]{6,64}", data):
        s = m.group().decode("latin-1")
        if s.lower() in _GENERIC_STRINGS:
            continue
        key = (s, "ascii")
        if key in seen:
            continue
        seen.add(key)
        out.append({"offset": m.start(), "encoding": "ascii", "text": s})
    for m in re.finditer(rb"(?:[\x20-\x7e]\x00){6,64}", data):
        s = m.group().decode("utf-16le", "replace")
        if s.lower() in _GENERIC_STRINGS:
            continue
        key = (s, "utf16le")
        if key in seen:
            continue
        seen.add(key)
        out.append({"offset": m.start(), "encoding": "utf16le", "text": s})
    out.sort(key=lambda r: r["offset"])
    return out[:limit]


def decompile_excerpts(sha: str, limit: int = 3, chars: int = 1800) -> list[dict]:
    """Bounded decompiler excerpts from the deep-dive artifacts, if present."""
    case = case_dir(sha)
    excerpts: list[dict] = []
    for rel in ("deep_dive/05-deep-dive.json", "deep_dive/agentic_deep_dive.json"):
        path = case / rel
        if not path.is_file():
            continue
        data = _read_json(path)
        for entry in (data.get("decompiles") or data.get("sql_evidence") or [])[:limit * 3]:
            if not isinstance(entry, dict):
                continue
            body = entry.get("code") or entry.get("decompiled") or entry.get("text") or ""
            if not isinstance(body, str) or len(body) < 80:
                continue
            excerpts.append({
                "source": rel,
                "name": entry.get("name") or entry.get("func") or entry.get("address") or "",
                "excerpt": body[:chars],
            })
            if len(excerpts) >= limit:
                return excerpts
    return excerpts


def build_evidence_pack(sha: str, sample: Path) -> dict:
    """Everything the script author sees, plus an explicit withheld list."""
    data = sample.read_bytes()
    case = case_dir(sha)
    verdict = _read_json(case / "verdict.json")
    deep = _read_json(case / "deep_dive" / "05-deep-dive.json")
    pack = {
        "schema": "revai.artifact_gen.evidence/1",
        "sha256": sha,
        "sample_path": str(sample),
        "size": len(data),
        "file_entropy": round(_entropy(data), 3),
        "verdict": verdict.get("verdict"),
        "family_guess": verdict.get("family_guess"),
        "packed_signal": deep.get("packed_signal"),
        "sections": pe_sections(sample),
        "high_entropy_regions": high_entropy_regions(data),
        "strings_with_offsets": candidate_strings(data),
        "decompile_excerpts": decompile_excerpts(sha),
        "withheld_from_prompt": [
            "decoded plaintext of any obfuscated region (the pipeline does not "
            "decode; deriving it is the script's job)",
            "the sample bytes themselves (the script reads the file at runtime)",
        ],
    }
    return pack


# --------------------------------------------------------------------------
# prompt + response handling
# --------------------------------------------------------------------------

CONTRACT = """Write ONE small, self-contained Python 3 script that extracts a concrete
artifact from the malware sample it is given. Stdlib only. No network. No
arguments of your own.

Invocation (fixed):  python3 <script>.py <sample_path> <out_dir>
  - argv[1] is the sample to read. Read the file; never assume an answer.
  - argv[2] is a writable directory. Write your findings there as result.json.

result.json schema:
{
  "artifacts": [
    {"kind": "config|url|key|payload|path|registry|mutex|other",
     "value": "<extracted text or hex>",
     "offset": <int byte offset in the sample, or null>,
     "method": "raw|utf16le|xor|base64|hex",
     "key": "<only for xor: the single-byte key as an int>",
     "evidence": "<why you believe this is a real extraction: which bytes, which function>"}
  ],
  "not_extractable": ["<what you tried and why it is not extractable>"],
  "notes": "<one or two sentences>"
}

Rules:
  - Derive every value from the bytes you read. A value you merely print from a
    literal in your own source is worthless and will be flagged.
  - Report the byte offset of each value and the method that produced it, so the
    result can be independently re-derived and checked.
  - Your script travels to the runner as a JSON string, so backslash escapes can
    be mangled in transit. NEVER write \\x byte escapes inside the script. Build
    byte patterns with bytes.fromhex('50450000') or chr(0) instead, e.g.
    PE_SIG = bytes.fromhex('50450000').
  - If the sample is not amenable (no config, nothing to unpack), say so:
    applicability = "not_applicable" with a reason, and return no script.

Return JSON only:
{
  "applicability": "applicable" | "not_applicable",
  "reason": "<why not applicable, or ''>",
  "targets": ["<what the script extracts>"],
  "script": "<the complete Python source as one string>"
}"""

SYSTEM = (
    "You are a malware analyst who ships runnable extraction code, not prose. "
    "You never see the answer key: the sample is read by your script at runtime. "
    "Return valid JSON only."
)


def build_prompt(pack: dict) -> str:
    return (
        "Author a verifiable extraction script for this sample.\n\n"
        "EVIDENCE (structural; offsets and locations, not decoded answers):\n"
        + json.dumps(pack, indent=2, default=str)[:60000]
        + "\n\nSCRIPT CONTRACT:\n"
        + CONTRACT
    )


_FENCE = re.compile(r"```(?:python|py)?\s*(.*?)```", re.S)
# The script rides to the runner inside a JSON string, so an LLM that writes
# b'PE\x00\x00' emits an escaped backslash and the runner receives literal
# backslashes. Observed live 2026-09-27: the script compared against
# b'PE\\x00\\x00', concluded "not a PE" and exited. We warn instead of silently
# rewriting source - the failure stays diagnosable.
_MANGLED_BYTES_LITERAL = re.compile(r"""b(['"])[^'"]*\\\\x""")


def source_warnings(script_src: str) -> list[str]:
    """Static checks on the generated source, recorded honestly in the summary."""
    out: list[str] = []
    if _MANGLED_BYTES_LITERAL.search(script_src or ""):
        out.append("escaped_backslash_in_bytes_literal: build byte patterns with "
                   "bytes.fromhex() - \\x escapes are mangled by the JSON transport")
    if re.search(r"\bsocket\b|\brequests\b|\burlopen\b", script_src or ""):
        out.append("network_import_present: the sandbox has no network, so this "
                   "cannot work")
    return out


def extract_script(response: dict) -> tuple[str, dict]:
    """Parse the generation response. Returns (source, meta)."""
    meta: dict = {"parse_ok": False, "applicability": None, "reason": "",
                  "targets": [], "llm": llm_call_metadata(response)}
    try:
        content = response["choices"][0]["message"]["content"] or ""
    except Exception:
        meta["reason"] = "no content in response"
        return "", meta
    data: dict = {}
    try:
        data = json.loads(content)
    except Exception:
        m = _FENCE.search(content)
        blob = m.group(1) if m else content
        try:
            data = json.loads(blob)
        except Exception:
            meta["reason"] = "response was not JSON"
            return "", meta
    meta["parse_ok"] = True
    meta["applicability"] = str(data.get("applicability") or "").strip().lower()
    meta["reason"] = str(data.get("reason") or "")[:500]
    targets = data.get("targets")
    meta["targets"] = [str(t)[:120] for t in targets] if isinstance(targets, list) else []
    script = data.get("script") or ""
    if not isinstance(script, str):
        script = ""
    m = _FENCE.search(script)
    if m:
        script = m.group(1)
    meta["llm"]["request_model"] = get_llm_model()
    return script.strip(), meta


# --------------------------------------------------------------------------
# execution (sandbox facts are recorded, never assumed)
# --------------------------------------------------------------------------


def _network_isolation() -> tuple[list[str] | None, str]:
    """Prefix the command with `unshare -n` when available; report the truth."""
    exe = shutil.which("unshare")
    if not exe:
        return None, "unshare_not_available"
    probe = subprocess.run(
        [exe, "-n", "true"], capture_output=True, timeout=10, check=False
    )
    if probe.returncode == 0:
        return [exe, "-n"], "unshare_net_applied"
    return None, "unshare_net_unavailable_rc_%d" % probe.returncode


def run_generated_script(script_path: Path, sample: Path, out_dir: Path,
                         timeout_s: int | None = None) -> dict:
    """Run the generated script with bounded, scrubbed, recorded isolation."""
    net_prefix, net_state = _network_isolation()
    run_timeout = int(timeout_s or RUN_TIMEOUT_S)
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(out_dir),
        "TMPDIR": str(out_dir),
        "LANG": "C.UTF-8",
    }
    cmd = list(net_prefix or []) + [
        sys.executable, "-I", "-B", str(script_path), str(sample), str(out_dir),
    ]
    limits: dict = {"posix": os.name == "posix"}

    def _preexec() -> None:  # pragma: no cover - runs in the child
        try:
            import resource

            resource.setrlimit(resource.RLIMIT_AS, (MEM_LIMIT_BYTES, MEM_LIMIT_BYTES))
            resource.setrlimit(resource.RLIMIT_FSIZE, (FS_LIMIT_BYTES, FS_LIMIT_BYTES))
            cpu = run_timeout + 5
            resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
            limits["applied"] = True
        except Exception:
            limits["applied"] = False

    started = time.time()
    rec: dict = {
        "cmd": cmd,
        "network_isolation": net_state,
        "interpreter_isolated": True,
        "rlimits": {"as_bytes": MEM_LIMIT_BYTES, "fs_bytes": FS_LIMIT_BYTES,
                    "enforced": bool(limits["posix"])},
        "timeout_s": run_timeout,
        "started_at": _utc(),
    }
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(out_dir),
            env=env,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=run_timeout,
            preexec_fn=_preexec if limits["posix"] else None,
            check=False,
        )
        rec.update({
            "rc": proc.returncode,
            "stdout": (proc.stdout or "")[:OUT_CAP],
            "stderr": (proc.stderr or "")[:OUT_CAP],
            "timed_out": False,
        })
    except subprocess.TimeoutExpired as exc:
        rec.update({
            "rc": 124,
            "stdout": (exc.stdout or "")[:OUT_CAP] if isinstance(exc.stdout, str) else "",
            "stderr": "timeout: script exceeded RUN_TIMEOUT_S",
            "timed_out": True,
        })
    except Exception as exc:  # noqa: BLE001 - recorded, never raised
        rec.update({"rc": 125, "stdout": "", "stderr": f"{type(exc).__name__}: {exc}",
                    "timed_out": False})
    rec["elapsed_s"] = round(time.time() - started, 2)
    rec["finished_at"] = _utc()
    return rec


# --------------------------------------------------------------------------
# deterministic verification - the part that makes this "verifiable"
# --------------------------------------------------------------------------


def _window(data: bytes, offset: int, length: int) -> bytes:
    if offset < 0 or offset >= len(data):
        return b""
    return data[offset:offset + max(1, length)]


def rederive(data: bytes, artifact: dict) -> tuple[bool | None, str]:
    """Independently re-derive one claimed value from the sample bytes.

    Returns (verified, basis). verified is None when the method is outside the
    supported set - the value is kept, never counted as verified.
    """
    value = artifact.get("value")
    if not isinstance(value, str) or not value:
        return False, "empty_value"
    method = str(artifact.get("method") or "raw").strip().lower()
    offset = artifact.get("offset")
    if method not in SUPPORTED_METHODS:
        return None, f"method_unsupported:{method}"
    if offset is None:
        # No location claimed: the value must at least exist in the file.
        raw = value.encode("utf-8", "replace")
        if raw and raw in data:
            return True, "value_present_in_sample"
        if value.encode("utf-16le", "replace") in data:
            return True, "value_present_in_sample_utf16le"
        return False, "value_not_found_in_sample"
    try:
        off = int(offset)
    except Exception:
        return False, "offset_not_an_int"
    n = len(value)
    if method == "raw":
        return _cmp(_window(data, off, n), value, "raw_at_offset")
    if method == "utf16le":
        window = _window(data, off, n * 2).decode("utf-16le", "replace")
        return _cmp(window.encode("utf-8", "replace"), value, "utf16le_at_offset")
    if method == "hex":
        window = _window(data, off, n * 2)
        try:
            derived = bytes.fromhex(window.decode("latin-1", "replace").strip())
        except Exception:
            return False, "hex_window_not_hex"
        return _cmp(derived, value, "hex_decoded_at_offset")
    if method == "base64":
        window = _window(data, off, (n // 3 + 1) * 4 + 8)
        try:
            derived = base64.b64decode(window, validate=False)
        except Exception:
            return False, "base64_window_not_decodable"
        return _cmp(derived, value, "base64_decoded_at_offset")
    if method == "xor":
        key = artifact.get("key")
        try:
            k = int(str(key), 0)
        except Exception:
            return False, "xor_key_missing"
        if not 0 <= k <= 255:
            return False, "xor_key_out_of_range"
        window = _window(data, off, n)
        derived = bytes(b ^ k for b in window)
        return _cmp(derived, value, f"xor_0x{k:02x}_at_offset")
    return None, f"method_unsupported:{method}"


def _cmp(derived: bytes, value: str, basis: str) -> tuple[bool, str]:
    if derived == value.encode("utf-8", "replace"):
        return True, basis
    if derived.decode("utf-8", "replace").strip() == value.strip():
        return True, basis
    return False, f"re_derivation_mismatch:{basis}"


def _result_artifacts(out_dir: Path, execution: dict) -> tuple[list[dict], str]:
    """Read the script's result.json (or stdout JSON). Returns (artifacts, note)."""
    path = out_dir / "result.json"
    if path.is_file():
        data = _read_json(path)
        arts = data.get("artifacts")
        if isinstance(arts, list):
            return [a for a in arts if isinstance(a, dict)], ""
        return [], "result_json_without_artifacts_list"
    blob = (execution.get("stdout") or "").strip()
    if blob.startswith("{"):
        data = _read_json_text(blob)
        arts = data.get("artifacts") if isinstance(data, dict) else None
        if isinstance(arts, list):
            return [a for a in arts if isinstance(a, dict)], "from_stdout"
    return [], "no_result_json"


def _script_declined(execution: dict) -> str:
    """Did the *script itself* conclude there is nothing to extract?

    A generated script may answer in the generation shape (it was asked for that
    JSON) instead of writing result.json. Recorded as an honest not_applicable
    with the script's own reason, not as a silent zero-claim run.
    """
    blob = (execution.get("stdout") or "").strip()
    if not blob.startswith("{"):
        return ""
    data = _read_json_text(blob)
    if str(data.get("applicability") or "").strip().lower() == "not_applicable":
        return str(data.get("reason") or "script reported not_applicable")[:300]
    return ""


def _corrective_prompt(prompt: str, script_src: str, execution: dict,
                       verification: dict) -> str:
    """One bounded feedback pass - the 'scripts have a feedback loop' part."""
    return (
        prompt
        + "\n\nCORRECTION PASS (your previous script produced no verified artifact):\n"
        + "Your script reported:\n"
        + (execution.get("stdout") or "")[:1500]
        + "\n(exit rc=" + str(execution.get("rc"))
        + ", stderr: " + (execution.get("stderr") or "")[:600] + ")\n"
        + "Checklist for the fix:\n"
        + "  - the runner passes the sample path as argv[1] and an output dir as "
          "argv[2]; read argv[1], write argv[2] + '/result.json'\n"
        + "  - print NOTHING else: the only accepted outputs are result.json or a "
          "single JSON object on stdout with an 'artifacts' list\n"
        + "  - do not use \\x escapes in byte literals (they are mangled in transit); "
          "use bytes.fromhex('...')\n"
        + "  - do not bail out on a format check you are not sure about: locate the "
          "PE header by scanning for bytes.fromhex('50450000') if e_lfanew looks odd\n"
        + "  - if genuinely nothing is extractable, return applicability "
          "'not_applicable' with a specific reason and no script\n"
        + "\nYour previous script (for reference):\n" + script_src[:4000]
    )


def _read_json_text(text: str) -> dict:
    try:
        data = json.loads(text)
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def verify_claims(sample: Path, artifacts: list[dict], prompt_text: str,
                  script_src: str) -> dict:
    """Re-derive every claim + run the three anti-cheat measurements."""
    data = sample.read_bytes()
    prompt_lc = (prompt_text or "").lower()
    checked: list[dict] = []
    verified = unverified = unsupported = 0
    hardcoded = preseeded = 0

    for art in artifacts:
        value = art.get("value") if isinstance(art, dict) else None
        value = value if isinstance(value, str) else str(value or "")
        ok, basis = rederive(data, art)
        is_literal = (
            len(value) >= _MIN_LITERAL_LEN and f'"{value}"' in script_src
        ) or (len(value) >= _MIN_LITERAL_LEN and f"'{value}'" in script_src)
        in_prompt = len(value) >= _MIN_LITERAL_LEN and value.lower() in prompt_lc
        entry = {
            "kind": art.get("kind"),
            "value_preview": value[:120],
            "offset": art.get("offset"),
            "method": art.get("method"),
            "claimed_evidence": str(art.get("evidence") or "")[:300],
            "verified": ok,
            "basis": basis,
            "source_literal": bool(is_literal),
            "pre_seeded_in_prompt": bool(in_prompt),
        }
        if ok is True:
            verified += 1
        elif ok is None:
            unsupported += 1
        else:
            unverified += 1
        if is_literal:
            hardcoded += 1
        if in_prompt:
            preseeded += 1
        checked.append(entry)

    total = len(artifacts)
    if total == 0:
        independence = "no_claims"
    elif preseeded == total or hardcoded == total:
        independence = "not_independent"
    elif preseeded or hardcoded:
        independence = "partially_independent"
    else:
        independence = "independent"

    return {
        "schema": "revai.artifact_gen.verification/1",
        "input_read": bool(re.search(r"\bargv\b", script_src or "")),
        "claims_total": total,
        "claims_verified": verified,
        "claims_unverified": unverified,
        "claims_method_unsupported": unsupported,
        "hardcoded_output_literals": hardcoded,
        "values_pre_seeded_in_prompt": preseeded,
        "independence": independence,
        "artifacts": checked,
        "note": (
            "verified = the pipeline re-derived the value from the sample bytes at "
            "the claimed offset with the claimed method. independence = whether the "
            "value was already visible in the generation prompt or hardcoded in the "
            "script, which is measured, not assumed."
        ),
    }


# --------------------------------------------------------------------------
# stage
# --------------------------------------------------------------------------


def _skip(sha: str, stage_dir: Path, reason: str) -> dict:
    summary = {
        "schema": SCHEMA, "sha256": sha, "status": "skipped", "ok": True,
        "reason": reason, "generated": False, "artifacts_total": 0,
        "artifacts_verified": 0, "provenance": revai_provenance(),
        "finished_at": _utc(),
    }
    _write_json(stage_dir / SUMMARY_NAME, summary)
    print(f"[artifact_gen] skipped: {reason}", flush=True)
    return summary


def _not_applicable(sha: str, stage_dir: Path, reason: str, meta: dict) -> dict:
    summary = {
        "schema": SCHEMA, "sha256": sha, "status": "not_applicable", "ok": True,
        "reason": reason, "generated": False, "artifacts_total": 0,
        "artifacts_verified": 0, "llm": meta.get("llm"),
        "targets": meta.get("targets") or [],
        "provenance": revai_provenance(), "finished_at": _utc(),
    }
    _write_json(stage_dir / SUMMARY_NAME, summary)
    print(f"[artifact_gen] not_applicable: {reason}", flush=True)
    return summary


def run_stage(sha: str, *, force: bool = False) -> dict:
    ensure_pipeline_runtime_env()
    if not force and not _enabled():
        return _skip(sha, case_dir(sha) / STAGE_DIRNAME,
                     "REVAI_ENABLE_ARTIFACT_GEN not set (opt-in)")

    session = load_session(sha)
    sample = Path(session.get("sample_path") or "")
    stage_dir = case_dir(sha) / STAGE_DIRNAME
    stage_dir.mkdir(parents=True, exist_ok=True)
    if not sample.is_file():
        return _skip(sha, stage_dir, f"sample not available: {sample}")

    t0 = time.time()
    pack = build_evidence_pack(sha, sample)
    _write_json(stage_dir / "01-evidence.json", pack)
    prompt = build_prompt(pack)
    (stage_dir / "02-prompt.txt").write_text(prompt, encoding="utf-8")
    print(f"[artifact_gen] prompt {len(prompt)} chars, model={get_llm_model()}", flush=True)

    hitl_checkpoint("artifact_gen", "pre_generate", {"sha256": sha})

    try:
        response = llm_judge(prompt, model=get_llm_model())
    except Exception as exc:  # noqa: BLE001 - no LLM is honest not_applicable
        return _not_applicable(sha, stage_dir, f"LLM call failed: {exc}", {})

    script_src, meta = extract_script(response)
    _write_json(stage_dir / "00-generation.json", meta)
    if not meta.get("parse_ok"):
        return _not_applicable(sha, stage_dir,
                               meta.get("reason") or "generation not parseable", meta)
    if meta.get("applicability") == "not_applicable" or not script_src:
        return _not_applicable(
            sha, stage_dir, meta.get("reason") or "model declared no extraction applies",
            meta,
        )

    script_path = stage_dir / "03-generated.py"
    out_dir = stage_dir / "run"
    attempts: list[dict] = []
    script_src_final = script_src
    meta_final = meta
    prompt_final = prompt
    execution: dict = {}
    verification: dict = {}
    artifacts: list[dict] = []
    note = ""
    syntax_ok = True

    # Attempt loop: the first pass, plus ONE bounded correction when the script
    # produced no verified claim. This is the "scripts have a feedback loop"
    # half of #11 - the model sees what its own script actually printed.
    for attempt in (1, 2):
        script_path.write_text(script_src_final + "\n", encoding="utf-8")
        try:
            compile(script_src_final, str(script_path), "exec")
        except SyntaxError as exc:
            syntax_ok = False
            attempts.append({"attempt": attempt, "syntax_error": str(exc)[:300]})
            if attempt == 1:
                try:
                    response = llm_judge(
                        _corrective_prompt(prompt, script_src_final, {"rc": -1,
                                                                    "stdout": "",
                                                                    "stderr": f"SyntaxError: {exc}"},
                                           {}),
                        model=get_llm_model(),
                    )
                    script_src_final, meta_final = extract_script(response)
                except Exception:
                    break
                continue
            break
        if out_dir.exists():
            shutil.rmtree(out_dir, ignore_errors=True)
        out_dir.mkdir(parents=True, exist_ok=True)
        execution = run_generated_script(script_path, sample, out_dir)
        _write_json(stage_dir / f"04-execution{'' if attempt == 1 else '-retry'}.json",
                    execution)
        artifacts, note = _result_artifacts(out_dir, execution)
        verification = verify_claims(sample, artifacts, prompt_final, script_src_final)
        verification["result_source"] = note
        _write_json(stage_dir / f"05-verification{'' if attempt == 1 else '-retry'}.json",
                    verification)
        attempts.append({
            "attempt": attempt,
            "rc": execution.get("rc"),
            "claims_total": verification["claims_total"],
            "claims_verified": verification["claims_verified"],
            "independence": verification["independence"],
            "script_sha256": _sha256_bytes(script_src_final.encode("utf-8"))[:16],
        })
        if verification["claims_total"] > 0 or attempt == 2:
            break
        # Zero claims: one corrective pass, unless the script declined outright.
        if _script_declined(execution):
            break
        try:
            response = llm_judge(
                _corrective_prompt(prompt_final, script_src_final, execution, verification),
                model=get_llm_model(),
            )
        except Exception:
            break
        retry_src, meta_final = extract_script(response)
        if not retry_src:
            break
        script_src_final, prompt_final = retry_src, prompt_final

    declined = _script_declined(execution) if execution else ""
    if declined:
        summary = _not_applicable(sha, stage_dir, f"generated script: {declined}",
                                 meta_final)
        summary["attempts"] = attempts
        summary["source_warnings"] = source_warnings(script_src_final)
        _write_json(stage_dir / SUMMARY_NAME, summary)
        return summary

    # Honest taxonomy, fixed 2026-09-27 after the six-sample campaign showed a
    # single flag poisoning the outcome: a syntax error on attempt 1 used to force
    # status="failed" even when the correction pass ran fine (fgg_js reported
    # "failed" while it had 2 re-derived artifacts). Per-attempt state only:
    #   ran             the last attempt executed and produced >= 1 claim
    #   not_applicable  the last attempt ran and found nothing, or the model never
    #                   produced runnable code (unparseable) - nothing failed in
    #                   the pipeline, so this is not a failure
    #   failed          the last attempt's script ran and errored (rc != 0)
    last = attempts[-1] if attempts else {}
    last_syntax_ok = "syntax_error" not in last
    last_rc = last.get("rc")
    claims = int(verification.get("claims_total", 0) or 0)
    not_applicable_reason = ""
    if not last_syntax_ok:
        not_applicable_reason = (
            f"generated script was not valid Python after {len(attempts)} attempt(s): "
            f"{last.get('syntax_error')}"
        )
    elif last_rc == 0 and claims == 0:
        not_applicable_reason = (
            "the script ran but claimed no extractable artifact"
            + (f" ({note})" if note else "")
        )
    if not_applicable_reason:
        summary = _not_applicable(sha, stage_dir, not_applicable_reason, meta_final)
        summary["attempts"] = attempts
        summary["syntax_ok"] = last_syntax_ok
        summary["source_warnings"] = source_warnings(script_src_final)
        _write_json(stage_dir / SUMMARY_NAME, summary)
        return summary

    status = "ran" if last_rc == 0 else "failed"
    summary = {
        "schema": SCHEMA,
        "sha256": sha,
        "status": status,
        # Honest gate: green only when the script ran AND at least one claim was
        # re-derived. Never touches the verdict either way.
        "ok": status == "ran" and claims > 0
              and int(verification.get("claims_verified", 0) or 0) > 0,
        "generated": True,
        "targets": meta_final.get("targets") or meta.get("targets") or [],
        "script_path": str(script_path),
        "script_sha256": _sha256_bytes(script_src_final.encode("utf-8")),
        "prompt_sha256": _sha256_bytes(prompt.encode("utf-8")),
        "attempts": attempts,
        "source_warnings": source_warnings(script_src_final),
        "syntax_ok": last_syntax_ok,
        "execution": {k: execution.get(k) for k in
                      ("rc", "timed_out", "elapsed_s", "network_isolation",
                       "interpreter_isolated")},
        "artifacts_total": verification.get("claims_total", 0),
        "artifacts_verified": verification.get("claims_verified", 0),
        "artifacts_unverified": verification.get("claims_unverified", 0),
        "artifacts_method_unsupported": verification.get("claims_method_unsupported", 0),
        "independence": verification.get("independence", "no_claims"),
        "input_read": bool(verification.get("input_read")),
        "hardcoded_output_literals": verification.get("hardcoded_output_literals", 0),
        "values_pre_seeded_in_prompt": verification.get("values_pre_seeded_in_prompt", 0),
        "result_source": note,
        "verified_artifacts": [
            {k: a[k] for k in ("kind", "value_preview", "offset", "method", "basis",
                               "pre_seeded_in_prompt")}
            for a in verification.get("artifacts", []) if a.get("verified")
        ],
        "llm": meta_final.get("llm") or meta.get("llm"),
        "elapsed_s": round(time.time() - t0, 1),
        "provenance": revai_provenance(),
        "finished_at": _utc(),
    }
    _write_json(stage_dir / SUMMARY_NAME, summary)
    print(
        f"[artifact_gen] {status} rc={execution.get('rc')} "
        f"verified={summary['artifacts_verified']}/{summary['artifacts_total']} "
        f"independence={summary['independence']} attempts={len(attempts)} "
        f"({summary['elapsed_s']}s)",
        flush=True,
    )
    return summary


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("sha256")
    ap.add_argument("--force", action="store_true",
                    help="run even when REVAI_ENABLE_ARTIFACT_GEN is not set")
    args = ap.parse_args()
    summary = run_stage(args.sha256, force=args.force)
    # The stage never blocks a run: it is opt-in, presence-gated and cannot gate
    # the verdict, so every outcome (ran / skipped / not_applicable / failed)
    # exits 0. Failures live in artifact-gen.json, honestly.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
