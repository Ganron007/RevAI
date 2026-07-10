#!/usr/bin/env python3
"""
eval_recovery.py — ground-truth scoring harness for function recovery.

Usage:
  python3 /opt/cadre-v4-tools/eval_recovery.py \
      --truth truth.json --recovered /opt/samples/logs/<sha>/function_recovery.json

Truth JSON schema:
  {
    "<function_address_decimal_or_hex>": {
      "name": "parse_http_header",
      "parameters": [{"name": "request", "type": "const char *"}],
      "return_type": "int",
      "struct_fields": {"0": "method", "8": "path"}
    }
  }

Metrics written:
  * symbol_accuracy  — word-based Jaccard of function names
  * type_accuracy    — param/return type overlap
  * struct_precision/recall — field offsets matched by name
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


def _addr_key(addr: Any) -> str:
    try:
        return str(int(addr, 0) if isinstance(addr, str) and addr.startswith("0x") else int(addr))
    except Exception:
        return str(addr)


def tokenize(name: str) -> set[str]:
    return set(re.findall(r"[a-zA-Z0-9]+", name.lower()))


def jaccard(a: set, b: set) -> float:
    if not a and not b:
        return 1.0
    union = a | b
    if not union:
        return 0.0
    return len(a & b) / len(union)


def score_name(truth_name: str, recovered_name: str) -> float:
    if not truth_name or not recovered_name:
        return 0.0
    t = tokenize(truth_name)
    r = tokenize(recovered_name)
    return jaccard(t, r)


def score_types(truth: dict, rec: dict) -> float:
    scores = []
    if truth.get("return_type") and rec.get("return_type"):
        scores.append(1.0 if truth["return_type"].strip() == rec["return_type"].strip() else 0.0)
    truth_params = truth.get("parameters") or []
    rec_params = rec.get("parameters") or []
    if truth_params or rec_params:
        matched = 0
        for tp, rp in zip(truth_params, rec_params):
            if (tp.get("type") or "").strip() == (rp.get("type") or "").strip():
                matched += 1.5
            if (tp.get("name") or "").strip() == (rp.get("name") or "").strip():
                matched += 0.5
        denom = max(len(truth_params), len(rec_params)) * 2
        scores.append(matched / denom if denom else 1.0)
    return sum(scores) / len(scores) if scores else 0.0


def score_structs(truth: dict, rec_structs: list[dict]) -> tuple[float, float]:
    truth_fields = truth.get("struct_fields") or {}
    if not truth_fields:
        return 0.0, 0.0
    recovered_offsets: dict[str, str] = {}
    for s in rec_structs:
        for f in s.get("fields", []):
            recovered_offsets[str(f["offset"])] = f.get("suggested_name", "")
    tp, fp, fn = 0, 0, 0
    for off, name in truth_fields.items():
        if str(off) in recovered_offsets:
            if recovered_offsets[str(off)].lower() == name.lower():
                tp += 1
            else:
                fp += 1
                fn += 1
        else:
            fn += 1
    for off in recovered_offsets:
        if str(off) not in truth_fields:
            fp += 1
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    return precision, recall


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--truth", required=True, type=Path)
    ap.add_argument("--recovered", required=True, type=Path)
    ap.add_argument("--output", type=Path)
    args = ap.parse_args()

    truth = json.loads(args.truth.read_text())
    recovered = json.loads(args.recovered.read_text())
    rec_by_addr = {_addr_key(r.get("function_address")): r for r in recovered.get("function_results", [])}

    name_scores = []
    type_scores = []
    struct_precisions = []
    struct_recalls = []
    per_function = []

    for addr, t in truth.items():
        key = _addr_key(addr)
        r = rec_by_addr.get(key)
        if not r:
            per_function.append({"address": key, "name_score": 0.0, "found": False})
            name_scores.append(0.0)
            continue
        ns = score_name(t.get("name", ""), r.get("function_name", ""))
        ts = score_types(t, r)
        sp, sr = score_structs(t, recovered.get("synthesis", {}).get("proposed_structs", []))
        name_scores.append(ns)
        type_scores.append(ts)
        if sp or sr:
            struct_precisions.append(sp)
            struct_recalls.append(sr)
        per_function.append({
            "address": key,
            "truth_name": t.get("name"),
            "recovered_name": r.get("function_name"),
            "name_score": round(ns, 3),
            "type_score": round(ts, 3),
            "struct_precision": round(sp, 3) if sp else None,
            "struct_recall": round(sr, 3) if sr else None,
            "found": True,
        })

    report = {
        "truth_count": len(truth),
        "recovered_count": len(rec_by_addr),
        "symbol_accuracy": round(sum(name_scores) / len(name_scores), 3) if name_scores else 0.0,
        "type_accuracy": round(sum(type_scores) / len(type_scores), 3) if type_scores else 0.0,
        "struct_precision": round(sum(struct_precisions) / len(struct_precisions), 3) if struct_precisions else 0.0,
        "struct_recall": round(sum(struct_recalls) / len(struct_recalls), 3) if struct_recalls else 0.0,
        "per_function": per_function,
    }

    print(json.dumps(report, indent=2))
    if args.output:
        args.output.write_text(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
