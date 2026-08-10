# Agent-Loop Discipline

The agentic deep dive enforces four loop-discipline behaviors. They were inspired by
the benchmark evaluation methodology — the same ideas about agentic tool use,
applied to our own pipeline so the analysis converges, stays evidence-grounded, and
never wastes budget.

All four run in both agentic engines (`langgraph`, the default, and `custom`) and
appear in the deep-dive JSON (`redundant_calls`, `failure_taxonomy`).

## The four behaviors

| Behavior | What it does | Env flag (default) |
| :--- | :--- | :--- |
| **Budget warnings** | Converges the planner — warns at half-budget and when ≤2 tool calls remain, via the tool-output channel the model reads each turn | `REVAI_BUDGET_WARNINGS=1` |
| **Redundant-call detection** | Identical `(tool, args)` calls are skipped with a nudge instead of re-executed; waste is counted | `REVAI_REDUNDANT_NUDGE=1` |
| **Hallucination check** | `final_answer` claims must have supporting tool evidence in the run history; one grounded correction pass if not | `REVAI_HALLUCINATION_CHECK=1` |
| **Failure taxonomy** | Post-run classification into 6 buckets | `REVAI_FAILURE_TAXONOMY=1` |

## 1. Budget warnings

The deep-dive planner has a bounded tool budget. To prevent it from burning the entire
budget on exploratory queries, the loop injects convergence warnings:

- At **half-budget**: "prioritize the highest-value evidence; stop exploratory queries."
- At **≤2 calls remaining**: "prepare your final_answer NOW using the evidence collected."

In the `langgraph` engine these warnings are delivered through the **tool-output channel**
(a note appended to each tool result, which the model reads on its next turn); in the
`custom` engine they are injected into the planner prompt at the matching step.

## 2. Redundant-call detection

The loop tracks a signature of every `(tool, args)` call. If the planner issues an
identical call again, it is **skipped** with a nudge ("analyze the output you already
have or move on") instead of re-executed. The waste count is recorded as
`redundant_calls` in the deep-dive JSON.

## 3. Hallucination check

Before a `final_answer` is accepted, every claim in `key_evidence` is validated for
token overlap against the tool findings + history collected during the run. A claim
with **no supporting tool evidence** causes the final answer to be rejected once, with
a corrective prompt; the planner gets **one grounded correction pass** (in `langgraph`,
the verdict is re-derived strictly from evidence). This is the same anti-hallucination
principle used in evaluation benchmarks, applied at analysis time.

## 4. Failure taxonomy

After the run, failures are classified into six buckets and written to
`failure_taxonomy` in the deep-dive JSON:

1. `json_format_violation` — planner returned unparsable/empty JSON
2. `tool_misuse` — invalid tool names, unknown action types, redundant calls
3. `early_termination` — run ended without a complete final answer
4. `api_hallucination` — final answer rejected for ungrounded claims
5. `byte_level_reasoning` — syscall/opcode/shellcode-level misinterpretation signals
6. `control_flow_misinterpretation` — CFF/opaque-predicate/dispatcher signals

Each entry records `counts`, the `active` buckets, a `primary` bucket, and a `clean`
flag — so a red gate shows *why* the analysis failed, not just that it did.

## Configuration

Each behavior is independently env-gated and defaults **ON**:

```bash
export REVAI_BUDGET_WARNINGS=1
export REVAI_REDUNDANT_NUDGE=1
export REVAI_HALLUCINATION_CHECK=1
export REVAI_FAILURE_TAXONOMY=1
```

Set any to `0` to disable that behavior.
