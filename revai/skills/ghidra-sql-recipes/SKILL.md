name: ghidra-sql-recipes
version: 1
covers: [ghidra_sql_client, ida_sql_client, query patterns, schema navigation]
does_not_cover: [sqlite dialect reference, Ghidra scripting in Java or Python, headless analyse invocation]

# Ghidra / IDA SQL recipes

**Provenance.** This skill is derived from *this repository's own* SQL usage —
`ghidra_sql_client.py` and the deep-dive tool implementations — not from the
internal knowledge base. It therefore carries **no external citations**: the
sources are our code, and the honest statement is that the procedure is
maintained here rather than imported from elsewhere.

## When to load

Before writing any query against `ghidra_query` or `ida_query`. Also whenever a
query returns zero rows and you are unsure whether the schema or the spelling is
wrong.

## Why this skill exists

The full schema dump used to be shipped in *every* deep-dive prompt. That is the
anti-pattern: ~2,000 tokens per call, across up to 17 sections, on every sample,
to serve a query the agent writes maybe twice. This skill is loaded on demand
instead, and the prompt carries only the one-line index.

## Procedure

1. **Enumerate before you query.** Start from the address tables the client
   already exposes, not from a hand-written SQL join. `ghidra_query` and
   `ida_query` wrap the bridges; the wrappers exist because the raw SQL schema
   changed between ghidrasql releases and we re-validated our queries each time.
2. **Prefer the wrapper to raw SQL.** If a wrapper answers the question, use it.
   Raw SQL is for questions the wrapper does not cover, and a raw query is a
   claim about the schema that must be re-checked after every bridge upgrade.
3. **Spelling tolerance.** A symbol as written by a disassembler is the input.
   `api_lookup` accepts the spelling a disassembler emits (`__imp_`, `@N`, A/W,
   Nt/Zw). Do what it does: strip decoration before comparing.
4. **Zero rows is a finding, not a failure.** If a query returns nothing, the
   honest report is "not found", with the query you ran. Do not substitute
   recollection for an empty result.

## Stop conditions

- The wrapper answered the question.
- You have enumerated the candidate set and it is empty (report "not found").
- You are about to write a third query for the same fact — that is the signal to
  change tool, not to re-tune the SQL.

## Honesty rules

- A query result is evidence. A query you *intend* to write is not. Never
  describe a table's contents without having selected from it in this run.
- Record the query in the evidence citation. `{source, query_or_table,
  row_or_rule, why}` — the `query_or_table` field is exactly this.
- If the bridge is unavailable (soft-fail), say so. An absent bridge means the
  SQL evidence does not exist for this run; it does not mean the sample lacks
  the feature.

## What this skill does NOT cover

- The SQLite dialect itself.
- Ghidra scripting (Java/Python) — we do not execute model-authored code inside
  the analysis environment; see plan item #29 for why that was rejected.
- Headless `analyzeHeadless` invocation; that is intake's job.
