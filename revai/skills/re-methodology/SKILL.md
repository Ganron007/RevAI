name: re-methodology
version: 1
covers: [static analysis sequence, entry point, call graph, sinks, data flow, stop conditions]
does_not_cover: [debugging workflow, dynamic analysis, kernel-mode analysis, specific packer internals]

# Reverse-engineering methodology

**Provenance and attribution note.** This procedure was extracted from the internal
knowledge base. `sources.jsonl` records the exact chunks it came from, with chunk
id, source path and line range, so an operator with KB access can re-verify every
line. Those paths are **not resolvable in this public repository**; the citations
are provenance metadata, not links.

## When to load

Before any manual walkthrough that will exceed a handful of steps — i.e. before a
deep dive, and before the depth mode. If you are about to decompile a function to
see what it does, load this first.

## The sequence

Work outward from the entry point, and let the evidence decide when to stop. The
order is not arbitrary: each step narrows what the next one has to read.

1. **Establish the container first.** Format, architecture, entry point, sections,
   imports. This is intake and quick_scan's job and it is already done — read the
   artifacts rather than re-deriving. If the sample is packed, stop and load
   `unpack-and-verify`; the rest of this procedure applies to the *unpacked*
   image.
2. **Find the real entry point.** The PE entry point is a starting point, not
   necessarily where execution begins. A DLL with no exports is dispatched by
   whatever loads it; an injected payload begins at the injector's chosen
   address. If the entry point is a thunk, follow it.
3. **Build the call graph from main outward, not inward.** Read main, list its
   callees, read those. A depth-first dive into the first interesting callee is
   how an investigation gets lost in a utility function.
4. **Locate sinks before reading everything.** Network, file, registry, process,
   crypto. Anything the sample can *do* is a sink or a path to one. Use
   `revai_tools_sinks` and the import map rather than reading every function.
5. **Trace the data that reaches a sink.** What is written, where it comes from,
   and whether it is constructed at runtime. Configuration is data; the loader
   that decodes it is code. Both are evidence.
6. **Then, and only then, describe the behaviour.** Step 6 is where a summary is
   written, not where reading stops.

## Stop conditions

This is the part most likely to be skipped, so it is explicit. Stop when any of:

- every capability domain has either evidence or an explicit "not observed"
- the remaining unknowns are all *paid for*: you can say what is unknown, why,
  and what it would cost to resolve
- the next function to read cannot change any conclusion you would draw

Do NOT stop because a step budget ran out. A budget-exhausted run that reports
"complete" is the hollow-success defect. Report the gap instead.

## Honesty rules

- A function you did not read is not a function you understood. "Not observed" is
  a finding; "presumably" is not.
- Obfuscation is neutral. Packed, virtualised or flattened code is not evidence of
  malice — it is evidence of effort. It changes how hard the reading is, never
  what the reading means.
- A name from `api_lookup` is grounding, not proof. It tells you what an API does,
  not that this sample called it for that purpose.
- Cite the query or table for every claim about what the binary contains.

## What this skill does NOT cover

- Debugging (a different sequence, different tools, different failure modes).
- Dynamic analysis; when a detonation pack exists it *widens* scope, it does not
  replace any step here.
- Kernel-mode analysis.
- Specific packer internals — see `unpack-and-verify`.
