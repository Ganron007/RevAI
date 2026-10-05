name: unpack-and-verify
version: 1
covers: [packing detection, unpacking stub, OEP, memory dump, IAT rebuild, re-analysis, honesty rules]
does_not_cover: [specific VMProtect or Themida internals, kernel-mode unpacking, anti-debug bypass]

# Unpack, then verify

**Provenance and attribution note.** Extracted from the internal knowledge base;
`sources.jsonl` records the exact chunks with source path and line range so an
operator with KB access can re-verify. Those paths are **not resolvable in this
public repository**; the citations are provenance metadata, not links.

## When to load

As soon as the packer checklist or entropy says *packed*, and before spending any
effort reading code. Reading packed code produces confident nonsense: what you are
looking at is the unpacker, not the sample.

## The rule this whole skill exists for

**A rebuilt import table is a CLAIM, not an artifact.** Everything below serves
that sentence.

When a tool reconstructs imports from memory, the result is a hypothesis about
what the original table said. It can be wrong in both directions — a thunk
resolved at runtime that the original table never listed, or a genuine import the
reconstruction missed. Treat a rebuilt import exactly as you would treat a model
assertion: it must verify against something else before it enters a report.

## Procedure

1. **Confirm the sample is actually packed.** The packer checklist plus entropy
   plus the import surface. A packed sample often has few imports and high-entropy
   sections; a legitimate packed *stub* has almost no code at all. If it is a stub,
   say so rather than claiming the sample has no capability.
2. **Find the unpacking stub.** The entry point of a packed binary is the stub.
   Look for a decrypt-then-jump shape: a small decode loop followed by a transfer
   of control into the decoded region.
3. **Find the OEP — the original entry point, not the stub.** The standard tells:
   the stub jumps to a real entry point after the last section is written; a
   `popad`/`popfd` sequence restoring a saved register block immediately before a
   far jump is the classic shape. The OEP is where the *original* program begins.
4. **Dump at the OEP, not before.** Dumping mid-decode gives you a partial image
   with a plausible-looking header and nonsense body.
5. **Rebuild the import table** (pe-sieve `/imp`, Scylla-style). Record it as
   reconstructed, with the tool and the dump it came from.
6. **Re-run the static analysis on the dump.** This is the step people skip. The
   dump is a *different binary*; it gets its own hashes, sections and imports. A
   finding attributed to the original sample that was actually made on the dump is
   a provenance error.
7. **Corroborate the rebuilt imports.** Cross-check against: the original import
   surface, the strings, and what the code at the OEP actually references. A
   rebuilt import with no corroboration is reported as *probable*, never as fact.

## Stop conditions

- The OEP is found, the dump is valid (parseable PE, non-zero sections), and the
  rebuilt imports are corroborated.
- The unpacking attempt fails. That is a normal outcome for a protected sample;
  report it as *not unpacked* with the method that failed. Do not report the stub's
  behaviour as the sample's behaviour.
- The dump is dumped but the imports will not rebuild. Report the static findings
  on the dump and state the import reconstruction as unresolved.

## Honesty rules

- Never present the dump's hashes as the sample's.
- Never present a rebuilt import as an observed one.
- "Unpacked successfully" requires a valid dump AND a corroborated import table,
  not just the first half.
- If the unpack pass ran and the sample was not packed, that is fine — record it.

## What this skill does NOT cover

- The internals of VMProtect, Themida or a specific custom packer.
- Kernel-mode unpacking.
- Anti-debug / anti-VM bypass (see `obfuscation-recognition` for the tells, not
  for bypass technique).
- Dynamic unpacking via a debugger; that is the WinRE agentic-dbg path and it is
  optional, not a prerequisite here.
