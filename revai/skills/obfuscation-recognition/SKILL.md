name: obfuscation-recognition
version: 1
covers: [control flow flattening, mixed boolean arithmetic, string encryption, switch dispatch, VM detection, obfuscation as neutral]
does_not_cover: [deobfuscation implementation, symbolic execution tuning, specific protector VM bytecode]

# Recognising obfuscation

**Provenance and attribution note.** Extracted from the internal knowledge base;
`sources.jsonl` records the exact chunks with source path and line range so an
operator with KB access can re-verify. Those paths are **not resolvable in this
public repository**; the citations are provenance metadata, not links.

## When to load

When a function is hard to read for structural reasons rather than because the
logic is complex — and before concluding anything about intent from the fact that
it is hard to read.

## The rule first: obfuscation is NEUTRAL

This is the calibration contract and it outranks every technique below.
Obfuscation, packing, virtualisation and anti-analysis are evidence of *effort*,
never of *malice*. A protected build can be a licensed commercial product or a
researcher's CTF challenge. It changes how hard the sample is to read; it never
changes what a read of it means.

If the only thing pointing at "malicious" is that the sample is obfuscated, the
verdict is not supported.

## The tells, and the standard attack for each

1. **Control-flow flattening.** A dispatch block that reassigns a *state* variable
   and switches on it, where each case sets the next state. Tell: one predecessor
   dominates many blocks that all set a common variable; back-edges cluster on the
   dispatcher. Attack: recover the state values, order the blocks by them. Our
   `cff_deflatten` detector flags the shape; a detected flattening is a lead, not
   a result.
2. **Mixed boolean arithmetic.** Arithmetic identities that compute a simple
   expression through bitwise noise. Tell: long chains of `xor`/`and`/`or`/`mul`
   with constants, no side effects, feeding a comparison. Attack: a solver
   (`z3_solve`) reduces the expression; treat the result as recovered logic, not
   as the original source.
3. **String encryption.** No useful plaintext strings, but a short routine called
   with a pointer and a length. Tell: the loop with the xor/add and the stack
   buffer. Attack: decrypt at the call site; our oracle's decoded strings are
   evidence. A decoded string is only as good as the run that produced it — cite
   the emulation, not the source.
4. **Switch dispatch / jump tables.** An indirect jump through a computed index
   where a call graph would be. Tell: a table in `.rdata` indexed by a register.
   Attack: read the table, enumerate targets. This is not obfuscation per se —
   common in compilers and in CFF alike — so check for the state variable before
   calling it flattening.
5. **Anti-debug / anti-VM.** `IsDebuggerPresent`, `rdtsc` pairs, `cpuid` checks,
   timing loops. Tell: these are *named APIs and instructions*, easy to find and
   easy to over-read. Their presence means the author expected analysis; it does
   not say why.

## Stop conditions

- The technique is identified and the corresponding attack has been attempted.
- The obfuscation defeats the attempt. Report *not reconstructed*, with the
  technique named. A named defeat is a result; an unnamed one is a gap.
- You are about to spend your remaining budget on deobfuscation that cannot change
  the conclusion — stop and say so.

## Honesty rules

- Never report obfuscated code's *apparent* behaviour as the sample's behaviour.
  A flattening-resistant function that looks like a downloader may be decoy code.
- A deobfuscated region is a reconstruction. Cite the pass that produced it.
- "Anti-analysis present" is a fact. "Trying to evade me" is a motive claim and it
  is not supported by the fact.
- If a detector fires, the honest phrasing is that a *shape* matched, not that the
  technique is definitely present.

## What this skill does NOT cover

- Writing deobfuscation passes; our `cff_deflatten` and solver wrappers do that and
  their calibration is documented with them.
- Protector VM bytecode (VMProtect's handler tables, a custom VM's dispatch).
- Anti-debug bypass technique by design — we do not need to defeat the protection
  to say what it is.
