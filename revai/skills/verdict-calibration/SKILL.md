name: verdict-calibration
version: 1
covers: [calibration contract, malicious verdict requirements, neutral observations, behavioral intent evidence]
does_not_cover: [score thresholds, family naming, confidence intervals]

# Verdict calibration

**Provenance and attribution note.** The calibration contract is owned by *this
repository* (`revai/report_quality.py`) and is reproduced here verbatim so it is
cited rather than re-summarised. The internal knowledge base contributed only
supporting material on classifying intent from behaviour; `sources.jsonl` records
both, and marks which is which. The KB paths are **not resolvable in this public
repository** — the citations are provenance metadata, not links.

## When to load

Before rendering any judgment about the sample — a triage verdict, a deep-dive
judgment, a final agentic judge, or any sentence in a report that says *malicious*.

## The contract

**Obfuscation, protection, packing and virtualisation are NEUTRAL.** They are
evidence of effort, never of intent.

**A malicious verdict requires behavioural-intent evidence.** At least one of:

- network behaviour (C2, exfiltration, beaconing)
- persistence (registry run key, service, scheduled task, bootkit)
- injection or process manipulation
- credential access
- data destruction or ransomware behaviour
- collection and staging

**Not malicious indicators, no matter how they look:**

- generic YARA matches on a domain, a base64 blob, or a URL pattern
- high entropy
- zero imports
- obfuscation of any kind
- "looks like a packer"

A sample that is protected, has no imports and one base64 blob is **suspicious at
most** until behaviour says otherwise.

## Procedure

1. Load the capability map. For each capability, ask: is there behavioural
   evidence, or only a structural tell?
2. Discard the structural tells for the *verdict*. Keep them for the report's
   description of the sample — they are true and useful, they are just not intent.
3. If no behavioural evidence exists, the verdict is not malicious. It may be
   suspicious; say why.
4. Cross-check the triage verdict, the deep-dive verdict and the final agentic
   verdict against the same contract. A disagreement between them is a finding,
   not something to average away.

## Stop conditions

- Every capability is classified as behavioural-evidenced or structural-only.
- The verdict follows from the behavioural set alone.
- You can state, in one sentence, which behavioural evidence carries the verdict.
  If you cannot, the verdict is not supported.

## Honesty rules

- A behavioural YARA or capa rule IS intent evidence; a generic one is not. The
  distinction is whether the rule describes something the sample *does* or
  something it merely *contains*.
- Never raise the verdict because the sample is hard to analyse. Difficulty is not
  malice.
- Never lower the verdict to avoid a red audit. The gate exists to catch exactly
  that, and a green run reached by weakening the standard is worse than a red one.
- If the evidence is ambiguous, report the ambiguity. A calibrated "suspicious,
  behavioural evidence absent" is a correct and useful answer.

## What this skill does NOT cover

- Numeric score thresholds (those live with the scoring code).
- Family naming and attribution.
- Confidence intervals; our outputs are categorical plus the evidence that
  produced them.
