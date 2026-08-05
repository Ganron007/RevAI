# Why Malcat's capa engine?

Capability detection (capa) is the backbone of triage. The pipeline uses **Malcat's
native capa engine** (`malcat.capa.py`) as the primary capability detector, with
Mandiant capa as fallback — not the other way around. This is backed by a measured
10-sample benchmark on real malware:

| # | Size | Malcat | Mandiant capa | capa-rs |
|---|------|--------|---------------|---------|
| 0 | 0.03 MB | 41r / 0.95s | 42r / 0.62s | 22r / 0.33s |
| 1 | 0.12 MB | 95r / 1.16s | 104r / 22.2s | FAIL (SMDA) |
| 2 | 0.33 MB | 45r / 1.05s | 51r / 9.9s | FAIL |
| 3 | 0.53 MB | 87r / 1.88s | 96r / 80.5s | FAIL |
| 4 | 1.38 MB | 15r / 1.37s | 18r / 29.0s | 8r / 4.8s |
| 5 | 2.36 MB | 9r / 1.37s | 11r / 22.1s | FAIL |
| 6 | 3.12 MB | **101r / 5.0s** | FAIL / 300s TIMEOUT | FAIL |
| 7 | 3.56 MB | 81r / 3.8s | 90r / 145s | FAIL |
| 8 | 5.02 MB | **17r / 3.0s** | FAIL / 300s TIMEOUT | FAIL |
| 9 | 8.01 MB | **22r / 6.7s** | FAIL / 300s TIMEOUT | FAIL |

## Verdict

| Metric | Winner |
|--------|--------|
| **Speed** | **Malcat** — ~1–7s on all 10 samples; Mandiant 0.6–145s when it finishes, 3/10 timeout at 300s |
| **Reliability** | **Malcat** — 10/10 OK; Mandiant 7/10; capa-rs 2/10 (SMDA/parse failures) |
| **Rule count (when Mandiant completes)** | Mandiant slightly richer (~+5–10%) — different extractors, not identical corpora |
| **Usable signal on hard samples (#6/#8/#9)** | **Malcat only** |

Malcat's engine is a **native compiled scanner**: it never times out on large,
obfuscated, or installer-packed binaries (Inno Setup, NSIS, packers) that stall the
stock Mandiant Python engine. This keeps the quality gate green on hard samples
instead of falling back to stubs. Mandiant capa remains available as a fallback via
`CADRE_CAPA_ENGINE=malcat|capa-rs|capa`.

> **Malcat is optional — recommended, never required.** It is a commercial tool, and we
> respect that not everyone can use it. Without Malcat the pipeline **soft-fails**
> gracefully: capa falls back to Mandiant, Malcat triage sections are reported as
> unavailable, and the quality gate stays honest (soft-failure, not green).
> Install notes: [`docs/PREREQUISITES.md`](PREREQUISITES.md) → "Recommended (optional): Malcat".
> `install/setup-remnux.sh` auto-installs it if the archive is present at
> `internal/malcat.zip`, and skips with a warning otherwise.
