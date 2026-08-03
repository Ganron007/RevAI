# Sample Pool — InTheWild.0406 (150 samples)

Selected from `G:\MW_Samples\InTheWild.0406` (20,000 raw PE samples, no extensions,
filename format `YYYY-MM-DD_<md5>_<family1>_<family2>_...`).

| Category | Size range | Count | Families | Manifest |
|----------|-----------|-------|----------|----------|
| small | < 1 MB | 50 | 29 | [manifest_small.txt](manifest_small.txt) |
| mid | 1–3 MB | 50 | 32 | [manifest_mid.txt](manifest_mid.txt) |
| large | > 3 MB | 50 | 34 | [manifest_large.txt](manifest_large.txt) |

**Selection:** round-robin across families (alphabetical) so each category covers
the widest family diversity. All entries are MZ (PE) signatures.

**Deployment on the analysis VM:** `/opt/samples/incoming/manual-drop/pool/{small,mid,large}/`

**Manifest format:** `<filename>\t<bytes>`
