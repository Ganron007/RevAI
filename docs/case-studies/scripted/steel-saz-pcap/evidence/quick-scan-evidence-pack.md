## Tool evidence (stage=quick_scan, signal-prioritized)
<!-- stage: quick_scan | sha=58c043e134dc09b2 | packaging=v6.1 -->

## MalCat evidence
  File: type=ZIP, architecture=NONE, entropy=224, sha256=58c043e134dc09b27e86973d327ab252745662f12231695f6eeb5c5deb9b691b
  Anomalies (1): LocalFileAndCentralDirectoryFieldDifferent×144 (headers)
  YARA (info, 1 total): ValuableFileExtensions
  Strings (other, 300 items, omitted)
  Virtual files (26): raw/1_c.txt, raw/1_s.txt, raw/1_m.xml, raw/2_c.txt, raw/2_s.txt, raw/2_m.xml, raw/3_c.txt, raw/3_s.txt, raw/3_m.xml, raw/4_c.txt
  Recovered structures (55): LocalFile, LocalFile, LocalFile, LocalFile, LocalFile, LocalFile, LocalFile, LocalFile, LocalFile, LocalFile, LocalFile, LocalFile, LocalFile, LocalFile, LocalFile

## capa
  incomplete: CAPA supports PE/ELF/Mach-O only (got ooxml)


## pe_imports (0 imports, 0 high-signal)
  (no high-signal APIs matched)

## YARA matches (4)
  Rules: domain, IP, contains_base64, url

## floss
  error: FLOSS supports PE only (got ooxml)


<!-- evidence_assembler: used 896/28000 chars across 5 tools -->