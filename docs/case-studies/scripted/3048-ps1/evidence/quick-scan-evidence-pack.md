## Tool evidence (stage=quick_scan, signal-prioritized)
<!-- stage: quick_scan | sha=14a42d6418b38103 | packaging=v6.1 -->

## MalCat evidence
  File: type=text/utf8, architecture=NONE, entropy=148, sha256=14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2
  YARA (signal): Powershell
  YARA (info, 1 total): RunShell
  Strings/suspicious (2 total): powershell
  Strings/apis (9 total): StreamReader, ProcessStartInfo, UseShellExecute, WindowsPowerShell, MemoryStream, CreateNoWindow, FileName, ReadToEnd, WindowStyle
  Strings (other, 98 items, omitted)

## capa
  incomplete: CAPA supports PE/ELF/Mach-O only (got text)


## pe_imports (0 imports, 0 high-signal)
  (no high-signal APIs matched)

## YARA matches (5)
  Rules: domain, powershell, IP, contains_base64, Antivirus

## floss
  error: FLOSS supports PE only (got text)


<!-- evidence_assembler: used 713/28000 chars across 5 tools -->