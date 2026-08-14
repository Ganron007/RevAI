## Tool evidence (stage=quick_scan, signal-prioritized)
<!-- stage: quick_scan | sha=f3e743c919c1deaf | packaging=v6.1 -->

## MalCat evidence
  File: type=text/utf8, architecture=NONE, entropy=5.74, sha256=f3e743c919c1deaf5108d361c4ff610187606f450fabda0bea3786d4063511b1
  * Constants/crypto (1): crypto::Base64
  Strings (other, 300 items, omitted)

## capa
  incomplete: CAPA supports PE/ELF/Mach-O only (got text)


## pe_imports (0 imports, 0 high-signal)
  (no high-signal APIs matched)

## YARA matches (6)
  Rules: domain, possible_includes_base64_packed_functions, function_through_object, contains_base64, BASE64_table, android_meterpreter

## floss
  error: FLOSS supports PE only (got text)


## revai_tools_sec
  skipped: not_applicable:text


## revai_tools_sinks
  skipped: not_applicable:text


<!-- evidence_assembler: used 673/28000 chars across 7 tools -->