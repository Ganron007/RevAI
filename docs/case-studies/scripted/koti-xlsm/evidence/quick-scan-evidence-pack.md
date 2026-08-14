## Tool evidence (stage=quick_scan, signal-prioritized)
<!-- stage: quick_scan | sha=8e516c5e0ca2a7ff | packaging=v6.1 -->

## MalCat evidence
  File: type=ZIP, architecture=NONE, entropy=7.56, sha256=8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e
  Strings (other, 300 items, omitted)
  Virtual files (24): [Content_Types].xml, _rels/.rels, xl/_rels/workbook.xml.rels, xl/workbook.xml, xl/theme/theme1.xml, xl/macrosheets/sheet1.xml, xl/worksheets/_rels/sheet1.xml.rels, xl/macrosheets/_rels/sheet1.xml.rels, xl/worksheets/_rels/sheet2.xml.rels, xl/drawings/_rels/drawing1.xml.rels
  Recovered structures (49): LocalFile, LocalFile, LocalFile, LocalFile, LocalFile, LocalFile, LocalFile, LocalFile, LocalFile, LocalFile, LocalFile, LocalFile, LocalFile, LocalFile, LocalFile

## capa
  incomplete: CAPA supports PE/ELF/Mach-O only (got ooxml)


## pe_imports (0 imports, 0 high-signal)
  (no high-signal APIs matched)

## YARA matches (2)
  Rules: domain, contains_base64

## floss
  error: FLOSS supports PE only (got ooxml)


## revai_tools_sec
  skipped: not_applicable:ooxml


## revai_tools_sinks
  skipped: not_applicable:ooxml


<!-- evidence_assembler: used 1017/28000 chars across 7 tools -->