## Tool evidence (stage=quick_scan, signal-prioritized)
<!-- stage: quick_scan | sha=385966f3d6be7b23 | packaging=v6.1 -->

## MalCat evidence
  File: type=ZIP, architecture=NONE, entropy=215, sha256=385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73
  Strings (other, 287 items, omitted)
  Virtual files (15): [Content_Types].xml, docProps/app.xml, docProps/core.xml, word/document.xml, word/fontTable.xml, word/settings.xml, word/styles.xml, word/vbaData.xml, word/vbaProject.bin, word/webSettings.xml
  Recovered structures (31): LocalFile, LocalFile, LocalFile, LocalFile, LocalFile, LocalFile, LocalFile, LocalFile, LocalFile, LocalFile, LocalFile, LocalFile, LocalFile, LocalFile, LocalFile

## capa
  incomplete: CAPA supports PE/ELF/Mach-O only (got ooxml)


## pe_imports (0 imports, 0 high-signal)
  (no high-signal APIs matched)

## YARA matches (6)
  Rules: domain, IP, docx_macro, contains_base64, Contains_VBA_macro_code, office_document_vba

## floss
  error: FLOSS supports PE only (got ooxml)


<!-- evidence_assembler: used 892/28000 chars across 5 tools -->