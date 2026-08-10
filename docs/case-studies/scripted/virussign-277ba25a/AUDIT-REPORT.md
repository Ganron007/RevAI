# Pipeline AUDIT-REPORT — `e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2`

> Public-showcase grade evidence pack: tools, RAG, LLM, REPORT-MASTER-v2/v3.

- **Mode:** single
- **Audited at:** 2026-08-10T00:56:27.613195+00:00
- **Provenance:** `unknown` · engine `langgraph` · flags: budget=True redundant=True hallucination=True taxonomy=True · 2026-08-10 00:56:27 UTC
- **all_green:** `True`
- **Strict standard:** `False`
- **Session mode:** `single`
- **Sample:** `/opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir`
- **Showcase pack:** `/opt/samples/logs/_showcase_audits/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2`

## Stage scoreboard

| Stage | OK |
|-------|----|
| intake | ok |
| quick_scan | ok |
| deep_dive | ok |
| yara_gen | ok |
| publish | ok |

---

_No tool retries occurred during this run._

## Cross-cutting — LLM / Reports

### LLM stages

#### `triage`

- source=`llm_judge` model=`mimo-v2.5` verdict=`suspicious` confidence=`40`
- key_evidence_count=`4`

```json
{
  "verdict": "suspicious",
  "score": 40,
  "family_guess": "packer/protector (unspecified)",
  "cross_engine_notes": "Function counts diverge significantly across tools (malcat=15, ghidra=365, ida=8), making coverage unreliable. Focus on malcat decompilation for runtime behavior. Obfuscation and packing indicators are present but neutral per calibration; no clear behavioral-intent evidence (e.g., C2, persistence, credential theft) was found.",
  "key_evidence": [
    {
      "source": "capa",
      "query_or_table": "rule 'encrypt data using RC4 via SystemFunction033'",
      "row_or_rule": "top rule",
      "why": "Identifies defense evasion via RC4 encryption, a common technique in malware for obfuscation or data protection, but also used in benign protectors. Without evidence of malicious data encryption (e.g., ransomware), this remains suspicious."
    },
    {
      "source": "malcat",
      "query_or_table": "Decompilations",
      "row_or_rule": "function sub_474643 at address 474179",
      "why": "Shows XOR decryption loop unpacking a large buffer (0x401400) and executing decrypted code, indicative of runtime unpacking or payload execution, which is common in packed malware or protectors."
    },
    {
      "source": "malcat",
      "query_or_table": "Anomalies",
      "row_or_rule": "HighEntropy, CodeSectionNotExecutable, BigBufferNoXrefMediumToHighEntropy",
      "why": "Multiple anomalies indicate packing or obfuscation: high file entropy, non-executable code section, and large high-entropy buffers without cross-references, consistent with encrypted or compressed payloads."
    },
    {
      "source": "ida",
      "query_or_table": "Imports",
      "row_or_rule": "advapi32.SystemFunction033",
      "why": "Import of SystemFunction033 supports capa's RC4 encryption rule, confirming use of cryptographic functions for defense evasion."
    }
  ],
  "summary": "This PE sample exhibits strong indicators of packing and obfuscation, including high entropy, a decryption routine in function sub_474643, and anomalies like non-executable code sections. The use of RC4 encryption via SystemFunction033 suggests defense evasion, but no behavioral-intent evidence (e.g., network C2, persistence, credential theft) was identified. Function analysis across tools is inconsistent, limiting coverage. Based on calibration, protection-only evidence classifies this as suspicious, not definitively malicious.",
  "source": "llm_judge",
  "model": "mimo-v2.5",
  "agreement": "llm_v1_disagree",
  "v1_verdict": {
    "verdict": "malicious",
    "score": 290,
    "findings": [
      "yara: 7 matches",
      "capa: 2 rules"
    ],
    "source": "fallback_v1"
  },
  "v1_summary": {
    "verdict": "malicious",
    "score": 290,
    "findings": [
      "yara: 7 matches",
      "capa: 2 rules"
    ]
  },
  "tool_gate": {
    "ok": true,
    "format": "pe",
    "required": [
      "capa",
      "yara",
      "floss",
      "malcat",
      "pe_imports"
    ],
    "tools": {
      "capa": {
        "ok": true,
        "why": "ok"
      },
      "yara": {
        "ok": true,
        "why": "ok"
      },
      "floss": {
        "ok": true,
        "why": "ok"
      },
      "pe_imports": {
        "ok": true,
        "why": "ok"
      }
    },
    "hard_failures": [],
    "soft_failures": [],
    "missing": [],
    "not_applicable": [],
    "large_sample": false
  },
  "yara_family_hits": [
    "IsPE32",
    "IsWindowsGUI",
    "IsPacked",
    "HasRichSignatur
… [866 more chars]
```

#### `deep_dive`

- source=`deep_dive_agentic` model=`None` verdict=`malicious` confidence=`90`
- key_evidence_count=`13`

```json
{
  "source": "deep_dive_agentic",
  "engine": "langgraph",
  "verdict": "malicious",
  "confidence": 90,
  "summary": "RC4-packed Windows PE dropper/loader with geo-fencing, privilege escalation, and encrypted payload. The binary imports only 7 APIs including SystemFunction033 (undocumented RC4 encryption/decryption) and ZwAdjustPrivilegesToken (privilege manipulation). The .text section is ~479KB with very high entropy (202), containing 19 large high-entropy buffers with no cross-references \u2014 consistent with a RC4-encrypted payload. Language detection APIs (GetUserDefaultLangID, GetSystemDefaultLCID, GetUserDefaultUILanguage) implement geo-fencing, likely to avoid execution on CIS/Russian systems. Capa confirms RC4 encryption via SystemFunction033 and System Language Discovery (T1614.001). YARA matches IsPacked and IsWindowsGUI. FLOSS extracted 1144 static strings but zero decoded/stack strings \u2014 all non-import content is encrypted. The entry function spans nearly the entire .text section, acting as a decryptor stub.",
  "key_evidence": [
    "capa: 'encrypt data using RC4 via SystemFunction033' \u2014 Defense Evasion/T1027, MBC C0027.009",
    "capa: 'identify system language via API' \u2014 Discovery/T1614.001 (geo-fencing evasion)",
    "Import: SystemFunction033 (ADVAPI32.DLL) \u2014 undocumented RC4 encryption API, used to decrypt payload at runtime",
    "Import: ZwAdjustPrivilegesToken (NTDLL.DLL) \u2014 undocumented privilege escalation API",
    "Import: FreeEncryptedFileKeyInfo (ADVAPI32.DLL) \u2014 EFS encryption key management",
    "YARA: IsPacked match \u2014 binary is packed/encrypted",
    "Malcat anomaly: BigBufferNoXrefMediumToHighEntropy x19 \u2014 19 large crypto data blocks with no cross-references",
    "Malcat: .text section entropy=202, overall entropy=201 \u2014 extremely high entropy indicates encrypted content",
    "Ghidra: entry function spans 0x401000-0x4664844 (~466KB), cyclomatic complexity=102, 101 outgoing calls \u2014 massive decryptor stub",
    "Strings: 1144 static strings but only import names readable; all others are obfuscated/encoded (e.g. repeating '=?a\\x1b' patterns)",
    "FLOSS: 0 decoded strings, 0 stack strings, 0 language strings \u2014 entire payload remains encrypted at rest",
    "Ghidra xrefs: COMPUTED_JUMP to all imports \u2014 indirect/dynamic import resolution (IAT obfuscation)",
    "User locale APIs (GetUserDefaultLangID, GetSystemDefaultLCID, GetUserDefaultUILanguage) \u2014 CIS geo-fencing pattern common in ransomware"
  ],
  "incomplete_tooling": false,
  "successful_tool_calls": 31,
  "successful_non_bootstrap_tools": 20,
  "checklist_ok": true,
  "sql_deep_ok": true,
  "tool_gate": {
    "ok": true,
    "format": "pe",
    "required": [
      "capa",
      "pe_imports",
      "yara",
      "floss",
      "dotnet",
      "r2_decomp",
      "upx",
      "xor",
      "speakeasy",
      "frida_probe"
    ],
    "tools": {
      "capa": {
        "ok": true,
        "why": "ok"
      },
      "pe_imports": {
        "ok": true,
        "why": "ok"
      },
      "yara": {
        "ok": true,
        "why": "ok"
      },
      "floss": {
        "ok": true,
        "why": "ok"
      },
      "dotnet": {
        "ok": true,
        "why": "ok"
      },
      "r2_decomp": {
        "ok": true,
        "why": "ok"
      },
      "upx": {
        "ok": true,
        "why": "ok"
      },
      "xor": {
        "ok": true,
        "why": "ok"
      },
      "speakeasy": {
 
… [278 more chars]
```

#### `publish`

- source=`llm_judge` model=`mimo-v2.5` verdict=`None` confidence=`None`
- key_evidence_count=`0`

```json
{
  "title": "Malware Analysis Report: e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2",
  "markdown": "> **RevAI provenance** \u2014 commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` \u00b7 engine `langgraph` \u00b7 agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True \u00b7 generated 2026-08-08 13:04:11 UTC\n\n# Verdict sources (multi-source)\n\n| Source | Verdict |\n|--------|--------|\n| **Final** | **malicious** |\n| Triage upstream (quick \u222a deep) | malicious |\n| Quick scan | suspicious |\n| Deep dive | malicious |\n| Publish LLM (claimed) | malicious |\n\n- **Locked over publish LLM:** no\n\n## Executive Summary\nThis report analyzes a Windows PE sample (SHA256: e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2) identified as suspicious. The binary exhibits strong indicators of packing and obfuscation, including high entropy, RC4 encryption via SystemFunction033, and a large decryption stub that unpacks an encrypted payload. Locale-based checks (e.g., GetUserDefaultUILanguage) suggest potential geo-fencing, and imports like ZwAdjustPrivilegesToken indicate privilege escalation capabilities. However, no behavioral-intent evidence\u2014such as network C2, persistence, or credential theft\u2014was observed during analysis, as runtime tools were not applied. The upstream triage verdict is suspicious with a score of 40, aligning with protection-only evidence. We assess the sample as a packed dropper/loader with latent malicious potential, but definitive classification as malicious lacks runtime confirmation. Confidence is moderate based on static indicators alone.\n\n## 1. Sample Identification\nThe sample is a Windows Portable Executable (PE) file with the following identifiers:\n- **SHA256**: e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2 (source: evidence)\n- **File Path**: /opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir (source: evidence)\n- **Project Name**: incoming (source: evidence)\n\nThe file name suggests it was sourced from a submission context (virussign.com), but no additional metadata is available. The PE structure was confirmed by YARA rule IsPE32 (source: yara).\n\n## 2. Classification\nBased on upstream triage and evidence, the sample is classified as **suspicious** with a family guess of \"packer/protector (unspecified)\" and a confidence score of 40. This classification is derived from static analysis showing packing and obfuscation, but no definitive malicious behavior. Key reasons include:\n- High entropy and anomalies like CodeSectionNotExecutable, indicating packing (source: malcat).\n- RC4 encryption via SystemFunction033, which is common in both malware and protectors (source: capa).\n- Absence of observed runtime malicious intent, such as C2 communication or file encryption.\n\nPer verdict calibration, obfuscation alone is neutral; thus, suspicious is appropriate without behavioral-intent evidence. The deep-dive assessment of \"malicious\" is overridden by upstream triage constraints.\n\n## 3. Background & Family Lineage\nNo specific malware family was identified in the analysis. The triage suggests a generic packer or protector (source: triage verdict). Evidence points to custom obfuscation techniques, including RC4 decryption and locale-based checks, which are not tied to a known lineage. The sample's imports and code structure do n
… [10648 more chars]
```

### REPORT-MASTER excerpts

#### REPORT-MASTER-v2

```markdown
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-08 13:04:11 UTC

# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | suspicious |
| Deep dive | malicious |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

## Executive Summary
This report analyzes a Windows PE sample (SHA256: e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2) identified as suspicious. The binary exhibits strong indicators of packing and obfuscation, including high entropy, RC4 encryption via SystemFunction033, and a large decryption stub that unpacks an encrypted payload. Locale-based checks (e.g., GetUserDefaultUILanguage) suggest potential geo-fencing, and imports like ZwAdjustPrivilegesToken indicate privilege escalation capabilities. However, no behavioral-intent evidence—such as network C2, persistence, or credential theft—was observed during analysis, as runtime tools were not applied. The upstream triage verdict is suspicious with a score of 40, aligning with protection-only evidence. We assess the sample as a packed dropper/loader with latent malicious potential, but definitive classification as malicious lacks runtime confirmation. Confidence is moderate based on static indicators alone.

## 1. Sample Identification
The sample is a Windows Portable Executable (PE) file with the following identifiers:
- **SHA256**: e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2 (source: evidence)
- **File Path**: /opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir (source: evidence)
- **Project Name**: incoming (source: evidence)

The file name suggests it was sourced from a submission context (virussign.com), but no additional metadata is available. The PE structure was confirmed by YARA rule IsPE32 (source: yara).

## 2. Classification
Based on upstream triage and evidence, the sample is classified as **suspicious** with a family guess of "packer/protector (unspecified)" and a confidence score of 40. This classification is derived from static analysis showing packing and obfuscation, but no definitive malicious behavior. Key reasons include:
- High entropy and anomalies like CodeSectionNotEx
… [9078 more chars]
```

#### REPORT-MASTER-v3

```markdown
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-08 13:09:51 UTC

# RE Report — e891b8f4825a
_Generated 2026-08-08T13:09:51.877622+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=255c | cross_refs=True | llm_ok=True | runtime=48.48s -->

**Executive Summary**

This malware sample (SHA256: e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2) is assessed as **malicious** with a **90% confidence** level, based on deep dive agentic analysis that likely indicates hidden malicious intent beneath obfuscation (source: cross-section: deep_dive_agentic). The initial aggregated classification as "suspicious" is attributed to the use of a **packer or protector**, which we assess is employed to evade detection by masking true code behaviors (source: cross-section: family_guess). A discrepancy exists between an initial analysis verdict of malicious with a score of 290 (source: cross-section: v1_summary) and the aggregated suspicious result, but deeper investigation confirms the high probability of malicious activity, warranting further scrutiny (source: cross-section: agreement).

The family is identified as a **packer/protector** of unspecified origin, suggesting the sample leverages obfuscation techniques to conceal payloads and potentially execute malicious code post-unpacking (source: cross-section: family_guess).

In two sentences: This sample is a packer or protector that likely contains and hides malicious code, exhibiting evasion behaviors such as obfuscation and anti-analysis techniques. Due to its high confidence of malice and unknown specific threat, it requires immediate containment measures to prevent potential compromise.

---

<!-- section: 1. Sample Identification | pass=2 | evidence=273c | cross_refs=True | llm_ok=True | runtime=35.85s -->

This section establishes core identifiers for the malware sample, enabling consistent tracking and initial characterization. We present metadata that defines the sample's format, platform, and structural properties, with interpretations hedged based on available evidence.

### Identifiers and Interpretation

The following table summarizes key attributes derived from static analysis. Each value is introduced and interpreted to c
… [41301 more chars]
```

### Artifact inventory

| Artifact | exists | bytes | sha256 |
|----------|--------|-------|--------|
| `verdict.json` | `True` | `4366` | `5356d0898f1511e1` |
| `prompt.txt` | `True` | `22553` | `0247e64ad5d56b88` |
| `pipeline-audit.json` | `True` | `104179` | `98d264904ac22a9e` |
| `AUDIT-REPORT.md` | `True` | `76768` | `c988322043d5a8d1` |
| `REPORT-MASTER-v2.md` | `True` | `11589` | `a7db4dbe319c2999` |
| `REPORT-MASTER-v3.md` | `True` | `43821` | `fc872ac1c79aa077` |
| `REPORT-v2.md` | `True` | `11589` | `a7db4dbe319c2999` |
| `REPORT-TECHNICAL.md` | `False` | `0` | `` |
| `REPORT-TECHNICAL-v3.md` | `True` | `33535` | `cf16990fa3cc9188` |
| `rule.yar` | `True` | `1201` | `f30982aff470e18e` |
| `intake-validation.json` | `True` | `2104` | `b764e24637d8ed1c` |
| `source-decisions.json` | `True` | `1195` | `ab5485eedd240a96` |
| `malcat-triage.json` | `True` | `18606` | `390dfb4037f7ff67` |
| `deep_dive/01-tools-raw.json` | `True` | `56930` | `34f4035bc9afb415` |
| `deep_dive/01-tools-gate.json` | `True` | `921` | `f3d89b0704908331` |
| `deep_dive/05-deep-dive.json` | `True` | `3778` | `db4e741861d70971` |
| `deep_dive/03-prompt.txt` | `False` | `0` | `` |
| `quick_scan/00-tools-raw.json` | `True` | `53565` | `886aeabd320ffce7` |

---

## Stage: intake

**ok:** `True`

### Checks

| Check | Result |
|-------|--------|
| intake_validation | `True` |
| has_source_decisions | `True` |
| ghidra_mentioned | `True` |

### Artifact paths (verify on disk)

- **intake_validation:** `/opt/samples/logs/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/intake-validation.json` exists=`True` bytes=`2104` mtime=`2026-08-08T12:58:36.110067+00:00`
  - sha256: `b764e24637d8ed1c920f5f5eb03d999bdd4c01edabb9c1d086999d3f41982ab5`
- **malcat_triage:** `/opt/samples/logs/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/malcat-triage.json` exists=`True` bytes=`18606` mtime=`2026-08-08T12:57:26.480889+00:00`
  - sha256: `390dfb4037f7ff679e245f92a1c6319143d46b7f4e6a57cb9b67df4a61ed9d12`
- **source_decisions:** `/opt/samples/logs/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/source-decisions.json` exists=`True` bytes=`1195` mtime=`2026-08-08T12:58:36.111067+00:00`
  - sha256: `ab5485eedd240a966912e14a7d541f08b70a765385c4213aebca50ec15e39b53`
- **ghidra_import_log:** `/opt/samples/logs/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/intake-analyzeHeadless.log` exists=`True` bytes=`7988` mtime=`2026-08-03T06:31:49.916845+00:00`
  - sha256: `cc5d3ed1df05a6855bb523c07a9064705521534637f0eac6633a080b0a5525ee`
- **ida_bootstrap_log:** `/opt/samples/logs/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/intake-idasql.log` exists=`True` bytes=`254` mtime=`2026-08-08T12:57:28.303889+00:00`
  - sha256: `595d7ce6823f11e0cd7300bb579f8347bcc6aec666cd515afc82de466250bff4`

#### source_decisions_excerpt

```
{
  "sha256": "e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2",
  "imports": {
    "source": "both",
    "confidence": "high",
    "reason": "All tools report consistent import count of 7: malcat=7, ghidra=7, ida=7."
  },
  "functions": {
    "source": "none",
    "confidence": "low",
    "reason": "Function counts are highly divergent: malcat=10, ghidra=365, ida=8, with a ghidra-to-ida ratio of 45.62, making coverage unreliable."
  },
  "strings": {
    "source": "both",
    "confidence": "high",
    "reason": "Multiple sources provide string data; using both ghidra and ida engines for comprehensive coverage despite differing counts: ghidra=11, ida=3574."
  },
  "decompilation": {
    "source": "none",
    "confidence": "medium",
    "reason": "Function coverage is unrel
… [418 more chars]
```


#### malcat_triage_excerpt

```
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir",
  "profile": "triage",
  "limits": {
    "strings_max": 100,
    "imports_max": 100,
    "functions_max": 10,
    "anomaly_locations_max": 5,
    "decompile_top_n": 1
  },
  "file_summary": {
    "analysis_id": 1,
    "file_name": "virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir",
    "file_path": "/opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir",
    "file_size": 481280,
    "type": "PE",
    "architecture": "X86",
    "entropy": 201,
    "sha256": "e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2"
… [17806 more chars]
```


---

## Stage: quick_scan

**ok:** `True`

### Checks

| Check | Result |
|-------|--------|
| prompt | `True` |
| verdict | `True` |
| has_capa_section | `True` |
| has_yara_section | `True` |
| has_malcat_section | `True` |
| has_floss_section | `True` |
| verdict_has_family | `True` |
| llm_source | `True` |
| tools_all_ok | `True` |
| citations_grounded | `True` |
| capa_salvage_used | `False` |
| evidence_pack_present | `True` |
| benign_blocked_if_incomplete | `True` |
| yara_family_not_cleared | `True` |

### Tools (full evidence excerpts)

#### `capa` — ok=`True` why=`ok`

```json
{
  "rule_count": 2,
  "top_rules": [
    {
      "name": "encrypt data using RC4 via SystemFunction033",
      "attack": [
        {
          "parts": [
            "Defense Evasion",
            "Obfuscated Files or Information"
          ],
          "tactic": "Defense Evasion",
          "technique": "Obfuscated Files or Information",
          "subtechnique": "",
          "id": "T1027"
        }
      ],
      "mbc": [
        {
          "parts": [
            "Defense Evasion",
            "Obfuscated Files or Information",
            "Encryption-Standard Algorithm"
          ],
          "objective": "Defense Evasion",
          "behavior": "Obfuscated Files or Information",
          "method": "Encryption-Standard Algorithm",
          "id": "E1027.m05"
        },
        {
          "parts": [
            "Cryptography",
            "Encrypt Data",
            "RC4"
          ],
          "objective": "Cryptography",
          "behavior": "Encrypt Data",
          "method": "RC4",
          "id": "C0027.009"
        }
      ]
    },
    {
      "name": "identify system language via API",
      "attack": [
        {
          "parts": [
            "Discovery",
            "System Location Discovery",
            "System Language Discovery"
          ],
          "tactic": "Discovery",
          "technique": "System Location Discovery",
          "subtechnique": "System Language Discovery",
          "id": "T1614.001"
        }
      ],
      "mbc": []
    }
  ],
  "timeout_s": 300,
  "sample_size": 481280,
  "duration_s": 1.51,
  "engine": "malcat-capa",
  "capa_bin": "/opt/malcat/bin/malcat.capa.py"
}
```

#### `yara` — ok=`True` why=`ok`

```json
{
  "rule_count": 7,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir",
      "strings": [
        {
          "id": "$domain_regex",
          "offset": 0,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IP",
      "path": "/opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir",
      "strings": [
        {
          "id": "$ipv6",
          "offset": 339946,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir",
      "strings": [
        {
          "id": "$a",
          "offset": 479934,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir",
      "strings": []
    },
    {
      "rule": "IsPacked",
      "path": "/opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir",
      "strings": []
    },
    {
      "rule": "HasRichSignature",
      "path": "/opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir",
      "strings": [
        {
          "id": "$a0",
          "offset": 160,
          "length": 4,
          "xor_key": null
        }
      ]
    }
  ],
  "engine": "yara-x",
  "rules_compiled": 454,
  "compile_errors": [
    "/opt/samples/rules/flat/Android_Amtrckr_20160519.yar: error[E010]: unknown module `androguard`\n --> /opt/samples/rules/flat/Android_Amtrckr_20160519.yar:6:1\n  |\n6 | import \"androguard\"\n  | ^^^^^^^^^^^^^^^^^^^ module `androguard` not found",
    "/opt/samples/rules/flat/Android_Backdoor.yar: error[E010]: unknown module `androguard`\n  --> /opt/samples/rules/flat/Android_Backdoor.yar:11:1\n   |\n11 | import \"androguard\"\n   | ^^^^^^^^^^^^^^^^^^^ module `androguard` not found",
    "/opt/samples/rules/flat/MALW_Httpsd_ELF.yar: error[E009]: unknown identifier `is__elf`\n  --> /opt/samples/rules/flat/MALW_Httpsd_ELF.yar:54:14\n   |\n54 |          and is__elf\n   |              ^^^^^^^ this identifier has not been declared",
    "/opt/samples/rules/flat/Android_Pink_Locker.yar: error[E010]: unknown module `androguard`\n  --> /opt/samples/rules/flat/Android_Pink_Locker.yar:10:1\n   |\n10 | import \"androguard\"\n   | ^^^^^^^^^^^^^^^^^^^ module `androguard` not found",
    "/opt/samples/rules/flat/Android_pornClicker.yar: error[E010]: unknown module `androguard`\n --> /opt/samples/rules/flat/Android_pornClicker.yar:6:1\n  |\n6 | import \"androguard\"\n  | ^^^^^^^^^^^^^^^^^^^ module `androguard` not found",
    "/opt/samples/rules/flat/Android_Spywaller.yar: error[E010]: unknown module `androguard`
… [1285 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 1144,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "Rich!l",
    "`.rdata",
    "@.data",
    "eq9f(2A",
    "cqn,)=Aq",
    "QiR?])",
    "MC\tHsC",
    ":U=y-]",
    "m67X|}",
    "`s^cI(N",
    "rm33Um",
    "TX=w2U=",
    "T8);:V",
    "TX=w2Y=",
    "r|jW2!",
    "0Yh%2Y",
    "rx(dxs",
    "KdS8i'",
    "($38iG",
    "ES;i%>8",
    "{+Gp;i",
    "G83cO8",
    "eerXHD",
    "EORXHD",
    "E\\Nt:H",
    "r=93un",
    "gbq|]%ta",
    "*7J(57?EA",
    "rjth&h",
    "X{4eWw",
    "e?M&2h",
    "5hxu\tE",
    "w_&U4%t",
    "*}E5-u",
    "{[A6u{",
    "$FkOdH,",
    "cOdW,m",
    "2FlOdO,O$&;",
    "9O$F,X$",
    "2FlOdO,O$&;3",
    "=b*Z\t,^",
    "w_4:j^",
    "PhV!xG9qHFW",
    "^X<=\\[",
    "*7p&jjx",
    "p0(0(\"e",
    "j{lRcKz",
    "VBrDzV",
    "S/1 Sp",
    "#yp@{7",
    "s/q {7",
    "55wkEg",
    "Al<Yp}",
    "rTFP#K",
    "K=v86#",
    "EHTeW7",
    "Gi:xRU",
    "ho:XiU",
    "|5}jE1",
    "5hnJ0zT",
    "7i;L&q",
    "<7a{#?l",
    "<7a{#?",
    "La$?af07",
    "[Mf52La$?a",
    "c5RLa$?a",
    "i$?af\"7",
    "q[]4AWR",
    "npzLA(u",
    "\\nhDWx8onkw",
    "D~tz(J",
    ")Wz5>t",
    "`QAOh1",
    "+$|P;a",
    "?a;=?a",
    "A+5Iwz",
    "tR7zCY",
    "E]{=C_YYI",
    "B~s)}H"
  ],
  "per_category": {
    "decoded_strings": 0,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 1144
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 6.88,
  "size_bytes": 481280,
  "static_only": false,
  "size_exceeded_deobfuscate_limit": false
}
```

#### `malcat` — ok=`True` why=`not_applicable:pe`

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir",
  "profile": "deep",
  "limits": {
    "strings_max": 300,
    "imports_max": 300,
    "functions_max": 30,
    "anomaly_locations_max": 50,
    "decompile_top_n": 3
  },
  "file_summary": {
    "analysis_id": 1,
    "file_name": "virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir",
    "file_path": "/opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir",
    "file_size": 481280,
    "type": "PE",
    "architecture": "X86",
    "entropy": 201,
    "sha256": "e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2",
    "metadata": {},
    "entrypoint_ea": 1536,
    "layout": [
      {
        "name": "header",
        "effective_address": 0,
        "physical_size": 1536,
        "virtual_size": 0,
        "rights": "",
        "entropy": 39
      },
      {
        "name": ".text",
        "effective_address": 1536,
        "physical_size": 478208,
        "virtual_size": 479232,
        "rights": "RX",
        "entropy": 202
      },
      {
        "name": ".rdata",
        "effective_address": 480768,
        "physical_size": 512,
        "virtual_size": 4096,
        "rights": "R",
        "entropy": 0
      },
      {
        "name": ".data",
        "effective_address": 484864,
        "physical_size": 512,
        "virtual_size": 4096,
        "rights": "RW",
        "entropy": 0
      },
      {
        "name": ".rsrc",
        "effective_address": 488960,
        "physical_size": 512,
        "virtual_size": 4096,
        "rights": "RW",
        "entropy": 44
      }
    ],
    "kesakode_verdict": []
  },
  "views": {
    "anomalies": [
      {
        "name": "BigBufferNoXrefMediumToHighEntropy",
        "desc": "a medium-to-high-entropy 10KB+ buffer, which is not part of a known structure and has no cross-reference inside: most likely a big crypto data block. File must have at least one function for this anomaly to run",
        "category": "entropy",
        "level": 3,
        "num_hits": 19
      },
      {
        "name": "CodeSectionNotExecutable",
        "desc": "code section is not executable",
        "category": "sections",
        "level": 3,
        "num_hits": 1
      },
      {
        "name": "DataBetweenHeaderAndFirstSection",
        "desc": "There is non-zero data between the PE header and the first section",
        "category": "headers",
        "level": 3,
        "num_hits": 1
      },
      {
        "name": "GuiSubsystemNoWindowApi",
        "desc": "A GUI windows application does not import any user32 window-related function",
        "category": "headers",
        "level": 2,
        "num_hits": 1
      },
      {
        "name": "HighEntropy",
        "desc": "File has high entropy overall (> 200)",
        "category": "entropy",
        "level": 2,
        "num_hits": 0
      },
      {
        "name": "ManyHighValueImmediates",
        "desc": "Function contains at least 5 and more than 10% of high-value immediate operands (i.e. immediate values that contains at least 2 non-zero non-FF bytes and are not a valid address)",
        "category": "code",
        "level": 3,
        "num_hits": 8
      },
      {
        "name": "ManyUniqueImmediateBytes",
        "desc": "More than 48 unique bytes defined across all immediate 
… [37036 more chars]
```

### LLM citation grounding

```json
{
  "ok": true,
  "checked": 4,
  "hits": 4,
  "misses": [],
  "hit_examples": [
    "top rule rule 'encrypt data using RC4 via SystemFunction033' Identifies defense evasion via RC4 encryption, a common tec",
    "function sub_474643 at address 474179 Decompilations Shows XOR decryption loop unpacking a large buffer (0x401400) and e",
    "HighEntropy, CodeSectionNotExecutable, BigBufferNoXrefMediumToHighEntropy Anomalies Multiple anomalies indicate packing ",
    "advapi32.SystemFunction033 Imports Import of SystemFunction033 supports capa's RC4 encryption rule, confirming use of cr"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "verdict": "suspicious",
  "family": "packer/protector (unspecified)",
  "score": 40,
  "agreement": "llm_v1_disagree",
  "source": "llm_judge",
  "model": "mimo-v2.5",
  "key_evidence": [
    {
      "source": "capa",
      "query_or_table": "rule 'encrypt data using RC4 via SystemFunction033'",
      "row_or_rule": "top rule",
      "why": "Identifies defense evasion via RC4 encryption, a common technique in malware for obfuscation or data protection, but also used in benign protectors. Without evidence of malicious data encryption (e.g., ransomware), this remains suspicious."
    },
    {
      "source": "malcat",
      "query_or_table": "Decompilations",
      "row_or_rule": "function sub_474643 at address 474179",
      "why": "Shows XOR decryption loop unpacking a large buffer (0x401400) and executing decrypted code, indicative of runtime unpacking or payload execution, which is common in packed malware or protectors."
    },
    {
      "source": "malcat",
      "query_or_table": "Anomalies",
      "row_or_rule": "HighEntropy, CodeSectionNotExecutable, BigBufferNoXrefMediumToHighEntropy",
      "why": "Multiple anomalies indicate packing or obfuscation: high file entropy, non-executable code section, and large high-entropy buffers without cross-references, consistent with encrypted or compressed payloads."
    },
    {
      "source": "ida",
      "query_or_table": "Imports",
      "row_or_rule": "advapi32.SystemFunction033",
      "why": "Import of SystemFunction033 supports capa's RC4 encryption rule, confirming use of cryptographic functions for defense evasion."
    }
  ],
  "summary": "This PE sample exhibits strong indicators of packing and obfuscation, including high entropy, a decryption routine in function sub_474643, and anomalies like non-executable code sections. The use of RC4 encryption via SystemFunction033 suggests defense evasion, but no behavioral-intent evidence (e.g., network C2, persistence, credential theft) was identified. Function analysis across tools is inco"
}
```

### Artifact paths (verify on disk)

- **prompt:** `/opt/samples/logs/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/prompt.txt` exists=`True` bytes=`22553` mtime=`2026-08-08T12:58:49.926062+00:00`
  - sha256: `0247e64ad5d56b8851ef84ffed1ef2c22abb94e682949b9304aaf9f1d90b1a1d`
- **verdict:** `/opt/samples/logs/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/verdict.json` exists=`True` bytes=`4366` mtime=`2026-08-08T12:59:16.972028+00:00`
  - sha256: `5356d0898f1511e1a07dffe189fcade5f887926ce257d0b99c8d068c97a1af55`

#### prompt_excerpt

```
# Triage evidence
sha256: e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2
sample_path: /opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir
ghidra_session: ghidra-pe-e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2
ida_session: ida-e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2

## Source decisions (from intake validation)
- imports: both (confidence=high) — All tools report consistent import count of 7: malcat=7, ghidra=7, ida=7.
- functions: none (confidence=low) — Function counts are highly divergent: malcat=10, ghidra=365, ida=8, with a ghidra-to-ida ratio of 45.62, making coverage unreliable.
- strings: both (confidence=high) — Multiple sources provide string data; using both ghidra and ida engines for comprehensive coverage despite differing counts: ghidra=11, ida=3574.
- decompilation: none (confidence=medium) — Function coverage is unrel
… [21520 more chars]
```


#### verdict_excerpt

```
{
  "verdict": "suspicious",
  "score": 40,
  "family_guess": "packer/protector (unspecified)",
  "cross_engine_notes": "Function counts diverge significantly across tools (malcat=15, ghidra=365, ida=8), making coverage unreliable. Focus on malcat decompilation for runtime behavior. Obfuscation and packing indicators are present but neutral per calibration; no clear behavioral-intent evidence (e.g., C2, persistence, credential theft) was found.",
  "key_evidence": [
    {
      "source": "capa",
      "query_or_table": "rule 'encrypt data using RC4 via SystemFunction033'",
      "row_or_rule": "top rule",
      "why": "Identifies defense evasion via RC4 encryption, a common technique in malware for obfuscation or data protection, but also used in benign protectors. Without evidence of malicious data encryption (e.g., ransomware), this remains suspicious."
    },
    {
      "source": "malcat",
      "query_or_table": "Decompilations",
      "row_or_rule": "function sub_474643 at addres
… [3366 more chars]
```


---

## Stage: deep_dive

**ok:** `True`

### Checks

| Check | Result |
|-------|--------|
| 01_tools_raw | `True` |
| 00_sql_evidence | `False` |
| 03_prompt | `False` |
| 04_llm | `False` |
| 05_deep | `True` |
| tools_all_ok | `True` |
| llm_source | `False` |
| citations_grounded | `True` |
| engine_citation_ok | `True` |
| upx_second_pass_ok | `True` |
| no_incomplete_tooling | `True` |
| confidence_sane | `True` |
| evidence_pack_present | `True` |
| depth_coverage | `True` |
| agentic_json | `True` |
| sql_deep_re | `True` |
| complete_verdict | `True` |
| not_incomplete | `True` |
| checklist_ok_flag | `True` |
| agentic_confidence_sane | `True` |

### Tools (full evidence excerpts)

#### `malcat` — ok=`True` why=`not_applicable:pe`

```json

```

#### `capa` — ok=`True` why=`ok`

```json
{
  "rule_count": 2,
  "top_rules": [
    {
      "name": "encrypt data using RC4 via SystemFunction033",
      "attack": [
        {
          "parts": [
            "Defense Evasion",
            "Obfuscated Files or Information"
          ],
          "tactic": "Defense Evasion",
          "technique": "Obfuscated Files or Information",
          "subtechnique": "",
          "id": "T1027"
        }
      ],
      "mbc": [
        {
          "parts": [
            "Defense Evasion",
            "Obfuscated Files or Information",
            "Encryption-Standard Algorithm"
          ],
          "objective": "Defense Evasion",
          "behavior": "Obfuscated Files or Information",
          "method": "Encryption-Standard Algorithm",
          "id": "E1027.m05"
        },
        {
          "parts": [
            "Cryptography",
            "Encrypt Data",
            "RC4"
          ],
          "objective": "Cryptography",
          "behavior": "Encrypt Data",
          "method": "RC4",
          "id": "C0027.009"
        }
      ]
    },
    {
      "name": "identify system language via API",
      "attack": [
        {
          "parts": [
            "Discovery",
            "System Location Discovery",
            "System Language Discovery"
          ],
          "tactic": "Discovery",
          "technique": "System Location Discovery",
          "subtechnique": "System Language Discovery",
          "id": "T1614.001"
        }
      ],
      "mbc": []
    }
  ],
  "timeout_s": 60,
  "sample_size": 481280,
  "duration_s": 1.1,
  "engine": "malcat-capa",
  "capa_bin": "/opt/malcat/bin/malcat.capa.py"
}
```

#### `pe_imports` — ok=`True` why=`ok`

```json
{
  "engine": "pe_imports",
  "sample_size": 481280,
  "duration_s": 0.03,
  "import_count": 7,
  "signal_count": 0,
  "signals": [],
  "hint": "PE import high-signal map (pefile). Not capa."
}
```

#### `yara` — ok=`True` why=`ok`

```json
{
  "rule_count": 7,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir",
      "strings": [
        {
          "id": "$domain_regex",
          "offset": 0,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IP",
      "path": "/opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir",
      "strings": [
        {
          "id": "$ipv6",
          "offset": 339946,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir",
      "strings": [
        {
          "id": "$a",
          "offset": 479934,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir",
      "strings": []
    },
    {
      "rule": "IsPacked",
      "path": "/opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir",
      "strings": []
    },
    {
      "rule": "HasRichSignature",
      "path": "/opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir",
      "strings": [
        {
          "id": "$a0",
          "offset": 160,
          "length": 4,
          "xor_key": null
        }
      ]
    }
  ],
  "engine": "yara-x",
  "rules_compiled": 454,
  "compile_errors": [
    "/opt/samples/rules/flat/Android_Amtrckr_20160519.yar: error[E010]: unknown module `androguard`\n --> /opt/samples/rules/flat/Android_Amtrckr_20160519.yar:6:1\n  |\n6 | import \"androguard\"\n  | ^^^^^^^^^^^^^^^^^^^ module `androguard` not found",
    "/opt/samples/rules/flat/Android_Backdoor.yar: error[E010]: unknown module `androguard`\n  --> /opt/samples/rules/flat/Android_Backdoor.yar:11:1\n   |\n11 | import \"androguard\"\n   | ^^^^^^^^^^^^^^^^^^^ module `androguard` not found",
    "/opt/samples/rules/flat/MALW_Httpsd_ELF.yar: error[E009]: unknown identifier `is__elf`\n  --> /opt/samples/rules/flat/MALW_Httpsd_ELF.yar:54:14\n   |\n54 |          and is__elf\n   |              ^^^^^^^ this identifier has not been declared",
    "/opt/samples/rules/flat/Android_Pink_Locker.yar: error[E010]: unknown module `androguard`\n  --> /opt/samples/rules/flat/Android_Pink_Locker.yar:10:1\n   |\n10 | import \"androguard\"\n   | ^^^^^^^^^^^^^^^^^^^ module `androguard` not found",
    "/opt/samples/rules/flat/Android_pornClicker.yar: error[E010]: unknown module `androguard`\n --> /opt/samples/rules/flat/Android_pornClicker.yar:6:1\n  |\n6 | import \"androguard\"\n  | ^^^^^^^^^^^^^^^^^^^ module `androguard` not found",
    "/opt/samples/rules/flat/Android_Spywaller.yar: error[E010]: unknown module `androguard`
… [1264 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 1144,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "Rich!l",
    "`.rdata",
    "@.data",
    "eq9f(2A",
    "cqn,)=Aq",
    "QiR?])",
    "MC\tHsC",
    ":U=y-]",
    "m67X|}",
    "`s^cI(N",
    "rm33Um",
    "TX=w2U=",
    "T8);:V",
    "TX=w2Y=",
    "r|jW2!",
    "0Yh%2Y",
    "rx(dxs",
    "KdS8i'",
    "($38iG",
    "ES;i%>8",
    "{+Gp;i",
    "G83cO8",
    "eerXHD",
    "EORXHD",
    "E\\Nt:H",
    "r=93un",
    "gbq|]%ta",
    "*7J(57?EA",
    "rjth&h",
    "X{4eWw",
    "e?M&2h",
    "5hxu\tE",
    "w_&U4%t",
    "*}E5-u",
    "{[A6u{",
    "$FkOdH,",
    "cOdW,m",
    "2FlOdO,O$&;",
    "9O$F,X$",
    "2FlOdO,O$&;3",
    "=b*Z\t,^",
    "w_4:j^",
    "PhV!xG9qHFW",
    "^X<=\\[",
    "*7p&jjx",
    "p0(0(\"e",
    "j{lRcKz",
    "VBrDzV",
    "S/1 Sp",
    "#yp@{7",
    "s/q {7",
    "55wkEg",
    "Al<Yp}",
    "rTFP#K",
    "K=v86#",
    "EHTeW7",
    "Gi:xRU",
    "ho:XiU",
    "|5}jE1",
    "5hnJ0zT",
    "7i;L&q",
    "<7a{#?l",
    "<7a{#?",
    "La$?af07",
    "[Mf52La$?a",
    "c5RLa$?a",
    "i$?af\"7",
    "q[]4AWR",
    "npzLA(u",
    "\\nhDWx8onkw",
    "D~tz(J",
    ")Wz5>t",
    "`QAOh1",
    "+$|P;a",
    "?a;=?a",
    "A+5Iwz",
    "tR7zCY",
    "E]{=C_YYI",
    "B~s)}H"
  ],
  "per_category": {
    "decoded_strings": 0,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 1144
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 6.81,
  "size_bytes": 481280,
  "static_only": false,
  "size_exceeded_deobfuscate_limit": false
}
```

#### `dotnet` — ok=`True` why=`ok`

```json
{
  "is_dotnet": false,
  "runtime_version": null,
  "assembly_name": null,
  "module_name": null,
  "language_hint": null,
  "external_assembly_refs": [],
  "suspicious_native_refs": [],
  "suspicious_methods": [],
  "interesting_pinvoke": [],
  "has_suppress_ildasm": false,
  "shellcode_embed_hint": false,
  "il_total_lines": 0,
  "il_excerpt": ""
}
```

#### `r2_decomp` — ok=`True` why=`ok`

```json
{
  "r2_ok": true,
  "sample": "/opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir",
  "disassembly": {
    "0x00475a2a": "; CALL XREF from entry0 @ 0x401000(x)\n\u250c 6: LCID sub.kernel32.dll_GetSystemDefaultLCID ();\n\u2514           0x00475a2a      ff2520604700   jmp dword [sym.imp.kernel32.dll_GetSystemDefaultLCID] ; 0x476020 ; \"Na\\a\"",
    "0x00475a1e": "; XREFS(46)\n\u250c 6: int sub.user32.dll_MessageBoxExA (HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType, WORD wLanguageId);\n\u2514           0x00475a1e      ff2500604700   jmp dword [sym.imp.user32.dll_MessageBoxExA] ; 0x476000",
    "0x00475a24": "; XREFS(50)\n\u250c 6: sub.advapi32.dll_SystemFunction033 ();\n\u2514           0x00475a24      ff2508604700   jmp dword [sym.imp.advapi32.dll_SystemFunction033] ; 0x476008",
    "0x00475a30": "; CALL XREFS from entry0 @ 0x401093(x), 0x40111c(x), 0x4011a5(x)\n\u250c 6: LANGID sub.kernel32.dll_GetUserDefaultUILanguage ();\n\u2514           0x00475a30      ff2524604700   jmp dword [sym.imp.kernel32.dll_GetUserDefaultUILanguage] ; 0x476024 ; \"ea\\a\""
  },
  "engine": "pdf (disasm)",
  "fallback": true,
  "functions_attempted": [
    "0x00401000",
    "0x00475a2a",
    "0x00475a1e",
    "0x00475a24",
    "0x00475a30"
  ]
}
```

#### `upx` — ok=`True` why=`ok`

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 0 file"
}
```

#### `xor` — ok=`True` why=`ok`

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir",
  "candidates": [
    "Found XOR 00 position 00000000: 000000B8 ........!..L.!This program cannot be r"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 000000B8 ........!..L.!This program cannot be r\n",
  "xorsearch_stderr": "",
  "xorsearch_returncode": 0
}
```

#### `speakeasy` — ok=`True` why=`ok`

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir",
  "module_base": null,
  "entry_point": null,
  "key_events": [],
  "api_calls": [],
  "strings": []
}
```

#### `frida_probe` — ok=`True` why=`ok`

```json
{
  "frida_available": true,
  "frida_version": "17.16.4",
  "pe_probe": {
    "path": "/opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir",
    "exists": true
  }
}
```

#### `frida_trace` — ok=`True` why=`not_applicable:pe`

```json

```

### LLM citation grounding

```json
{
  "ok": true,
  "checked": 13,
  "hits": 13,
  "misses": [],
  "hit_examples": [
    "capa: 'encrypt data using RC4 via SystemFunction033' \u2014 Defense Evasion/T1027, MBC C0027.009",
    "capa: 'identify system language via API' \u2014 Discovery/T1614.001 (geo-fencing evasion)",
    "Import: SystemFunction033 (ADVAPI32.DLL) \u2014 undocumented RC4 encryption API, used to decrypt payload at runtime",
    "Import: ZwAdjustPrivilegesToken (NTDLL.DLL) \u2014 undocumented privilege escalation API",
    "Import: FreeEncryptedFileKeyInfo (ADVAPI32.DLL) \u2014 EFS encryption key management"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "source": "deep_dive_agentic",
  "confidence": 90,
  "summary": "RC4-packed Windows PE dropper/loader with geo-fencing, privilege escalation, and encrypted payload. The binary imports only 7 APIs including SystemFunction033 (undocumented RC4 encryption/decryption) and ZwAdjustPrivilegesToken (privilege manipulation). The .text section is ~479KB with very high ent",
  "key_evidence": [
    "capa: 'encrypt data using RC4 via SystemFunction033' \u2014 Defense Evasion/T1027, MBC C0027.009",
    "capa: 'identify system language via API' \u2014 Discovery/T1614.001 (geo-fencing evasion)",
    "Import: SystemFunction033 (ADVAPI32.DLL) \u2014 undocumented RC4 encryption API, used to decrypt payload at runtime",
    "Import: ZwAdjustPrivilegesToken (NTDLL.DLL) \u2014 undocumented privilege escalation API",
    "Import: FreeEncryptedFileKeyInfo (ADVAPI32.DLL) \u2014 EFS encryption key management",
    "YARA: IsPacked match \u2014 binary is packed/encrypted",
    "Malcat anomaly: BigBufferNoXrefMediumToHighEntropy x19 \u2014 19 large crypto data blocks with no cross-references",
    "Malcat: .text section entropy=202, overall entropy=201 \u2014 extremely high entropy indicates encrypted content",
    "Ghidra: entry function spans 0x401000-0x4664844 (~466KB), cyclomatic complexity=102, 101 outgoing calls \u2014 massive decryptor stub",
    "Strings: 1144 static strings but only import names readable; all others are obfuscated/encoded (e.g. repeating '=?a\\x1b' patterns)",
    "FLOSS: 0 decoded strings, 0 stack strings, 0 language strings \u2014 entire payload remains encrypted at rest",
    "Ghidra xrefs: COMPUTED_JUMP to all imports \u2014 indirect/dynamic import resolution (IAT obfuscation)",
    "User locale APIs (GetUserDefaultLangID, GetSystemDefaultLCID, GetUserDefaultUILanguage) \u2014 CIS geo-fencing pattern common in ransomware"
  ],
  "model": null,
  "llm_audit": null
}
```

### Agentic tool-call history (excerpts)

- **yara_scan** ok=`True` checklist=`True` — Required checklist tool (yara)

```json
{
  "rule_count": 7,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir",
      "strings": [
        {
          "id": "$domain_regex",
          "offset": 0,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "
… [4364 more chars]
```

- **malcat_analyze** ok=`True` checklist=`True` — Required checklist tool (malcat)

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir",
  "profile": "deep",
  "limits": {
    "strings_max": 300,
    "imports_max": 300,
    "functions_max": 30,
    "anomaly_locations_max": 50,
    "decompile_top_n": 3
  },
  "file_summary": {
    "analysis_id": 1,
    "fi
… [40114 more chars]
```

- **capa_analyze** ok=`True` checklist=`True` — Required checklist tool (capa)

```json
{
  "rule_count": 2,
  "top_rules": [
    {
      "name": "encrypt data using RC4 via SystemFunction033",
      "attack": [
        {
          "parts": [
            "Defense Evasion",
            "Obfuscated Files or Information"
          ],
          "tactic": "Defense Evasion",
          "technique": "Obfuscated Files or Information",
          "subtechnique": "",
          "id": "T1027"
    
… [1240 more chars]
```

- **pe_import_signals** ok=`True` checklist=`True` — Required checklist tool (pe_imports)

```json
{
  "engine": "pe_imports",
  "sample_size": 481280,
  "duration_s": 0.03,
  "import_count": 7,
  "signal_count": 0,
  "signals": [],
  "hint": "PE import high-signal map (pefile). Not capa."
}
```

- **floss_extract** ok=`True` checklist=`True` — Required checklist tool (floss)

```json
{
  "floss_ok": true,
  "string_count": 1144,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "Rich!l",
    "`.rdata",
    "@.data",
    "eq9f(2A",
    "cqn,)=Aq",
    "QiR?])",
    "MC\tHsC",
    ":U=y-]",
    "m67X|}",
    "`s^cI(N",
    "rm33Um",
    "TX=w2U=",
    "T8);:V",
    "TX=w2Y=",
    "r|jW2!",
    "0Yh%2Y",
    "rx(dxs",
    "KdS8i'",
    "(
… [1287 more chars]
```

- **dotnet_analyze** ok=`True` checklist=`True` — Required checklist tool (dotnet)

```json
{
  "is_dotnet": false,
  "runtime_version": null,
  "assembly_name": null,
  "module_name": null,
  "language_hint": null,
  "external_assembly_refs": [],
  "suspicious_native_refs": [],
  "suspicious_methods": [],
  "interesting_pinvoke": [],
  "has_suppress_ildasm": false,
  "shellcode_embed_hint": false,
  "il_total_lines": 0,
  "il_excerpt": ""
}
```

- **r2_decompile** ok=`True` checklist=`True` — Required checklist tool (r2_decomp)

```json
{
  "r2_ok": true,
  "sample": "/opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir",
  "disassembly": {
    "0x00475a2a": "; CALL XREF from entry0 @ 0x401000(x)\n\u250c 6: LCID sub.kernel32.dll_GetSystemDefaultLCID ();\n\u2514           0x00475a2a      ff2520604700   jmp dword [sym.imp.kernel32.dll_GetSys
… [946 more chars]
```

- **upx_unpack** ok=`True` checklist=`True` — Required checklist tool (upx)

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    
… [34 more chars]
```

- **xor_string_search** ok=`True` checklist=`True` — Required checklist tool (xor)

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir",
  "candidates": [
    "Found XOR 00 position 00000000: 000000B8 ........!..L.!This program cannot be r"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 000000B8 ........!..L.!This program cannot be r\n"
… [57 more chars]
```

- **speakeasy_emulate** ok=`True` checklist=`True` — Required checklist tool (speakeasy)

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir",
  "module_base": null,
  "entry_point": null,
  "key_events": [],
  "api_calls": [],
  "strings": []
}
```

- **frida_static_probe** ok=`True` checklist=`True` — Required checklist tool (frida_probe)

```json
{
  "frida_available": true,
  "frida_version": "17.16.4",
  "pe_probe": {
    "path": "/opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir",
    "exists": true
  }
}
```

- **ghidra_query** ok=`True` checklist=`False` — Auto SQL seed for large-mode deep RE gate

```json
{
  "columns": [
    "name",
    "address",
    "size"
  ],
  "rows": [
    {
      "name": "entry",
      "address": "4198400",
      "size": "560"
    },
    {
      "name": "FUN_00472edc",
      "address": "4665052",
      "size": "56"
    },
    {
      "name": "FUN_004757ef",
      "address": "4675567",
      "size": "56"
    },
    {
      "name": "FUN_0047406c",
      "address": "4669548",

… [2222 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "address",
    "name",
    "module"
  ],
  "rows": [
    {
      "address": "1",
      "name": "MessageBoxExA",
      "module": "USER32.DLL"
    },
    {
      "address": "2",
      "name": "SystemFunction033",
      "module": "ADVAPI32.DLL"
    },
    {
      "address": "3",
      "name": "FreeEncryptedFileKeyInfo",
      "module": "ADVAPI32.DLL"
    },
    {
      "address":
… [702 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "address",
    "ea",
    "length",
    "type",
    "type_name",
    "width",
    "width_name",
    "layout",
    "layout_name",
    "encoding",
    "content"
  ],
  "rows": [
    {
      "address": "4677869",
      "ea": "4677869",
      "length": "25",
      "type": "TerminatedCString",
      "type_name": "ascii",
      "width": "1",
      "width_name": "1-byte",
      "layou
… [3553 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "address",
    "start_ea",
    "name",
    "size",
    "end_ea",
    "flags",
    "namespace",
    "signature",
    "return_type",
    "arg_count",
    "calling_conv",
    "return_is_ptr",
    "return_is_void",
    "return_is_int",
    "return_is_integral"
  ],
  "rows": [
    {
      "address": "4198400",
      "start_ea": "4198400",
      "name": "entry",
      "size": "560"
… [6848 more chars]
```

- **capa_analyze** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "rule_count": 2,
  "top_rules": [
    {
      "name": "encrypt data using RC4 via SystemFunction033",
      "attack": [
        {
          "parts": [
            "Defense Evasion",
            "Obfuscated Files or Information"
          ],
          "tactic": "Defense Evasion",
          "technique": "Obfuscated Files or Information",
          "subtechnique": "",
          "id": "T1027"
    
… [1241 more chars]
```

- **malcat_analyze** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir",
  "profile": "deep",
  "limits": {
    "strings_max": 300,
    "imports_max": 300,
    "functions_max": 30,
    "anomaly_locations_max": 50,
    "decompile_top_n": 3
  },
  "file_summary": {
    "analysis_id": 1,
    "fi
… [40114 more chars]
```

- **ida_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "address",
    "name",
    "ordinal",
    "module",
    "module_idx",
    "folder_path",
    "full_path"
  ],
  "rows": [
    {
      "address": "4677632",
      "name": "MessageBoxExA",
      "ordinal": "0",
      "module": "user32",
      "module_idx": "0",
      "folder_path": "user32",
      "full_path": "/user32/MessageBoxExA"
    },
    {
      "address": "4677640",
    
… [1698 more chars]
```

- **ghidra_decompile** ok=`False` checklist=`False` — langgraph tool call
  - error: `session registry not found: /opt/samples/sessions/pe-e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2.json`

```json
{
  "error": "session registry not found: /opt/samples/sessions/pe-e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2.json"
}
```

- **ida_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "string_addr",
    "string_value",
    "string_length",
    "ref_addr",
    "func_addr",
    "func_name"
  ],
  "rows": [],
  "row_count": 0,
  "total_row_count": 0,
  "truncated": false,
  "source": "ida_query",
  "session_id": "ida-e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2",
  "audit_path": "/opt/samples/logs/e891b8f4825a86999ef858ac13af749d982c91e9d3e
… [36 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "func_addr",
    "func_name",
    "size",
    "instruction_count",
    "block_count",
    "edge_count",
    "cyclomatic_complexity",
    "call_in_count",
    "call_out_count",
    "string_ref_count",
    "token_count"
  ],
  "rows": [
    {
      "func_addr": "4198400",
      "func_name": "entry",
      "size": "560",
      "instruction_count": "117",
      "block_count": "110
… [3475 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "from_ea",
    "to_ea",
    "kind",
    "is_code",
    "is_data"
  ],
  "rows": [
    {
      "from_ea": "4676126",
      "to_ea": "1",
      "kind": "COMPUTED_JUMP",
      "is_code": "1",
      "is_data": "0"
    },
    {
      "from_ea": "4676132",
      "to_ea": "2",
      "kind": "COMPUTED_JUMP",
      "is_code": "1",
      "is_data": "0"
    },
    {
      "from_ea": "467
… [1431 more chars]
```

- **pe_import_signals** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "engine": "pe_imports",
  "sample_size": 481280,
  "duration_s": 0.05,
  "import_count": 7,
  "signal_count": 0,
  "signals": [],
  "hint": "PE import high-signal map (pefile). Not capa."
}
```

- **ida_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "content"
  ],
  "rows": [
    {
      "content": "\r\bQ,\r\bQ,\r\bQ,\r\bQ,\r\bQ,\r\bQ,\r\bQ,\r\bQ,\r\bQ,\r\bQ,\r\bQ,\r\bQ,\r\bQ,\r\bQ,\r\bQ,\r\bQ,\r\bQ,\r\bQ,\r\bQ,\r\bQ,\r\bQ,\r\bQ,\r\bQ,\r\bQ,\r\bQ,\r\bQ,\r\bQ,\r\bQ,\r\bQ,\r\bQ,\r\bQ,\r\bQ,\r\bQ,\r\bQ,\r\bQ,\r\bQ,G"
    },
    {
      "content": "sQ6a\u001b=?a\u001b=?a\u001b=?a\u001b=?a\u001b=?a\u001b=?a\u001b=?a\u001b=?a\u
… [2675 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "address",
    "name",
    "data_type",
    "size",
    "value_repr",
    "segment_name",
    "is_string",
    "is_initialized"
  ],
  "rows": [
    {
      "address": "4194304",
      "name": "IMAGE_DOS_HEADER_00400000",
      "data_type": "IMAGE_DOS_HEADER",
      "size": "128",
      "value_repr": "",
      "segment_name": "",
      "is_string": "0",
      "is_initialized":
… [2211 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "start_ea",
    "end_ea",
    "name",
    "class",
    "perm",
    "bitness",
    "size",
    "is_read",
    "is_write",
    "is_exec"
  ],
  "rows": [
    {
      "start_ea": "4194304",
      "end_ea": "4195839",
      "name": "Headers",
      "class": "DATA",
      "perm": "4",
      "bitness": "0",
      "size": "1536",
      "is_read": "1",
      "is_write": "0",
      "is
… [1300 more chars]
```

- **ghidra_query** ok=`False` checklist=`False` — langgraph tool call
  - error: `ghidrasql SQL error: no such column: from_func_addr`

```json
{
  "error": "ghidrasql SQL error: no such column: from_func_addr"
}
```

- **ida_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "string_addr",
    "string_value",
    "string_length",
    "ref_addr",
    "func_addr",
    "func_name"
  ],
  "rows": [],
  "row_count": 0,
  "total_row_count": 0,
  "truncated": false,
  "source": "ida_query",
  "session_id": "ida-e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2",
  "audit_path": "/opt/samples/logs/e891b8f4825a86999ef858ac13af749d982c91e9d3e
… [36 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "string_addr",
    "string_value",
    "string_length",
    "ref_addr",
    "func_addr",
    "func_name"
  ],
  "rows": [],
  "row_count": 0,
  "total_row_count": 0,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2",
  "audit_path": "/opt/samples/logs/e891b8f4825a86999ef858ac13af749d98
… [45 more chars]
```

- **floss_extract** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "floss_ok": true,
  "string_count": 1144,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "Rich!l",
    "`.rdata",
    "@.data",
    "eq9f(2A",
    "cqn,)=Aq",
    "QiR?])",
    "MC\tHsC",
    ":U=y-]",
    "m67X|}",
    "`s^cI(N",
    "rm33Um",
    "TX=w2U=",
    "T8);:V",
    "TX=w2Y=",
    "r|jW2!",
    "0Yh%2Y",
    "rx(dxs",
    "KdS8i'",
    "(
… [1287 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "address",
    "start_ea",
    "name",
    "size",
    "end_ea",
    "flags",
    "namespace",
    "signature",
    "return_type",
    "arg_count",
    "calling_conv",
    "return_is_ptr",
    "return_is_void",
    "return_is_int",
    "return_is_integral"
  ],
  "rows": [
    {
      "address": "4676126",
      "start_ea": "4676126",
      "name": "MessageBoxExA",
      "size
… [2045 more chars]
```

- **ida_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "content",
    "length"
  ],
  "rows": [
    {
      "content": "FreeEncryptedFileKeyInfo",
      "length": "25"
    }
  ],
  "row_count": 1,
  "total_row_count": 1,
  "truncated": false,
  "source": "ida_query",
  "session_id": "ida-e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2",
  "audit_path": "/opt/samples/logs/e891b8f4825a86999ef858ac13af749d982c91e9d3e
… [36 more chars]
```

- **ida_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "content",
    "length"
  ],
  "rows": [
    {
      "content": "\r\bQ,\r\bQ,\r\bQ,\r\bQ,\r\bQ,\r\bQ,\r\bQ,\r\bQ,\r\bQ,\r\bQ,\r\bQ,\r\bQ,\r\bQ,\r\bQ,\r\bQ,\r\bQ,\r\bQ,\r\bQ,\r\bQ,\r\bQ,\r\bQ,\r\bQ,\r\bQ,\r\bQ,\r\bQ,\r\bQ,\r\bQ,\r\bQ,\r\bQ,\r\bQ,\r\bQ,\r\bQ,\r\bQ,\r\bQ,\r\bQ,\r\bQ,G",
      "length": "145"
    },
    {
      "content": "sQ6a\u001b=?a\u001b=?a\u001b=?a\u001b=?a\
… [2790 more chars]
```

### Artifact paths (verify on disk)

- **tools_raw:** `/opt/samples/logs/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/deep_dive/01-tools-raw.json` exists=`True` bytes=`56930` mtime=`2026-08-08T12:59:32.200015+00:00`
  - sha256: `34f4035bc9afb41555a4c144237057e68ccc542f63ebd60434e135df2f2a2430`
- **sql_evidence:** `/opt/samples/logs/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/deep_dive/00-sql-evidence.json` exists=`False` bytes=`0` mtime=`None`
- **prompt:** `/opt/samples/logs/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/deep_dive/03-prompt.txt` exists=`False` bytes=`0` mtime=`None`
- **llm_raw:** `/opt/samples/logs/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/deep_dive/04-llm-raw.json` exists=`False` bytes=`0` mtime=`None`
- **deep05:** `/opt/samples/logs/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/deep_dive/05-deep-dive.json` exists=`True` bytes=`3778` mtime=`2026-08-08T13:01:00.799840+00:00`
  - sha256: `db4e741861d7097143e343946ad6281ea806d3dcf0f7b32cb29ca7bd31f6f9a1`

#### prompt_excerpt

```

```


#### llm_raw_excerpt

```
{}
```


#### deep05_excerpt

```
{
  "source": "deep_dive_agentic",
  "engine": "langgraph",
  "verdict": "malicious",
  "confidence": 90,
  "summary": "RC4-packed Windows PE dropper/loader with geo-fencing, privilege escalation, and encrypted payload. The binary imports only 7 APIs including SystemFunction033 (undocumented RC4 encryption/decryption) and ZwAdjustPrivilegesToken (privilege manipulation). The .text section is ~479KB with very high entropy (202), containing 19 large high-entropy buffers with no cross-references \u2014 consistent with a RC4-encrypted payload. Language detection APIs (GetUserDefaultLangID, GetSystemDefaultLCID, GetUserDefaultUILanguage) implement geo-fencing, likely to avoid execution on CIS/Russian systems. Capa confirms RC4 encryption via SystemFunction033 and System Language Discovery (T161
… [2978 more chars]
```

- **agentic:** `/opt/samples/logs/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/deep_dive/agentic_deep_dive.json` exists=`True` bytes=`348681` mtime=`2026-08-08T13:01:00.798840+00:00`
  - sha256: `467c262521b7695c9725e82b76f7b40c957430da923a6d68b7b194b4122b6c99`

---

## Stage: yara_gen

**ok:** `True`

### Checks

| Check | Result |
|-------|--------|
| rule_yar | `True` |
| non_empty | `True` |
| has_rule_block | `True` |
| rule_compiles | `True` |
| rule_check | `ok` |
| meta_yara_valid | `True` |

### Artifact paths (verify on disk)

- **rule_yar:** `/opt/samples/logs/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/rule.yar` exists=`True` bytes=`1201` mtime=`2026-08-08T13:02:58.709899+00:00`
  - sha256: `f30982aff470e18e137d915d69e396c858906c0bae14396efce8278608af31c1`

#### excerpt

```
// yara_gen_v2.py — 2026-08-08T13:02:58.710998+00:00
rule CADRE_v2_unknown_e891b8f4825a {
    meta:
        description = "RevAI v2 auto rule for unknown"
        sha256 = "e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2"
        family = "unknown"
        revai = true
        revai_commit = "80c92a39d67f7e321883d3656b87cc4b04c5b7b5"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "FreeEncryptedFileKeyInfo" ascii wide
        $s1 = "GetUserDefaultUILanguage" ascii wide
        $s2 = "ZwAdjustPrivilegesToken" ascii wide
        $s3 = "GetUserDefaultLangID" ascii wide
        $s4 = "GetSystemDefaultLCID" ascii wide
        $s5 = "SystemFunction033" ascii wide
        $s6 = "MessageBoxExA" ascii wide
      
… [399 more chars]
```


---

## Stage: publish

**ok:** `True`

### Checks

| Check | Result |
|-------|--------|
| REPORT_MASTER_v2 | `True` |
| REPORT_MASTER_v3 | `True` |
| REPORT_v2 | `True` |
| REPORT_TECHNICAL_v2 | `True` |
| REPORT_TECHNICAL_v3 | `True` |
| v2_min_chars | `True` |
| v3_min_chars | `True` |
| v2_heads | `True` |
| v3_heads | `True` |
| v2_fresh_vs_deep | `True` |
| v3_fresh_vs_deep | `True` |
| not_llm_env_failure_v2 | `True` |
| not_llm_env_failure_v3 | `True` |
| v2_no_missing_sections | `True` |
| verdict_lock_ok | `True` |
| quality_pack_ok | `True` |
| master_source_llm | `True` |
| tech2_source_llm | `True` |
| tech3_source_ok | `True` |
| tech2_no_stubs | `True` |
| no_tech2_fallback | `True` |
| quality_issues | `[]` |
| engine_citation_ok | `True` |

### Artifact paths (verify on disk)

- **REPORT_MASTER_v2:** `/opt/samples/logs/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/REPORT-MASTER-v2.md` exists=`True` bytes=`11589` mtime=`2026-08-08T13:04:11.518064+00:00`
  - sha256: `a7db4dbe319c2999935266909aa1bd9b5b9a674d7c765ae510b9ccea70b7713f`
- **REPORT_MASTER_v3:** `/opt/samples/logs/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/REPORT-MASTER-v3.md` exists=`True` bytes=`43821` mtime=`2026-08-08T13:09:51.887832+00:00`
  - sha256: `fc872ac1c79aa077f7c7f27b0faa5ffee6161baab362e227512e86a7c3125a13`
- **REPORT_v2:** `/opt/samples/logs/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/REPORT-v2.md` exists=`True` bytes=`11589` mtime=`2026-08-08T13:04:11.518064+00:00`
  - sha256: `a7db4dbe319c2999935266909aa1bd9b5b9a674d7c765ae510b9ccea70b7713f`
- **REPORT_TECHNICAL_v2:** `/opt/samples/logs/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/REPORT-TECHNICAL-v2.md` exists=`True` bytes=`36929` mtime=`2026-08-08T13:05:05.115902+00:00`
  - sha256: `979bec8c37ce9d1ef0ddad0dbadf04a0955564ef56e24247fc845c2b9abfe32f`
- **REPORT_TECHNICAL_v3:** `/opt/samples/logs/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/REPORT-TECHNICAL-v3.md` exists=`True` bytes=`33535` mtime=`2026-08-08T13:10:44.665642+00:00`
  - sha256: `cf16990fa3cc918851fb773f32574a5c3313a877a0187c4fe3491ed80cb689d1`
- **report_v2_json:** `/opt/samples/logs/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/report-v2.json` exists=`True` bytes=`14148` mtime=`2026-08-08T13:05:05.118902+00:00`
  - sha256: `b665d23b27b4fcaece9217df4aa0bba92115d25291150ff739b558310dceae08`

#### v2_excerpt

```
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-08 13:04:11 UTC

# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | suspicious |
| Deep dive | malicious |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

## Executive Summary
This report analyzes a Windows PE sample (SHA256: e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2) identified as suspicious. The binary exhibits strong indicators of packing and obfuscation, including high entropy, RC4 encryption via SystemFunction033, and a large decryption stub that unpacks an encrypted payload. Locale-based checks (e.g., GetUserDefaultUILanguage) 
… [10678 more chars]
```


#### v3_excerpt

```
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-08 13:09:51 UTC

# RE Report — e891b8f4825a
_Generated 2026-08-08T13:09:51.877622+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=255c | cross_refs=True | llm_ok=True | runtime=48.48s -->

**Executive Summary**

This malware sample (SHA256: e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2) is assessed as **malicious** with a **90% confidence** level, based on deep dive agentic analysis that likely indicates hidden malicious intent beneath obfuscation (source: cross-section: deep_dive_agentic). The initial aggregated classification as "suspicious" 
… [42901 more chars]
```


---

## Manual verification checklist (public showcase)

1. Open every **Artifact path** and confirm bytes/mtime/sha256 match this report.
2. For each tool: confirm raw excerpt matches on-disk JSON (`01-tools-raw.json`).
3. For each LLM stage: `key_evidence` strings appear in tool/SQL JSON (citation grounding).
4. Confirm REPORT-MASTER-v2 **and** REPORT-MASTER-v3 are fresh vs deep_dive mtime.
5. If capa salvaged: malcat `capa_summary` exists and LLM cited it.
6. Showcase pack under `/opt/samples/logs/_showcase_audits/<sha>/` is complete.
