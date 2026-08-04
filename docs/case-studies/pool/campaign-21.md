# 21-Sample Campaign — Run Plan (overnight re-run + 6 new)

Full re-run of all 15 existing case studies (replacing reports) + 6 new samples
(2 small / 2 mid / 2 large). Reboot VM after every 2 runs.

## Existing 15 (re-run, replace reports)

| # | Mode | Sample | Family | Size |
|---|------|--------|--------|------|
| 1 | scripted | virussign-01984caa | Unicorn VB6 | 469K |
| 2 | scripted | virussign-277ba25a | packed PE | 470K |
| 3 | scripted | virussign-780d28e3 | DartyCrypter | 521K |
| 4 | scripted | remcos | Remcos RAT | 683K |
| 5 | scripted | pool-small-bkransomware | BK ransomware | 485K |
| 6 | agentic | virussign-40f92672 | packed Delphi loader | 982K |
| 7 | agentic | virussign-8264dc61 | packed dropper | 1024K |
| 8 | agentic | virussign-f622efa7 | UPX malware | 1265K |
| 9 | agentic | virussign-970b822a | ASPack loader | 3075K |
| 10 | agentic | virussign-7edf35d0 | Themida payload | 3092K |
| 11 | agentic | virussign-9358c2e1 | UPX dropper | 8755K |
| 12 | agentic | lumma-stealer | Lumma | 1116K |
| 13 | agentic | koi-stealer | Koi/Delphi | 2211K |
| 14 | agentic | pool-mid-quasar | Quasar RAT | 1874K |
| 15 | agentic | pool-large-darkgate | darkgate multi | 8701K |

## New 6 (from InTheWild pool)

| # | Mode | Sample (pool path) | Family | Size |
|---|------|--------------------|--------|------|
| 16 | scripted | `pool/small/2026-07-03_064480af..._mespinoza` | Mespinoza (Pysa) ransomware | 794K |
| 17 | scripted | `pool/small/2026-07-03_057dff56..._conti` | Conti ransomware | 594K |
| 18 | agentic | `pool/mid/2026-07-04_578608b9..._vidar` | Vidar stealer | 1489K |
| 19 | agentic | `pool/mid/2026-07-03_02c9e518..._mespinoza` | Mespinoza (Pysa) | 2019K |
| 20 | agentic | `pool/large/2026-07-03_52e3a64e..._hive` | Hive ransomware | 4315K |
| 21 | agentic | `pool/large/2026-07-03_7089acf1..._sliver` | Sliver C2 | 9282K |

Full filenames:
- `2026-07-03_064480afd4e5e59c783aec43ab1de3ef_mespinoza`
- `2026-07-03_057dff5650af402177d65141acdf65d0_conti`
- `2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar`
- `2026-07-03_02c9e5186bff0f868d7d7b5028b42753_mespinoza`
- `2026-07-03_52e3a64ea0a04ce87227ea213caa2371_hive`
- `2026-07-03_7089acf1941ea01081b4eab5f0b77136_sliver`

## Naming for new case studies

- scripted: `pool-small-mespinoza`, `pool-small-conti`
- agentic: `pool-mid-vidar`, `pool-mid-mespinoza`, `pool-large-hive`, `pool-large-sliver`
