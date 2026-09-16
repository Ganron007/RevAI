# Offline Windows API index (`api_lookup`)

`api_lookup` gives the deep-dive agent a local, deterministic answer to *"what is
this API and how is it abused?"*, so API claims in reports are grounded in an
index instead of model recall. It is deliberately narrow: knowledge lookup only —
it never contributes a verdict and never performs capability matching (the
pipeline's own `capa` stage owns that).

This page is the operator guide for **building the index yourself**. It is an
optional prerequisite: the pipeline runs without it, and `api_lookup` degrades to
`available:false` when no index is present.

## Coverage levels

| Level | Content | Size | Where it comes from |
| :--- | :--- | :--- | :--- |
| **Bundled default** | 369 APIs catalogued by [malapi.io](https://malapi.io): abuse notes, 8 attack categories, signatures, parameters | ~0.7 MB | committed at `assets/api_index/api_index.db` |
| **Full corpus** | ~46,000 APIs: every documented Win32 function plus kernel DDI routines, merged with malapi's intent layer | ~55 MB | built by you from Microsoft's markdown |

The full corpus is **not committed**: it is a generated artifact of a
third-party corpus and changes with every rebuild. Build it on a machine with
internet, then copy the finished file to the analysis VM. The VM itself stays
offline and never needs the source clones.

## Prerequisites

* `git` and `python3` (the builder is stdlib-only: `sqlite3`, `json`, `zlib` — no packages)
* ~2 GB free disk for the source checkouts, ~55 MB for the finished index
* A machine with internet access (your workstation, or any host that can reach the VM by `scp`)

## Build

### One command

```bash
./scripts/build-api-index.sh
```

This sparse-clones both Microsoft repositories, builds the index at
`api_index_full.db` in the repository root, and prints the deploy commands.
Source clones are cached under `$TMPDIR/revai-api-index` so a rebuild is fast.

Useful flags:

| Flag | Meaning |
| :--- | :--- |
| `--sdk-only` | skip the kernel DDI corpus (~38k APIs instead of ~46k, ~45 MB) |
| `--out FILE` | write the index somewhere else |
| `--work DIR` | cache the source clones in a different directory |
| `--sdk-dir DIR` / `--ddi-dir DIR` | reuse existing checkouts instead of cloning |

### Manual equivalent

```bash
git clone --depth 1 --filter=blob:none --sparse \
    https://github.com/MicrosoftDocs/sdk-api.git .api-build/sdk-api
git -C .api-build/sdk-api sparse-checkout set sdk-api-src/content

git clone --depth 1 --filter=blob:none --sparse \
    https://github.com/MicrosoftDocs/windows-driver-docs-ddi.git .api-build/ddi
git -C .api-build/ddi sparse-checkout set wdk-ddi-src/content

python3 revai/api_index_build.py \
    --malapi assets/api_index/malapi.json \
    --sdk-api .api-build/sdk-api/sdk-api-src/content \
    --sdk-api .api-build/ddi/wdk-ddi-src/content \
    --out api_index_full.db
```

The builder prints the API count and per-category totals. Expect roughly:

```
api_index_build: 46365 APIs (71031 sdk-api pages, 21324 interface methods, 173 shadowed) -> api_index_full.db (55928 KB, sources=malapi+sdk-api)
```

### What the builder does with the corpus

* **Plain text, not HTML.** Markdown is flattened to prose because the consumer
  is the LLM/agent, not a rich-text panel. No third-party markdown or HTML
  library is required.
* **Compression.** Documentation columns are zlib-compressed per row and the
  runtime decodes them transparently (`meta.text_compression=zlib`). Indexes
  built by older versions (plain `TEXT`) still read.
* **Interface methods as a fallback.** Pages describing COM interface methods
  (`IThing.Method`) are ingested under the bare method name, but such a row can
  never displace a real function or a malapi entry that shares the name.
* **FTS excerpts are bounded.** The full-text index stores a short plain-text
  excerpt per API (600 characters), not a second copy of the corpus.

## Deploy to the analysis VM

```bash
scp api_index_full.db <user>@<vm>:/opt/revai/api_index/api_index.db
ssh <user>@<vm> 'cd /opt/scripts && python3 cli.py api_lookup --info'
```

`scripts/deploy.sh` **preserves** an existing index on the VM, so a full-corpus
build survives routine deploys. To put the small bundled default back, set
`REVAI_FORCE_API_INDEX=1` for that deploy:

```bash
sudo REVAI_FORCE_API_INDEX=1 ./scripts/deploy.sh --restart
```

Store the index elsewhere and point the runtime at it with `REVAI_API_INDEX`
(see [`OPERATE.md`](OPERATE.md)).

## Verify

```bash
cd /opt/scripts
python3 cli.py api_lookup --info                 # coverage, build time, attribution
python3 cli.py api_lookup CreateRemoteThread     # lookup a symbol
python3 cli.py api_lookup ZwCreateFile           # Nt/Zw folding
python3 cli.py api_lookup __imp_CreateFileW      # thunk/ANSI-wide folding
python3 cli.py api_lookup --search "process hollowing"
python3 cli.py api_lookup --category Injection
python3 cli.py api_lookup --categories
```

`--info` should report `sources: malapi+sdk-api` and the expected API count. A
symbol outside the index returns an explicit "not found — do not guess" result
rather than inventing behaviour.

## Provenance and licences

The index redistributes third-party content. Attribution is written into the
index's `meta` table (and shown by `cli.py api_lookup --info`) so it travels with
any copy of the file; keep `assets/api_index/NOTICE.md` alongside it.

| Content | Source | Licence |
| :--- | :--- | :--- |
| API abuse descriptions, attack categories | [malapi.io](https://malapi.io) (curated by mr.d0x and contributors) | redistributed with attribution; unaffiliated |
| Win32 reference documentation | [MicrosoftDocs/sdk-api](https://github.com/MicrosoftDocs/sdk-api) | CC BY 4.0 |
| Kernel DDI reference documentation | [MicrosoftDocs/windows-driver-docs-ddi](https://github.com/MicrosoftDocs/windows-driver-docs-ddi) | CC BY 4.0 |

The `capa-rules` API-combination layer used by the upstream reference tool is
**not** ingested here: capability matching already belongs to the pipeline's
`capa` stage, and a second, weaker answer to the same question adds no evidence.

## Refreshing the corpus

Microsoft's documentation moves. To refresh:

```bash
git -C "$TMPDIR/revai-api-index/sdk-api" pull --ff-only
git -C "$TMPDIR/revai-api-index/windows-driver-docs-ddi" pull --ff-only
./scripts/build-api-index.sh        # rebuilds from the updated clones
scp api_index_full.db <user>@<vm>:/opt/revai/api_index/api_index.db
```

## Troubleshooting

| Symptom | Cause / fix |
| :--- | :--- |
| `api_lookup: api index not found` | No index at the default paths. Build one, or set `REVAI_API_INDEX` to its location. |
| `available: false` in agent output | Same as above — the tool is fail-open by design; the pipeline is unaffected. |
| `no index entry for ...` | The symbol is genuinely absent (internal, non-Windows, or misspelled). This is the honest answer, not an error. |
| Build is slow or the clone is huge | Use `--sdk-only`, or keep the sparse checkouts (the clone is ~650 MB before sparse filtering). |
| Reclaim disk | Delete the cache directory (`$TMPDIR/revai-api-index` by default); the next build re-clones. |
| `git sparse-checkout` fails on Windows | Run the script under WSL or Git Bash; it is a bash script. The builder itself is cross-platform Python. |

## Related

* [`tool-stack.md`](tool-stack.md) — where `api_lookup` sits in the tool inventory
* [`OPERATE.md`](OPERATE.md) — `REVAI_API_INDEX`, `REVAI_FORCE_API_INDEX`
* [`PREREQUISITES.md`](PREREQUISITES.md) — the full prerequisite list
* [`../assets/api_index/NOTICE.md`](../assets/api_index/NOTICE.md) — bundled-data notices
