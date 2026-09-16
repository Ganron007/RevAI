# Bundled data notices — API lookup index

The API lookup index ships third-party content. The notices below are also
stored inside the built index (`meta` table) so they travel with any copy of
`api_index.db`, as the licences require.

## malapi.json (bundled)

API abuse descriptions and attack categories from [malapi.io](https://malapi.io),
curated by mr.d0x and contributors. Redistributed unmodified.

This project is not affiliated with or endorsed by malapi.io.

## sdk-api documentation (optional build input, not bundled)

When `api_index_build.py` is run with `--sdk-api`, Windows API reference
documentation is ingested from
[MicrosoftDocs/sdk-api](https://github.com/MicrosoftDocs/sdk-api) and
[MicrosoftDocs/windows-driver-docs-ddi](https://github.com/MicrosoftDocs/windows-driver-docs-ddi).

Windows API reference documentation © Microsoft Corporation, licensed
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Markdown is rendered
to plain text at build time; no prose is altered.

## capa-rules (not bundled)

The upstream reference implementation derived its API-combination layer from
[mandiant/capa-rules](https://github.com/mandiant/capa-rules) (Apache License
2.0). The RevAI index does not ingest that layer: capability matching is already
performed by the pipeline's own `capa` stage, and duplicating it here would
produce a second, weaker answer to the same question.
