#!/usr/bin/env bash
# build-api-index.sh - build the full offline Windows-API index for `api_lookup`.
#
# Clones Microsoft's reference markdown (sparse checkouts), builds the SQLite
# index with revai/api_index_build.py, and prints the deploy step for the
# analysis VM. Run this on a machine WITH INTERNET: the VM itself stays offline
# and only ever receives the finished file.
#
# Usage:
#   ./scripts/build-api-index.sh [options]
#
# Options:
#   --work DIR      cache directory for the source clones (default: $TMPDIR/revai-api-index)
#   --out FILE      output index path (default: <repo>/api_index_full.db)
#   --sdk-dir DIR   reuse an existing sdk-api checkout instead of cloning
#   --ddi-dir DIR   reuse an existing windows-driver-docs-ddi checkout
#   --sdk-only      build from sdk-api alone (skip the kernel DDI corpus)
#   -h, --help      show this help
#
# Output: a SQLite index (~55 MB for the full corpus: ~46k APIs). It is
# intentionally NOT committed to the repository - see docs/api-index.md.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${TMPDIR:-/tmp}/revai-api-index"
OUT="$REPO_ROOT/api_index_full.db"
SDK_DIR=""
DDI_DIR=""
SDK_ONLY=0

usage() {
    sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --work)     WORK="$2"; shift 2 ;;
        --out)      OUT="$2"; shift 2 ;;
        --sdk-dir)  SDK_DIR="$2"; shift 2 ;;
        --ddi-dir)  DDI_DIR="$2"; shift 2 ;;
        --sdk-only) SDK_ONLY=1; shift ;;
        -h|--help)  usage; exit 0 ;;
        *) echo "build-api-index: unknown argument: $1" >&2; exit 2 ;;
    esac
done

command -v git >/dev/null 2>&1 || { echo "build-api-index: git is required" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "build-api-index: python3 is required" >&2; exit 1; }

SDK_REPO="https://github.com/MicrosoftDocs/sdk-api.git"
DDI_REPO="https://github.com/MicrosoftDocs/windows-driver-docs-ddi.git"

mkdir -p "$WORK"

# Shallow, blob-filtered sparse checkout: we only need the function pages.
clone_sparse() {
    local repo="$1" dir="$2" content="$3"
    if [[ ! -d "$dir/.git" ]]; then
        echo "[clone] $repo"
        git clone --depth 1 --filter=blob:none --sparse "$repo" "$dir" >/dev/null
    else
        echo "[cache] $dir"
    fi
    git -C "$dir" sparse-checkout set "$content" >/dev/null
}

SDK_DIR="${SDK_DIR:-$WORK/sdk-api}"
clone_sparse "$SDK_REPO" "$SDK_DIR" "sdk-api-src/content"

ARGS=(
    --malapi "$REPO_ROOT/assets/api_index/malapi.json"
    --sdk-api "$SDK_DIR/sdk-api-src/content"
    --out "$OUT"
)

if [[ "$SDK_ONLY" -eq 0 ]]; then
    DDI_DIR="${DDI_DIR:-$WORK/windows-driver-docs-ddi}"
    clone_sparse "$DDI_REPO" "$DDI_DIR" "wdk-ddi-src/content"
    ARGS+=(--sdk-api "$DDI_DIR/wdk-ddi-src/content")
fi

echo "[build] $OUT"
python3 "$REPO_ROOT/revai/api_index_build.py" "${ARGS[@]}"

SIZE="$(du -h "$OUT" | cut -f1)"
cat <<EOF

Built: $OUT ($SIZE)
Source clones are cached under $WORK (delete them to reclaim disk; a rebuild re-clones).

Deploy to the analysis VM (the VM stays offline):
  scp "$OUT" <user>@<vm>:/opt/revai/api_index/api_index.db
  ssh <user>@<vm> 'cd /opt/scripts && python3 cli.py api_lookup --info'

Notes:
  - deploy.sh preserves an existing VM index; REVAI_FORCE_API_INDEX=1 replaces it
    with the bundled 369-API default.
  - Attribution for the ingested Microsoft documentation (CC BY 4.0) is written
    into the index itself; keep assets/api_index/NOTICE.md with any copy.
EOF
