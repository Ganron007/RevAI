#!/bin/bash
# stage_shortlist.sh — Tier 1 APT/malware shortlist on REMnux.
# Run on VM: bash /opt/scripts/stage_shortlist.sh
# Does NOT touch main CADRE repo or ansible.
set -euo pipefail

CORPUS="/opt/samples/corpus"
SHORTLIST="/opt/samples/shortlist"
GOODWARE="/opt/samples/goodware"
mkdir -p "$CORPUS" "$SHORTLIST" "$GOODWARE"

clone_sparse() {
  local url="$1"
  local dest="$2"
  local path="${3:-}"
  if [[ -d "$dest/.git" ]]; then
    echo "[skip] $dest exists"
    return 0
  fi
  echo "[clone] $url -> $dest"
  if [[ -n "$path" ]]; then
    git clone --depth 1 --filter=blob:none --sparse "$url" "$dest"
    (cd "$dest" && git sparse-checkout set $path)
  else
    git clone --depth 1 "$url" "$dest"
  fi
}

# Tier 1 — small high-value clones (user may need network on NAT)
clone_sparse "https://github.com/gentilkiwi/mimikatz.git" "$SHORTLIST/mimikatz" "x64"
clone_sparse "https://github.com/BishopFox/sliver.git" "$SHORTLIST/sliver" "implant/sliver"

# BusyBox clean baseline (if missing)
BUSY="$CORPUS/_clean/busybox"
if [[ ! -f "$BUSY" ]]; then
  mkdir -p "$(dirname "$BUSY")"
  wget -q -O "$BUSY" "https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox"
  chmod 755 "$BUSY"
fi

# Goodware seed — busybox + optional system binaries for yarGen FP checks
if [[ ! -f "$GOODWARE/busybox" ]]; then
  cp -f "$BUSY" "$GOODWARE/busybox" 2>/dev/null || true
fi

cat > "$SHORTLIST/README.md" <<'EOF'
# Tier 1 shortlist (RevAI lab)

Staged by `stage_shortlist.sh`. Add samples manually to `/opt/samples/incoming/manual-drop/`.

| Path | Purpose |
|------|---------|
| mimikatz/ | Credential tool reference |
| sliver/ | C2 implant reference |
| ../corpus/_clean/busybox | Clean FP baseline |

EOF

echo "STAGE_SHORTLIST_OK corpus=$CORPUS shortlist=$SHORTLIST goodware=$GOODWARE"
