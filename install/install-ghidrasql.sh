#!/usr/bin/env bash
# install-ghidrasql.sh — build LibGhidraHost + ghidrasql and install the CLI
# Requires: Ghidra at GHIDRA_INSTALL_DIR (/opt/ghidra), JDK 21, CMake, Gradle, g++
#
# Usage:
#   sudo ./install/install-ghidrasql.sh
#   sudo GHIDRA_INSTALL_DIR=/opt/ghidra ./install/install-ghidrasql.sh

set -euo pipefail

ok()   { echo "[OK]   $1"; }
warn() { echo "[WARN] $1"; }
fail() { echo "[FAIL] $1"; exit 1; }
hdr()  { echo ""; echo "=== $1 ==="; }

GHIDRA_INSTALL_DIR="${GHIDRA_INSTALL_DIR:-/opt/ghidra}"
BUILD_ROOT="${GHIDRASQL_BUILD_ROOT:-/opt/src}"
BIN_DST="${GHIDRASQL_BIN:-/usr/local/bin/ghidrasql}"

if [[ ! -d "$GHIDRA_INSTALL_DIR" ]] || [[ ! -x "$GHIDRA_INSTALL_DIR/support/analyzeHeadless" && ! -x "$GHIDRA_INSTALL_DIR/support/ghidraRun" ]]; then
  fail "Ghidra not found at $GHIDRA_INSTALL_DIR (need support/analyzeHeadless or ghidraRun)"
fi

hdr "Install build tools"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --no-install-recommends \
  build-essential cmake ninja-build git openjdk-21-jdk gradle pkg-config \
  libssl-dev zlib1g-dev >/dev/null
ok "build tools present"

hdr "Clone libghidra + ghidrasql"
mkdir -p "$BUILD_ROOT"
cd "$BUILD_ROOT"
if [[ ! -d libghidra/.git ]]; then
  git clone --depth 1 https://github.com/0xeb/libghidra.git
else
  ok "libghidra already cloned"
fi
if [[ ! -d ghidrasql/.git ]]; then
  git clone --depth 1 https://github.com/0xeb/ghidrasql.git
else
  ok "ghidrasql already cloned"
fi

hdr "Install LibGhidraHost extension into Ghidra"
cd "$BUILD_ROOT/libghidra/ghidra-extension"
gradle installExtension "-PGHIDRA_INSTALL_DIR=$GHIDRA_INSTALL_DIR"
if [[ ! -d "$GHIDRA_INSTALL_DIR/Ghidra/Extensions/LibGhidraHost" ]]; then
  fail "LibGhidraHost missing after gradle installExtension"
fi
ok "LibGhidraHost installed"

hdr "Build ghidrasql"
cd "$BUILD_ROOT/ghidrasql"
rm -rf build
cmake -B build -DCMAKE_BUILD_TYPE=Release \
  -DGHIDRASQL_LIBGHIDRA_DIR="$BUILD_ROOT/libghidra/cpp"
cmake --build build -j"$(nproc)"

# Locate binary (layout varies by cmake version)
CAND=""
for p in \
  "$BUILD_ROOT/ghidrasql/build/ghidrasql" \
  "$BUILD_ROOT/ghidrasql/build/bin/ghidrasql" \
  "$BUILD_ROOT/ghidrasql/build/Release/ghidrasql" \
  "$BUILD_ROOT/ghidrasql/build/bin/Release/ghidrasql"
do
  if [[ -x "$p" ]]; then CAND="$p"; break; fi
done
if [[ -z "$CAND" ]]; then
  CAND="$(find "$BUILD_ROOT/ghidrasql/build" -type f -name ghidrasql -perm -111 | head -1 || true)"
fi
[[ -n "$CAND" && -x "$CAND" ]] || fail "ghidrasql binary not found under build/"

install -m 0755 "$CAND" "$BIN_DST"
ok "installed $BIN_DST"
"$BIN_DST" --help >/dev/null
ok "ghidrasql --help OK"
echo ""
echo "ghidrasql ready: $BIN_DST"
