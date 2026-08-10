#!/usr/bin/env bash
set -euo pipefail

# Build and install the CADRE custom Ghidra PE loader extension.
# Run this on the REMnux lab VM (or any machine with GHIDRA_HOME set).

GHIDRA_HOME="${GHIDRA_HOME:-/opt/ghidra}"
SRC_DIR="$(cd "$(dirname "$0")" && pwd)/src/main/java"
BUILD_DIR="$(cd "$(dirname "$0")" && pwd)/build"
# Install location. System extensions (visible to analyzeHeadless) live at
# $GHIDRA_HOME/Ghidra/Extensions/<name>.  User extensions are NOT loaded by
# analyzeHeadless, so the default is the system path (requires write access).
EXT_DIR="${GHIDRA_EXT_DIR:-$GHIDRA_HOME/Ghidra/Extensions/CADRE}"

if [ ! -d "$GHIDRA_HOME" ]; then
    echo "GHIDRA_HOME not found: $GHIDRA_HOME" >&2
    exit 1
fi

# Collect all Ghidra jars into a classpath.
CP=""
while IFS= read -r -d '' jar; do
    CP="$CP:$jar"
done < <(find "$GHIDRA_HOME" -name "*.jar" -print0)

mkdir -p "$BUILD_DIR/classes"

javac -cp "$CP" -d "$BUILD_DIR/classes" "$SRC_DIR/cadre/revai/ghidra/CADREPeLoader.java"

mkdir -p "$EXT_DIR/lib"
jar cf "$EXT_DIR/lib/CADRE.jar" -C "$BUILD_DIR/classes" .

cp "$(dirname "$0")/Module.manifest" "$EXT_DIR/"
cp "$(dirname "$0")/extension.properties" "$EXT_DIR/"

echo "CADRE PE Loader installed to $EXT_DIR"
echo "Restart Ghidra or run analyzeHeadless to pick up the new loader."
