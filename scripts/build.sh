#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
: "${THEOS:?Set THEOS to an existing Theos checkout}"
scheme="${1:-injection}"
case "$scheme" in
  injection) package_scheme=""; package_arch="iphoneos-arm" ;;
  rootless) package_scheme="rootless"; package_arch="iphoneos-arm64" ;;
  *) echo "Usage: bash scripts/build.sh [injection|rootless]" >&2; exit 2 ;;
esac
make clean
make package FINALPACKAGE=1 ARCHS=arm64 THEOS_PACKAGE_SCHEME="$package_scheme"
out="dist/$scheme"
mkdir -p "$out"
python3 scripts/verify_source_contract.py > "$out/source-contract.json"
# The Theos staging directory contains the final, stripped and signed binary.
dylib="$(find .theos/_ -type f -name WeChatEnvBypass.dylib -print -quit)"
test -n "$dylib"
cp "$dylib" "$out/WeChatEnvBypass.dylib"
cp WeChatEnvBypass.plist preferences.example.plist "$out/"
package="$(find packages -type f -name "com.macxk.wcenvbypass_*_${package_arch}.deb" -print | sort | tail -n 1)"
test -n "$package"
cp "$package" "$out/WeChatEnvBypass-$scheme.deb"
python3 scripts/verify_artifacts.py "$out" "$scheme"
