#!/usr/bin/env bash
set -euo pipefail

CXX=${CXX:-clang++-21}
CLANG_MAJOR=$("$CXX" --version | sed -n 's/.*clang version \([0-9]*\).*/\1/p')
LLVM_CONFIG=${LLVM_CONFIG:-llvm-config-$CLANG_MAJOR}
SOURCE_DIR=$(cd "$(dirname "$0")" && pwd)
OUTPUT=${1:-$SOURCE_DIR/SilkTLSCheckPass.so}

# shellcheck disable=SC2046
"$CXX" -O2 -fPIC -shared $("$LLVM_CONFIG" --cxxflags) "$SOURCE_DIR/SilkTLSCheckPass.cpp" -o "$OUTPUT"

echo "Built $OUTPUT"
echo
echo "Configure ClickHouse (debug build only — the check is compiled out under NDEBUG) with:"
echo "  -DSILK_TLS_CHECK_PASS_PLUGIN=$OUTPUT"
echo
echo "A fiber touching a thread-local that is neither SILK_TLS_BENIGN nor a FiberLocal slot calls std::terminate."
