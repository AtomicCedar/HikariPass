#!/usr/bin/env bash
# VMP acceptance: clean vs virtualized parity + IR markers.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LLVM_BIN="${LLVM_BIN:-/opt/homebrew/opt/llvm/bin}"
OUT="${ROOT}/samples/out"
PASSES="${PASSES:-hikari()}"

if [[ -z "${PLUGIN:-}" ]]; then
  for cand in \
    "${ROOT}/build/obfuscation/libHikari.dylib" \
    "${ROOT}/build-llvm22/obfuscation/libHikari.dylib" \
    "${ROOT}/build/obfuscation/libHikari.so" \
    "${ROOT}/build-llvm22/obfuscation/libHikari.so"; do
    if [[ -f "$cand" ]]; then
      PLUGIN="$cand"
      break
    fi
  done
fi

if [[ -z "${PLUGIN:-}" || ! -f "$PLUGIN" ]]; then
  echo "error: libHikari not found" >&2
  exit 1
fi

mkdir -p "$OUT"
export PATH="$LLVM_BIN:$PATH"

SRC="$ROOT/samples/c/vmp_add.c"
echo "==> Plugin: $PLUGIN"
echo "==> Passes: $PASSES"

clang -O0 -emit-llvm -c "$SRC" -o "$OUT/vmp_add.bc"
cp "$OUT/vmp_add.bc" "$OUT/vmp_add_clean.bc"

opt -load-pass-plugin="$PLUGIN" --passes="$PASSES" \
  "$OUT/vmp_add.bc" -o "$OUT/vmp_add_obf.bc" 2>"$OUT/vmp_opt.err"

llvm-dis "$OUT/vmp_add_clean.bc" -o "$OUT/vmp_add_clean.ll"
llvm-dis "$OUT/vmp_add_obf.bc" -o "$OUT/vmp_add_obf.ll"

llc -filetype=obj "$OUT/vmp_add_clean.bc" -o "$OUT/vmp_add_clean.o"
llc -filetype=obj "$OUT/vmp_add_obf.bc" -o "$OUT/vmp_add_obf.o"
clang -no-pie "$OUT/vmp_add_clean.o" -o "$OUT/vmp_add_clean"
clang -no-pie "$OUT/vmp_add_obf.o" -o "$OUT/vmp_add_obf"

echo "-- clean --"
CLEAN_OUT="$("$OUT/vmp_add_clean")"
echo "$CLEAN_OUT"
echo "-- vmp  --"
VMP_OUT="$("$OUT/vmp_add_obf")"
echo "$VMP_OUT"

if [[ "$CLEAN_OUT" != "$VMP_OUT" ]]; then
  echo "error: clean vs vmp output mismatch" >&2
  exit 1
fi

echo
echo "-- IR markers --"
echo "vmp_loop count:  $(rg -c 'vmp_loop' "$OUT/vmp_add_obf.ll" || true)"
echo "vmp_code count:  $(rg -c '@vmp_code_' "$OUT/vmp_add_obf.ll" || true)"
echo "vmp_seeds count: $(rg -c '@vmp_seeds_' "$OUT/vmp_add_obf.ll" || true)"
echo "vmp_ch count:    $(rg -c '@vmp_ch_' "$OUT/vmp_add_obf.ll" || true)"
echo "bytecode globals:"
rg -o '@vmp_code_[A-Za-z0-9_]+' "$OUT/vmp_add_obf.ll" | sort -u

# Expect encryption by default
if ! rg -q 'encrypt=1' "$OUT/vmp_opt.err"; then
  echo "error: expected encrypt=1 in opt log (default L1 encryption)" >&2
  exit 1
fi
if ! rg -q '@vmp_seeds_' "$OUT/vmp_add_obf.ll"; then
  echo "error: missing vmp_seeds_ tables" >&2
  exit 1
fi
# Expect reentrancy sample virtualized
if ! rg -q '@vmp_code_vmp_fact' "$OUT/vmp_add_obf.ll"; then
  echo "error: vmp_fact not virtualized" >&2
  exit 1
fi

echo
echo "OK: VMP acceptance sample matched clean results (encrypt + reentrancy markers)"
