#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LLVM_BIN="${LLVM_BIN:-/opt/homebrew/opt/llvm/bin}"
OUT="${ROOT}/samples/out"
PASSES="${PASSES:-hikari(enable-bcfobf,enable-cffobf,enable-subobf,enable-splitobf,enable-strcry,enable-indibran)}"

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
  echo "error: libHikari not found. Build the plugin first, e.g.:" >&2
  echo "  cmake -G Ninja -S . -B build -DLT_LLVM_INSTALL_DIR=/opt/homebrew/opt/llvm && cmake --build build" >&2
  echo "Or set PLUGIN=/path/to/libHikari.dylib" >&2
  exit 1
fi

mkdir -p "$OUT"
export PATH="$LLVM_BIN:$PATH"

echo "==> LLVM: $(llvm-config --version 2>/dev/null || echo unknown)"
echo "==> Plugin: $PLUGIN"
echo "==> Passes: $PASSES"
echo "==> Note: Objective-C support has been removed from this plugin."


############################################
# C sample
############################################
echo
echo "========== C sample =========="
clang -O0 -emit-llvm -c "$ROOT/samples/c/hello.c" -o "$OUT/hello.bc"
cp "$OUT/hello.bc" "$OUT/hello_clean.bc"

opt -load-pass-plugin="$PLUGIN" --passes="$PASSES" \
  "$OUT/hello.bc" -o "$OUT/hello_obf.bc"

# IR text for comparison
llvm-dis "$OUT/hello_clean.bc" -o "$OUT/hello_clean.ll"
llvm-dis "$OUT/hello_obf.bc" -o "$OUT/hello_obf.ll"

# Object + binary
llc -filetype=obj "$OUT/hello_clean.bc" -o "$OUT/hello_clean.o"
llc -filetype=obj "$OUT/hello_obf.bc" -o "$OUT/hello_obf.o"
clang -no-pie "$OUT/hello_clean.o" -o "$OUT/hello_clean"
clang -no-pie "$OUT/hello_obf.o" -o "$OUT/hello_obf"

echo "-- clean run --"
"$OUT/hello_clean" 2 "hikari-secret-2026" || true
echo "-- obf run --"
"$OUT/hello_obf" 2 "hikari-secret-2026" || true

echo
echo "-- sizes --"
ls -la "$OUT/hello_clean" "$OUT/hello_obf"
echo
echo "-- strings (secret / message) --"
echo "clean:"
strings "$OUT/hello_clean" | rg -n "hikari-secret|Hello from Hikari|access granted" || true
echo "obf:"
strings "$OUT/hello_obf" | rg -n "hikari-secret|Hello from Hikari|access granted" || true

echo
echo "-- disasm classify() snippet --"
echo "===== CLEAN classify ====="
objdump -d --no-show-raw-insn "$OUT/hello_clean" 2>/dev/null \
  | awk '/<_classify>:/{p=1} p{print} p&&/^$/{if(++c>0 && NR>1) exit}' \
  | head -60 || true
echo "===== OBF classify ====="
# mangled names may differ; search by symbol or just dump main-ish
nm "$OUT/hello_obf" | rg -i "classify|main|check" || true
objdump -d --no-show-raw-insn "$OUT/hello_obf" 2>/dev/null \
  | awk '/<_classify>:/{p=1} p{print} /^_/{if(p&&!/<_classify>/){exit}}' \
  | head -80 || true

echo
echo "-- IR stats --"
echo "clean IR lines: $(wc -l < "$OUT/hello_clean.ll")"
echo "obf   IR lines: $(wc -l < "$OUT/hello_obf.ll")"
echo "clean functions: $(rg -c '^define ' "$OUT/hello_clean.ll" || true)"
echo "obf   functions: $(rg -c '^define ' "$OUT/hello_obf.ll" || true)"
echo "clean br/switch: $(rg -c '\b(br|switch)\b' "$OUT/hello_clean.ll" || true)"
echo "obf   br/switch: $(rg -c '\b(br|switch)\b' "$OUT/hello_obf.ll" || true)"
echo "clean xor: $(rg -c '\bxor\b' "$OUT/hello_clean.ll" || true)"
echo "obf   xor: $(rg -c '\bxor\b' "$OUT/hello_obf.ll" || true)"

############################################
# Rust sample
############################################
echo
echo "========== Rust sample =========="
pushd "$ROOT/samples/rust" >/dev/null

# clean
cargo +nightly rustc --release --target-dir "$OUT/rust-clean" -- 2>/dev/null
# obf
cargo +nightly rustc --release --target-dir "$OUT/rust-obf" -- \
  -C opt-level=0 \
  -Zllvm-plugins="$PLUGIN" \
  -Cpasses="$PASSES"

CLEAN_BIN="$OUT/rust-clean/release/hikari-sample"
OBF_BIN="$OUT/rust-obf/release/hikari-sample"

echo "-- clean run --"
"$CLEAN_BIN" 8 "HIKARI-RUST-KEY" || true
echo "-- obf run --"
"$OBF_BIN" 8 "HIKARI-RUST-KEY" || true

echo
echo "-- sizes --"
ls -la "$CLEAN_BIN" "$OBF_BIN"

echo
echo "-- strings (banner / key) --"
echo "clean:"
strings "$CLEAN_BIN" | rg -n "Hello Hikari from Rust|HIKARI-RUST-KEY|license valid" || true
echo "obf:"
strings "$OBF_BIN" | rg -n "Hello Hikari from Rust|HIKARI-RUST-KEY|license valid" || true

echo
echo "-- rust fib disasm (symbol search) --"
echo "clean symbols:"
nm "$CLEAN_BIN" | rg -i "fib|license|main" | head -20 || true
echo "obf symbols:"
nm "$OBF_BIN" | rg -i "fib|license|main" | head -20 || true

# dump a chunk of main from both
echo "===== CLEAN main (first 40 insns of entry) ====="
objdump -d --no-show-raw-insn "$CLEAN_BIN" 2>/dev/null \
  | awk '/<_main>:/{p=1} p{print; if(++n>=40) exit}'
echo "===== OBF main (first 60 insns of entry) ====="
objdump -d --no-show-raw-insn "$OBF_BIN" 2>/dev/null \
  | awk '/<_main>:/{p=1} p{print; if(++n>=60) exit}'

popd >/dev/null

echo
echo "========== Artifacts =========="
ls -la "$OUT" | sed -n '1,40p'
echo
echo "Done. IR dumps: $OUT/hello_clean.ll vs $OUT/hello_obf.ll"
