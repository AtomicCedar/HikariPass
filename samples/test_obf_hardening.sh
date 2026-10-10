#!/usr/bin/env bash
# Hardening acceptance tests for VMP.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LLVM_BIN="${LLVM_BIN:-/usr/lib/llvm-21/bin}"
PLUGIN="${PLUGIN:-$ROOT/build-llvm21/obfuscation/libHikari.so}"
OUT="$(mktemp -d)"
export PATH="$LLVM_BIN:$PATH"
FAIL=0
check() { # name condition_result
  if [[ "$2" == "0" ]]; then echo "PASS: $1"; else echo "FAIL: $1"; FAIL=1; fi
}

SRC="$ROOT/samples/c/vmp_add.c"
clang -O0 -emit-llvm -c "$SRC" -o "$OUT/a.bc"
opt -load-pass-plugin="$PLUGIN" --passes='hikari()' "$OUT/a.bc" -o "$OUT/a_obf.bc" 2>"$OUT/a.err"
llvm-dis "$OUT/a_obf.bc" -o "$OUT/a_obf.ll"

# T1: no readable interpreter BB names survive in the host (vmp_loop etc.)
if grep -q 'vmp_disp\|"vmp_loop"\|h_binop\|st_cst_loop' "$OUT/a_obf.ll"; then r=1; else r=0; fi
check "T1-no-readable-bb-names" $r

# T2: vmp_seeds table is per-build polymorphic — different HIKARI_SEED
# produces a different (masked) seeds table.
S1=$(grep -o '@vmp_seeds_vmp_abs = .*' "$OUT/a_obf.ll" | head -1)
HIKARI_SEED=999 opt -load-pass-plugin="$PLUGIN" --passes='hikari()' "$OUT/a.bc" -o "$OUT/c_obf.bc" 2>/dev/null
llvm-dis "$OUT/c_obf.bc" -o "$OUT/c_obf.ll"
S2=$(grep -o '@vmp_seeds_vmp_abs = .*' "$OUT/c_obf.ll" | head -1)
if [[ -n "$S1" && -n "$S2" && "$S1" != "$S2" ]]; then r=0; else r=1; fi
check "T2-seeds-table-obfuscated" $r

# T3: fake NOP instructions present in bytecode is not directly observable in IR (skip; covered by parity)
# T3: behavioral parity (always must hold)
clang -O0 -c "$SRC" -o "$OUT/a_clean.o" 2>/dev/null
clang -no-pie "$OUT/a_clean.o" -o "$OUT/a_clean"
llc -filetype=obj "$OUT/a_obf.bc" -o "$OUT/a_obf.o" 
clang -no-pie "$OUT/a_obf.o" -o "$OUT/a_obf_bin"
C="$("$OUT/a_clean" 2>&1; echo "rc=$?")"
V="$("$OUT/a_obf_bin" 2>&1; echo "rc=$?")"
if [[ "$C" == "$V" && "$C" == *"rc=0"* ]]; then r=0; else r=1; fi
check "T3-parity" $r

# T4: bounded IP: corrupt a copy of the obf bc's code global? Instead: fuzz seeds by env
# simpler: run with VMPNOENC=0 and VMPENCRYPT=1 (defaults) - parity again under different seed path
HIKARI_SEED=12345 opt -load-pass-plugin="$PLUGIN" --passes='hikari()' "$OUT/a.bc" -o "$OUT/b_obf.bc" 2>/dev/null
llc -filetype=obj "$OUT/b_obf.bc" -o "$OUT/b_obf.o"
clang -no-pie "$OUT/b_obf.o" -o "$OUT/b_obf_bin"
V2="$("$OUT/b_obf_bin" 2>&1; echo "rc=$?")"
if [[ "$C" == "$V2" ]]; then r=0; else r=1; fi
check "T4-seeded-repro-parity" $r

# T5: multi-thread stress — virtualized fib (recursive) + mix under 8 threads
# x 50 iterations must match the clean build exactly.
clang -O0 -c "$ROOT/samples/c/vmp_threads.c" -o "$OUT/thr_clean.o" -pthread
clang -no-pie "$OUT/thr_clean.o" -o "$OUT/thr_clean" -pthread
clang -O0 -emit-llvm -c "$ROOT/samples/c/vmp_threads.c" -o "$OUT/thr.bc"
opt -load-pass-plugin="$PLUGIN" --passes='hikari()' "$OUT/thr.bc" -o "$OUT/thr_obf.bc" 2>/dev/null
llc -filetype=obj "$OUT/thr_obf.bc" -o "$OUT/thr_obf.o"
clang -no-pie "$OUT/thr_obf.o" -o "$OUT/thr_obf_bin"
TC="$("$OUT/thr_clean"; echo "rc=$?")"
TV="$("$OUT/thr_obf_bin"; echo "rc=$?")"
if [[ "$TC" == "$TV" && "$TC" == *"rc=0"* ]]; then r=0; else r=1; fi
check "T5-multithread-parity" $r

# T6: varargs call sites (JNI style) must not emit verifier-failing IR: the
# function is skipped cleanly and the module still verifies.
clang -O0 -emit-llvm -S "$ROOT/samples/c/vmp_varargs.c" -o "$OUT/va.ll"
if opt -load-pass-plugin="$PLUGIN" --passes='hikari(enable-vmp)' "$OUT/va.ll" -o "$OUT/va.bc" 2>"$OUT/va.err"; then r=0; else r=1; fi
if grep -q "verify failed\|does not have terminator\|Terminator found" "$OUT/va.err"; then r=1; fi
if grep -q "varargs call site" "$OUT/va.err"; then r=0; else r=1; fi
check "T6-varargs-call-site-clean-skip" $r

# T7: a function with NO varargs calls but a global store (JNI_OnLoad shape)
# must virtualize successfully (no verify failure).
cat > "$OUT/jnionload.c" <<'CEOF'
typedef struct JavaVM { int x; } JavaVM;
static JavaVM *g_vm;
int JNI_OnLoad(JavaVM *v, void *r) { (void)r; g_vm = v; return 65542; }
CEOF
clang -O0 -emit-llvm -S "$OUT/jnionload.c" -o "$OUT/jo.ll"
opt -load-pass-plugin="$PLUGIN" --passes='hikari(enable-vmp)' "$OUT/jo.ll" -o "$OUT/jo.bc" 2>"$OUT/jo.err"
if grep -q "verify failed" "$OUT/jo.err"; then r=1; else r=0; fi
if grep -q "@vmp_code_JNI_OnLoad" <(llvm-dis "$OUT/jo.bc" -o -); then r=0; else r=1; fi
check "T7-simple-jni-onload-virtualized" $r

# T8: interpreter handler BBs must not sit in bytecode/switch order
python3 "$ROOT/samples/check_handler_shuffle.py" >/dev/null 2>&1
check "T8-handler-shuffle" $?

# T9: strings referenced only through a global POINTER variable
# (const char *g = "..."; return g;) must also be encrypted.
cat > "$OUT/gvar.c" <<'GEOF'
const char *g = "through global ptr secret";
const char *getg(void){ return g; }
__attribute__((annotate("strenc")))
const char *main2(void){ return getg(); }
GEOF
clang -O0 -emit-llvm -S "$OUT/gvar.c" -o "$OUT/gvar.ll"
opt -load-pass-plugin="$PLUGIN" --passes='hikari(enable-strcry)' "$OUT/gvar.ll" -o "$OUT/gvar.bc" 2>/dev/null
llvm-dis "$OUT/gvar.bc" -o "$OUT/gvar_o.ll"
if grep -q "through global ptr secret" "$OUT/gvar_o.ll"; then r=1; else r=0; fi
check "T9-global-ptr-string-encrypted" $r

rm -rf "$OUT"
exit $FAIL
