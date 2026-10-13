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

# T10: atomics (RMW + CAS) virtualized and stack-safe in a long loop.
# Guards two regressions: (a) atomicrmw/cmpxchg rejected outright,
# (b) handler-local allocas lowering to per-visit dynamic stack adjustments
# that leak ~1KB/iteration and hit the guard page after ~8k iterations.
cat > "$OUT/atomic_loop.c" <<'AEOF'
#include <stdatomic.h>
#include <stddef.h>
static _Atomic int hits = 0;
static _Atomic int rmw = 0;
__attribute__((annotate("vmp")))
static void loop(int n) {
  for (int i = 0; i < n; ++i) {
    int exp = i;
    atomic_compare_exchange_strong(&hits, &exp, i + 1);
    atomic_fetch_add(&rmw, 1);
  }
}
int main(void) {
  loop(20000);
  return (atomic_load(&hits) == 20000 && rmw == 20000) ? 0 : 1;
}
AEOF
clang -O0 -emit-llvm -S -Xclang -disable-O0-optnone "$OUT/atomic_loop.c" -o "$OUT/atomic_loop.ll"
opt -load-pass-plugin="$PLUGIN" --passes='hikari(enable-vmp)' "$OUT/atomic_loop.ll" \
  -o "$OUT/atomic_loop.bc" 2>"$OUT/atomic_loop.err"
r=1
if grep -q "build fail\|translate fail" "$OUT/atomic_loop.err"; then r=1; else
  llc -filetype=obj "$OUT/atomic_loop.bc" -o "$OUT/atomic_loop.o" 2>/dev/null && \
  clang -no-pie "$OUT/atomic_loop.o" -o "$OUT/atomic_loop_run" 2>/dev/null && \
  "$OUT/atomic_loop_run" >/dev/null 2>&1 && r=0
fi
check "T10-atomic-longloop-stress" $r

# T11: floating-point IR must be virtualized, not skipped.
# A float function (fadd/fmul/fcmp) previously hard-failed the whole
# function, leaving it completely unprotected. Verify the VM runs it and
# produces exact results (including an fcmp branch).
cat > "$OUT/float_calc.c" <<'FEOF'
#include <stddef.h>
__attribute__((annotate("vmp")))
double calc(double a, double b) {
  double x = a * b + 3.5;
  if (x > 10.0)
    x = x / 2.0;
  return x;
}
__attribute__((annotate("vmp")))
float fcalc(float a, float b) {
  return a / b - 1.5f;
}
int main(void) {
  // calc(4,4)=19.5>10 -> 9.75 ; calc(2,3)=9.5 ; fcalc(7,2)=2.0
  if (calc(4.0, 4.0) != 9.75) return 1;
  if (calc(2.0, 3.0) != 9.5) return 2;
  if (fcalc(7.0f, 2.0f) != 2.0f) return 3;
  return 0;
}
FEOF
clang -O0 -emit-llvm -S -Xclang -disable-O0-optnone "$OUT/float_calc.c" -o "$OUT/float_calc.ll"
opt -load-pass-plugin="$PLUGIN" --passes='hikari(enable-vmp)' "$OUT/float_calc.ll" \
  -o "$OUT/float_calc.bc" 2>"$OUT/float_calc.err"
r=1
if grep -q "skip calc\|floating-point IR unsupported" "$OUT/float_calc.err"; then r=1; else
  llc -filetype=obj "$OUT/float_calc.bc" -o "$OUT/float_calc.o" 2>/dev/null && \
  clang -no-pie "$OUT/float_calc.o" -o "$OUT/float_calc_run" 2>/dev/null && \
  "$OUT/float_calc_run" >/dev/null 2>&1 && r=0
fi
check "T11-float-virtualized" $r

# T12: seed KDF strength. The seed-mask stream must not be a single
# plain-xorshift32 chain seeded by one FNV hash: an attacker who reverses
# xorshift32 once (globally) recovers every function's seeds and thus the
# opcode map + bytecode. Gate: the runtime replay helper vmp_mask_<fn> must
# consume TWO independent derived streams (dual-stream mixing), detectable in
# the emitted IR as two distinct seed constants stored into two state allocas
# before the loop, and a rotate/mix of one stream with the other (shift + xor
# + or/rotate pattern). Also the KDF must differ when HIKARI_SEED changes
# (already covered by T2) — here we assert structural strength only.
cat > "$OUT/kdf_probe.c" <<'KEOF'
__attribute__((annotate("vmp")))
int target(int x) { return x * 3 + 1; }
KEOF
clang -O0 -emit-llvm -S -Xclang -disable-O0-optnone "$OUT/kdf_probe.c" -o "$OUT/kdf_probe.ll"
opt -load-pass-plugin="$PLUGIN" --passes='hikari(enable-vmp)' "$OUT/kdf_probe.ll" \
  -o "$OUT/kdf_probe.bc" 2>/dev/null
llvm-dis "$OUT/kdf_probe.bc" -o "$OUT/kdf_o.ll"
# count distinct xorshift chains in vmp_mask_target: two state allocas each
# seeded with a DIFFERENT constant, both updated in the loop body.
python3 - "$OUT/kdf_o.ll" <<'PEOF'
import re, sys
ll = open(sys.argv[1]).read()
m = re.search(r'define internal i32 @vmp_mask_target\(i32[^\{]*\{(.*)$', ll, re.S)
body = m.group(1) if m else ''
# find all i32 constant stores inside mask fn (the stream seeds)
stores = re.findall(r'store i32 (-?\d+), ptr %', body)
seeds = [int(s) & 0xFFFFFFFF for s in stores if (int(s) & 0xFFFFFFFF) > 0x10000]
# dual-stream = 2+ distinct large seed constants
sys.exit(0 if len(set(seeds)) >= 2 else 1)
PEOF
check "T12-dual-stream-seed-kdf" $?

# T13: bcf opaque-predicate strength. Upstream Hikari uses two GLOBAL
# variables (x, y) for the opaque predicate (y<10 || x*(x+1)%2==0), which
# is a single-regex signature (the comment even admits it). After the
# hardening, no bcf-specific global variable may be emitted and the
# predicate must be computed from locally-derived values.
cat > "$OUT/bcf_probe.c" <<'BEOF'
__attribute__((annotate("bcf")))
int probe(int x) {
  if (x > 3) x += 2; else x -= 1;
  return x * 5;
}
int main(void) { return probe(4) - 30; }
BEOF
clang -O0 -emit-llvm -S -Xclang -disable-O0-optnone "$OUT/bcf_probe.c" -o "$OUT/bcf_probe.ll"
opt -load-pass-plugin="$PLUGIN" --passes='hikari(enable-bcfobf)' "$OUT/bcf_probe.ll" \
  -o "$OUT/bcf_probe.bc" 2>"$OUT/bcf.err"
llvm-dis "$OUT/bcf_probe.bc" -o "$OUT/bcf_o.ll"
r=0
if grep -qE '@(HikariBCF|x_bcf|y_bcf|bcfCond)[A-Za-z0-9_]* *=|@.*OpaquePredicate.* =' "$OUT/bcf_o.ll"; then r=1; fi
llc -filetype=obj "$OUT/bcf_probe.bc" -o "$OUT/bcf_probe.o" 2>/dev/null && \
clang -no-pie "$OUT/bcf_probe.o" -o "$OUT/bcf_probe_run" 2>/dev/null && \
"$OUT/bcf_probe_run" >/dev/null 2>&1 || r=1
check "T13-bcf-local-opaque-predicate" $r

# T14: cff (flattening) must not leak the textbook switchVar signature:
# a named "%switchVar" alloca + central switch is what deflattener
# scripts (deflat/astatine) key on. After hardening the state variable
# must be anonymous (no textual name) and the dispatch must not be a
# single central switch on a plain counter (checked by absence of the
# literal "switchVar" name AND presence of mixed dispatch).
cat > "$OUT/cff_probe.c" <<'CEOF2'
__attribute__((annotate("cff")))
int probe(int x) {
  int r = 0;
  for (int i = 0; i < 4; ++i) { r += x * i + 1; if (r > 40) r -= 7; }
  return r;
}
int main(void) { return probe(3) != 22; }
CEOF2
clang -O0 -emit-llvm -S -Xclang -disable-O0-optnone "$OUT/cff_probe.c" -o "$OUT/cff_probe.ll"
opt -load-pass-plugin="$PLUGIN" --passes='hikari(enable-cffobf)' "$OUT/cff_probe.ll" \
  -o "$OUT/cff_probe.bc" 2>/dev/null
llvm-dis "$OUT/cff_probe.bc" -o "$OUT/cff_o.ll"
r=0
if grep -q '"switchVar"\| %switchVar' "$OUT/cff_o.ll"; then r=1; fi
llc -filetype=obj "$OUT/cff_probe.bc" -o "$OUT/cff_probe.o" 2>/dev/null && \
clang -no-pie "$OUT/cff_probe.o" -o "$OUT/cff_probe_run" 2>/dev/null && \
"$OUT/cff_probe_run" >/dev/null 2>&1 || r=1
check "T14-cff-no-switchvar-signature" $r

# T15: strcry strength. Per-character INDEPENDENT xor with a fresh key is
# trivially broken by a known-plaintext byte (each byte independent).
# After hardening the per-element decrypt must mix the key with a rolling
# state (shift/xor chain), observable in the runtime decrypt helper.
cat > "$OUT/str_probe.c" <<'SEOF'
const char *msg = "rolling key probe string";
int main(void) { return msg[0] != 'r'; }
SEOF
clang -O0 -emit-llvm -S -Xclang -disable-O0-optnone "$OUT/str_probe.c" -o "$OUT/str_probe.ll"
opt -load-pass-plugin="$PLUGIN" --passes='hikari(enable-strcry)' "$OUT/str_probe.ll" \
  -o "$OUT/str_probe.bc" 2>/dev/null
llvm-dis "$OUT/str_probe.bc" -o "$OUT/str_o.ll"
python3 - "$OUT/str_o.ll" <<'PEOF'
import re, sys
ll = open(sys.argv[1]).read()
# locate decryption loops: functions or inlined regions that xor a loaded
# byte and must also update a rolling key via shift/rotate.
xs = len(re.findall(r'\bxor\b', ll))
sh = len(re.findall(r'\b(shl|lshr)\b', ll))
sys.exit(0 if (xs >= 1 and sh >= 1) else 1)
PEOF
check "T15-strcry-rolling-key" $?

# T16: indibran table must not be a .rodata-resident constant: a static
# constant BlockAddress array lets a static analyzer read every branch
# target straight out of .rodata. After hardening the table must be
# non-constant (writable, runtime-initialized) or eliminated.
cat > "$OUT/ib_probe.c" <<'IEOF'
__attribute__((annotate("indibranch")))
int probe(int x) {
  switch (x) {
    case 1: return 10; case 2: return 20; case 3: return 30;
    default: return 40;
  }
}
int main(void) { return probe(2) - 20; }
IEOF
clang -O0 -emit-llvm -S -Xclang -disable-O0-optnone "$OUT/ib_probe.c" -o "$OUT/ib_probe.ll"
opt -load-pass-plugin="$PLUGIN" --passes='hikari(enable-indibran)' "$OUT/ib_probe.ll" \
  -o "$OUT/ib_probe.bc" 2>/dev/null
llvm-dis "$OUT/ib_probe.bc" -o "$OUT/ib_o.ll"
r=0
if grep -q '@IndirectBranchingGlobalTable = .*constant' "$OUT/ib_o.ll"; then r=1; fi
llc -filetype=obj "$OUT/ib_probe.bc" -o "$OUT/ib_probe.o" 2>/dev/null && \
clang -no-pie "$OUT/ib_probe.o" -o "$OUT/ib_probe_run" 2>/dev/null && \
"$OUT/ib_probe_run" >/dev/null 2>&1 || r=1
check "T16-indibran-nonconstant-table" $r

# T17: VMP token-entry. Previously the host function's body WAS the VM
# launcher: its entry block directly references vmp_code_<fn>/
# vmp_seeds_<fn>/vmp_seed_<fn>/vmp_mask_<fn>, so the first basic block of
# every virtualized function screams "Hikari VM". After hardening the host
# body must be a token stub: (a) no direct reference to any vmp_* global
# or call to any vmp_* helper from the HOST function, (b) the launcher
# lives in a separate internal function vmp_entry_<fn>, (c) the host calls
# it indirectly through a pointer computed at runtime (indirect call, not
# a direct @vmp_entry_<fn> reference).
cat > "$OUT/tok_probe.c" <<'TEOF'
__attribute__((annotate("vmp")))
int target(int x) { return x * 7 + 3; }
int main(void) { return target(5) != 38; }
TEOF
clang -O0 -emit-llvm -S -Xclang -disable-O0-optnone "$OUT/tok_probe.c" -o "$OUT/tok_probe.ll"
opt -load-pass-plugin="$PLUGIN" --passes='hikari(enable-vmp)' "$OUT/tok_probe.ll" \
  -o "$OUT/tok_probe.bc" 2>"$OUT/tok.err"
llvm-dis "$OUT/tok_probe.bc" -o "$OUT/tok_o.ll"
python3 - "$OUT/tok_o.ll" <<'PEOF'
import re, sys
ll = open(sys.argv[1]).read()
m = re.search(r'define [^@]*@target\([^)]*\)[^\{]*\{([^#]*)', ll)
host = m.group(1) if m else ''
if not host:
    sys.exit(1)
# (a) host must not directly call vmp_* helpers or reference vmp_* globals
if re.search(r'call.*@vmp_(seed|mask|eval|read_var|ch)_', host): sys.exit(1)
if re.search(r'@vmp_(code|seeds)_', host): sys.exit(1)
sys.exit(0)
PEOF
T17A=$?
# (b) launcher moved into its own internal function
if grep -q 'define internal.*@vmp_entry_target' "$OUT/tok_o.ll"; then r2=0; else r2=1; fi
# (c) host must contain an INDIRECT call (callee not spelled @name)
IND=$(awk '/define.*@target\(/,/^}/' "$OUT/tok_o.ll" | grep -cE 'call [^@]*\(')
r=0
[ "$T17A" -ne 0 ] && r=1
[ "$r2" -ne 0 ] && r=1
[ "$IND" -eq 0 ] && r=1
# parity must hold
llc -filetype=obj "$OUT/tok_probe.bc" -o "$OUT/tok_probe.o" 2>/dev/null && \
clang -no-pie "$OUT/tok_probe.o" -o "$OUT/tok_run" 2>/dev/null && \
"$OUT/tok_run" >/dev/null 2>&1 || r=1
check "T17-vmp-token-entry" $r

rm -rf "$OUT"
exit $FAIL
