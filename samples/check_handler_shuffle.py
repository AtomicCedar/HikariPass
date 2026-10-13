#!/usr/bin/env python3
"""T8 RED gate: handler BBs of the interpreter must not appear in bytecode
order (their textual/creation order). Generates a noenc vmp module and checks
that the order of handler entry blocks in the .ll differs from the fixed
handler order ALLOCA,LOAD,STORE,BINOP,ICMP,BR,RET,GEP,CALL,CAST,SELECT,FENCE.
We identify handlers by their first distinctive call: read_var (alloca/load/
select) vs eval vs direct code reads. Simpler robust proxy: creation order of
the switch cases' target blocks == BB order in the function. Emit a module
and extract, for the host function, the sequence of block indices that the
main switch targets; assert it is NOT strictly increasing.
"""
import re, subprocess, sys, os, tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PLUGIN = os.environ.get("PLUGIN", os.path.join(ROOT, "build-llvm21/obfuscation/libHikari.so"))
LLVM = os.environ.get("LLVM_BIN", "/usr/lib/llvm-21/bin")
OPT = os.path.join(LLVM, "opt")
LLC = os.path.join(LLVM, "llc")
CLANG = os.path.join(LLVM, "clang")

SRC = os.path.join(ROOT, "samples", "c", "vmp_add.c")

def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)

with tempfile.TemporaryDirectory() as td:
    ll = os.path.join(td, "v.ll")
    bc = os.path.join(td, "v.bc")
    llc_bc = os.path.join(td, "v_o.bc")
    # c -> ll
    r = run([CLANG, "-O0", "-emit-llvm", "-S", "-Xclang", "-disable-O0-optnone", SRC, "-o", ll])
    if r.returncode: print("clang fail:", r.stderr); sys.exit(2)
    # vmp (noenc for stable inspection is irrelevant — structure is the same)
    env = dict(os.environ, VMPNOENC="1")
    r = run([OPT, "-load-pass-plugin", PLUGIN, "--passes=hikari(enable-vmp)", ll, "-o", bc], env=env)
    if r.returncode: print("opt fail:", r.stderr[-2000:]); sys.exit(2)
    r = run([os.path.join(LLVM, "llvm-dis"), bc, "-o", llc_bc])
    s = open(llc_bc).read()
    # Token-entry hardening: the interpreter lives in vmp_entry_<fn>
    mfn = re.search(r"define internal [^@]*@vmp_entry_vmp_add\(.*?\n}", s, re.S)
    if not mfn:
        mfn = re.search(r"define dso_local i32 @vmp_add\(.*?\n}", s, re.S)
    fn = mfn.group(0)
    # find the main opcode switch: switch on an i8 with ~12 cases
    m = None
    targets = []
    for sm in re.finditer(r"switch i8 %(\d+), label %(\d+) \[(.*?)\]", fn, re.S):
        cases = re.findall(r"i8 (-?\d+), label %(\d+)", sm.group(3))
        if len(cases) >= 12 and any(int(v) < 0 for v, _ in cases):
            m = sm; targets = [int(l) for _, l in cases]; break
    if not m or not targets:
        print("T8-handler-shuffle: no opcode switch found"); sys.exit(1)
    # textual block order in the function
    order = {int(l): i for i, l in enumerate(re.findall(r"^(\d+):", fn, re.M))}
    seq = [order[t] for t in targets]
    if seq == sorted(seq):
        print("T8-handler-shuffle: FAIL — handler blocks are in bytecode order:", seq)
        sys.exit(1)
    print("T8-handler-shuffle: PASS — handlers shuffled:", seq)
    sys.exit(0)
