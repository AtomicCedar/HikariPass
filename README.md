# Hikari-LLVM22

An out-of-tree LLVM 22 obfuscation pass plugin that loads dynamically into
**`opt` or `rustc` nightly** — without rebuilding LLVM or rustc.

Derived from [Hikari-LLVM15](https://github.com/61bcdefg/Hikari-LLVM15) by 61bcdefg.

> **Platform note**: verified on **macOS arm64** (C and Rust) and on **Linux
> x86_64** (C, AArch64 cross-compilation, `opt` and the Debian package). Other
> platforms have not been tested end to end. If obfuscated code misbehaves,
> first drop the optimization level to **`-C opt-level=0`** (Rust) or **`-O0`**
> (C) — Hikari targets `-O0` IR.

## Prebuilt packages

Every release carries the plugin and the host that loads it, so nothing has to
be assembled by hand. See the [releases page](../../releases) for the current
checksums. Releases are built from the `hardening-gates` workflow
(`.github/workflows/gates.yml`), which is the repository's only CI workflow —
the upstream `ci.yml` (smoke + stress + .deb packaging) was removed after its
smoke sweep caught two real bugs (both fixed and now covered by the gates), and
its stress stage kept dying of OOM on the 7GB standard runner.

The tables below describe the packaging layouts that ship in the repo
(`tools/deb/`, `tools/android-toolchain/`, `tools/termux/`). The GitHub
Actions release packaging from the old `ci.yml` is gone — build them locally
with the instructions in those sub-READMEs.

| Target | Artifact | What it is |
|---|---|---|
| Ubuntu / Debian x86_64 | `hikari_<version>_amd64.deb` | the plugin, an LLVM 22 `opt` with its `libLLVM`, and `hikari-clang` on `PATH` |
| Ubuntu / Debian arm64 | `hikari_<version>_arm64.deb` | the same, for `aarch64` hosts |
| Android, no NDK needed | `hikari-android-toolchain-full.tar.xz` | the plugin plus a bundled NDK: clang, lld, sysroot |
| Android, with your own NDK | `hikari-android-toolchain-slim.tar.xz` | the plugin, the LLVM 22 `opt` and the per-ABI wrappers |
| Termux (Android, aarch64) | `hikari_<version>_aarch64.deb` | the plugin built against Termux's own LLVM 21.1.8 — see [`tools/termux/README.md`](tools/termux/README.md) |
| Any LLVM 22 host | `libHikari.so` | the plugin on its own |

```bash
sudo dpkg -i hikari_1.0.0_amd64.deb
hikari-clang -O0 hello.c -o hello            # obfuscated
HIKARI_OBF=0 hikari-clang -O0 hello.c -o hi  # one clean build, to compare
```

Packaging details: [`tools/deb/README.md`](tools/deb/README.md) and
[`tools/android-toolchain/README.md`](tools/android-toolchain/README.md).

## Version alignment

| Component | Version |
|---|---|
| LLVM this plugin is developed against | **22** (also builds & gates on 21 and 23) |
| Homebrew `llvm` | 22.1.x (`brew install llvm`) |
| `rustc` stable | 1.97.x (LLVM 22) |
| `rustc` nightly | 1.99.x-nightly (LLVM 22) |

**rustc's LLVM major version has to match the LLVM this plugin was built
against**, or `-Zllvm-plugins` may fail to load it.

The build accepts LLVM **21, 22 and 23**. 21 is not a target of its own — it
is there because Termux ships 21.1.8 and nothing newer, and the only way to
run this on a phone is against the LLVM the phone has. 23 is fully supported
too (the hardening gates run a 21/23 matrix; LLVM 23 needs two small API
compat shims that are already in the tree). Anything below 21 is refused at
configure time.

## Building

### Dependencies

- CMake ≥ 3.20, Ninja
- An LLVM 22 development package (headers and cmake config)
- macOS: `brew install llvm ninja cmake`

### Build

```bash
cmake -G "Ninja" -S . -B ./build \
      -DCMAKE_CXX_STANDARD=17 \
      -DCMAKE_BUILD_TYPE=Release \
      -DBUILD_SHARED_LIBS=ON \
      -DLT_LLVM_INSTALL_DIR=/opt/homebrew/opt/llvm
cmake --build ./build
```

Replace `LT_LLVM_INSTALL_DIR` with your LLVM 22 prefix (the CMake default is
`/opt/homebrew/opt/llvm`; on Debian and Ubuntu it is `/usr/lib/llvm-22`).

| Platform | Artifact |
|---|---|
| macOS | `build/obfuscation/libHikari.dylib` |
| Linux | `build/obfuscation/libHikari.so` |

## Usage

### Rust (nightly, dynamic loading)

```bash
rustup toolchain install nightly

cargo new helloworld --bin
cd helloworld
cargo +nightly rustc --release -- \
  -C opt-level=0 \
  -Zllvm-plugins="/absolute/path/libHikari.dylib" \
  -Cpasses="hikari(enable-bcfobf,enable-cffobf,enable-strcry)"
```

### opt (C/C++, and anything else with LLVM IR)

```bash
clang -O0 -emit-llvm -c input.c -o input.bc

opt -load-pass-plugin="/absolute/path/libHikari.dylib" \
    --passes="hikari(enable-bcfobf,enable-cffobf,enable-strcry)" \
    input.bc -o output.bc

llc -filetype=obj output.bc -o output.o
clang output.o -o output
```

The pipeline name must be **`hikari(...)`**, with the individual switches inside.

The packaged `hikari-clang` driver runs those three stages for you and only
passes text IR between them; see
[`tools/android-toolchain/README.md`](tools/android-toolchain/README.md) for why
that is what makes an older clang able to feed an LLVM 22 plugin.

## Switches

| Switch | Meaning |
|---|---|
| `hikari(...)` | enables the scheduler (**required** as the outer pass name) |
| `enable-allobf` | turns on most passes (see below) |
| `enable-bcfobf` | bogus control flow |
| `enable-cffobf` | control-flow flattening |
| `enable-subobf` | instruction substitution |
| `enable-splitobf` | basic-block splitting |
| `enable-strcry` | string encryption (C strings / Rust string data) |
| `enable-constenc` | constant encryption |
| `enable-indibran` | indirect branches |
| `enable-fco` | function-call obfuscation (`dlopen`/`dlsym` style) |
| `enable-funcwra` | function wrapping (known unstable) |
| `enable-antihook` | AntiHook (AArch64 inline / antirebind) |
| `enable-adb` | AntiDebugging |
| `enable-vmp` | **IR virtualization (VMP)**: translate functions into a private bytecode plus an interpreter |

`enable-allobf` turns on: `bcf`, `cff`, `sub`, `split`, `strcry`, `indibran`,
`fco`, `funcwra`.
It does **not** turn on: `constenc`, `antihook`, `adb`, `vmp` — ask for those
explicitly.

Environment variables work as an alternative to the `hikari()` arguments:
`BCFOBF`, `CFFOBF`, `SUBOBF`, `SPLITOBF`, `STRCRY`, `INDIBRAN`, `FCO`,
`FUNCWRA`, `ANTIHOOK`, `ADB`, `CONSTENC`, `ALLOBF`, `VMP`.

### VMP (`enable-vmp`)

IR-level virtual machine protection: functions are translated into a private
bytecode plus a re-entrant interpreter that lives on the stack.

| Mechanism | Meaning |
|---|---|
| Function annotation | `__attribute__((annotate("vmp")))`; exclude with `novmp` |
| Pipeline | `hikari()` processes only annotated functions; `hikari(enable-vmp)` tries every translatable function in the module |
| Environment | `VMP=1` is the same as `enable-vmp` |
| Encryption | on by default, L1 dual-seed (opcode + whole basic blocks); `VMPNOENC=1` or the `novmpenc` annotation turns it off; `VMPENCRYPT=1` or the `vmpenc` annotation forces it on |
| Combined with flattening | `hikari(enable-vmp,enable-cffobf)`: **VMP first, then CFF** (a preceding CFF on VMP targets is skipped automatically, to avoid the size blowup of flattening something that is then virtualized wholesale) |
| Hardening | `VMPHARDEN=1` or the `vmpharden` annotation: equivalent to running CFF over the virtualized function and its helpers (usable on its own, without `enable-cffobf`) |

**Supported IR (friendly to `-O0`)**

- Memory: `alloca` / `load` / `store` (an alloca's result is a real VA, so
  pointers can be handed out)
- Integers: binop / icmp (signed and unsigned) / cast / select
- Scalar floats: fadd/fsub/fmul/fdiv, all 14 fcmp predicates (NaN semantics
  preserved), fpext/fptrunc/sitofp/fptosi/fptoui/uitofp; `llvm.fmuladd`
  expands to unfused fmul+fadd. Values ride i64 slots as IEEE bits
- Atomics: integer `atomicrmw` (11 sub-ops, acq_rel), `cmpxchg`, and plain
  atomic load/store (virtualized as plain ops + trailing acq_rel fence)
- Control flow: `br` / `ret` / `unreachable`
- `gep`: constant offsets, a single index, the common `[0, i]` array form
- `call`: direct and indirect, leaving through `vmp_ch_*` handlers
- Globals / function pointers: written into data slots by the launcher

**Runtime model**

- Per call: `data`, `ip` and the decryption state all live on the stack, so VMP
  functions are **re-entrant by default**, recursion included
- Bytecode: `@vmp_code_<fn>`; basic-block seed table: `@vmp_seeds_<fn>`
- Anything it cannot translate is **skipped wholesale** (visible as a
  `[VMP] skip/translate fail` log) rather than corrupting the module

**Explicitly unsupported (hard-fail skip)**

- varargs (including JNIEnv-style method calls), exceptions/EH, vector
  floats (scalar floats are supported), complex multi-dynamic-index GEPs

Target functions should be `-O0` / `optnone`. Acceptance tests:
`./samples/run_vmp.sh` and `bash samples/test_obf_hardening.sh`
(12 hardening gates: parity, multithreading, handler shuffling, atomic
long-loop stress, float virtualization, dual-stream seed KDF, …).
Builds and passes on LLVM 21 and LLVM 23.

**Full documentation** (architecture / bytecode / switches / mixing with CFF /
troubleshooting): [`docs/VMP.md`](docs/VMP.md).

### Removed

- **Objective-C support is gone entirely** (there was no test environment):
  - `enable-acdobf` / AntiClassDump
  - FCO's class/sel rewriting
  - strcry's CFString / NSString
  - antihook's ObjC runtime checks

This repository targets **C / Rust / ordinary LLVM IR**.

## Examples

The repository ships comparison scripts:

```bash
# build the plugin first (see above), then:
./samples/run_demo.sh
./samples/run_vmp.sh    # VMP correctness gate
```

See [`samples/README.md`](samples/README.md).

## Notes

1. **Dynamic loading** requires the host (`opt` / `rustc`) and the plugin to
   share the LLVM major version.
2. `enable-strcry` can still be unstable on some Rust code; turn strcry off or
   lower the optimization level if it misbehaves.
3. `enable-funcwra` is historically marked Broken and should not be enabled by
   default.
4. Control-flow passes (especially `indibran` + `bcf`) noticeably increase
   binary size and compile time.

## CI

Every gate lives in a script, so a human, a local runner and a hosted runner all
run the same thing — the workflows only decide *where*. See
[`docs/CI.md`](docs/CI.md).

## Thanks

- [Hikari-LLVM15](https://github.com/61bcdefg/Hikari-LLVM15) by 61bcdefg
- [ollvm-rust](https://github.com/0xlane/ollvm-rust) by 0xlane
