# Hikari-LLVM22

一个 out-of-tree 的 LLVM 22 混淆 pass 插件，动态加载进 **`opt` 或 `rustc` nightly**——无需重编 LLVM 或 rustc。

fork 自 61bcdefg 的 [Hikari-LLVM15](https://github.com/61bcdefg/Hikari-LLVM15)。

> **平台说明**：已在 **macOS arm64**（C 与 Rust）和 **Linux x86_64**（C、AArch64 交叉编译、`opt` 与 Debian 包）上验证。其他平台未做端到端测试。如果混淆后的代码行为异常，先把优化级别降到 **`-C opt-level=0`**（Rust）或 **`-O0`**（C）——Hikari 针对 `-O0` IR。

## 预构建包

每次 release 都携带插件及其加载宿主，无需手工拼装。当前校验和见 [releases 页面](../../releases)。Release 由 `hardening-gates` workflow（`.github/workflows/gates.yml`）构建，这是仓库唯一的 CI workflow——上游的 `ci.yml`（smoke + stress + .deb 打包）已删除：其 smoke 扫描曾抓出两个真实 bug（均已修复并纳入 gates 覆盖），而其 stress 阶段在 7GB 标准 runner 上反复因 OOM 被杀。

下表描述仓库内置的打包布局（`tools/deb/`、`tools/android-toolchain/`、`tools/termux/`）。旧 `ci.yml` 的 GitHub Actions release 自动打包已移除——请按各子目录 README 中的说明在本地构建。

| 目标 | 产物 | 说明 |
|---|---|---|
| Ubuntu / Debian x86_64 | `hikari_<version>_amd64.deb` | 插件、带 `libLLVM` 的 LLVM 22 `opt`、以及上 `PATH` 的 `hikari-clang` |
| Ubuntu / Debian arm64 | `hikari_<version>_arm64.deb` | 同上，面向 `aarch64` 主机 |
| Android，无需 NDK | `hikari-android-toolchain-full.tar.xz` | 插件加内置 NDK：clang、lld、sysroot |
| Android，使用自带 NDK | `hikari-android-toolchain-slim.tar.xz` | 插件、LLVM 22 `opt` 及各 ABI 的 wrapper |
| Termux（Android，aarch64） | `hikari_<version>_aarch64.deb` | 针对 Termux 自带的 LLVM 21.1.8 构建的插件——见 [`tools/termux/README.md`](tools/termux/README.md) |
| 任意 LLVM 22 宿主 | `libHikari.so` | 仅插件本体 |

```bash
sudo dpkg -i hikari_1.0.0_amd64.deb
hikari-clang -O0 hello.c -o hello            # 混淆
HIKARI_OBF=0 hikari-clang -O0 hello.c -o hi  # 一次干净构建，用于对比
```

打包细节：[`tools/deb/README.md`](tools/deb/README.md) 与 [`tools/android-toolchain/README.md`](tools/android-toolchain/README.md)。

## 版本对齐

| 组件 | 版本 |
|---|---|
| 本插件的开发目标 LLVM | **22**（21/23 也构建并通过 gates） |
| Homebrew `llvm` | 22.1.x（`brew install llvm`） |
| `rustc` stable | 1.97.x（LLVM 22） |
| `rustc` nightly | 1.99.x-nightly（LLVM 22） |

**rustc 的 LLVM 主版本必须与本插件构建所用的 LLVM 一致**，否则 `-Zllvm-plugins` 可能加载失败。

构建支持 LLVM **21、22 和 23**。21 并非独立目标——它存在是因为 Termux 只提供 21.1.8，没有更新的版本，而在手机上运行的唯一途径就是用手机已有的 LLVM。23 也得到完整支持（hardening gates 以 21/23 双矩阵运行；LLVM 23 需要的两个小 API 兼容 shim 已在代码树中）。低于 21 的版本在 configure 阶段直接拒绝。

## 构建

### 依赖

- CMake ≥ 3.20、Ninja
- LLVM 22 开发包（头文件与 cmake 配置）
- macOS：`brew install llvm ninja cmake`

### 构建

```bash
cmake -G "Ninja" -S . -B ./build \
      -DCMAKE_CXX_STANDARD=17 \
      -DCMAKE_BUILD_TYPE=Release \
      -DBUILD_SHARED_LIBS=ON \
      -DLT_LLVM_INSTALL_DIR=/opt/homebrew/opt/llvm
cmake --build ./build
```

把 `LT_LLVM_INSTALL_DIR` 换成你的 LLVM 22 前缀（CMake 默认为 `/opt/homebrew/opt/llvm`；Debian 和 Ubuntu 上为 `/usr/lib/llvm-22`）。

| 平台 | 产物 |
|---|---|
| macOS | `build/obfuscation/libHikari.dylib` |
| Linux | `build/obfuscation/libHikari.so` |

## 用法

### Rust（nightly，动态加载）

```bash
rustup toolchain install nightly

cargo new helloworld --bin
cd helloworld
cargo +nightly rustc --release -- \
  -C opt-level=0 \
  -Zllvm-plugins="/absolute/path/libHikari.dylib" \
  -Cpasses="hikari(enable-bcfobf,enable-cffobf,enable-strcry)"
```

### opt（C/C++，以及一切能产出 LLVM IR 的语言）

```bash
clang -O0 -emit-llvm -c input.c -o input.bc

opt -load-pass-plugin="/absolute/path/libHikari.dylib" \
    --passes="hikari(enable-bcfobf,enable-cffobf,enable-strcry)" \
    input.bc -o output.bc

llc -filetype=obj output.bc -o output.o
clang output.o -o output
```

pipeline 名必须为 **`hikari(...)`**，各开关写在括号内。

打包提供的 `hikari-clang` driver 会替你跑完这三个阶段，且各阶段之间只传递文本 IR；关于为何"旧版 clang 喂 LLVM 22 插件"正依赖于此，见 [`tools/android-toolchain/README.md`](tools/android-toolchain/README.md)。

## 开关

| 开关 | 含义 |
|---|---|
| `hikari(...)` | 启用调度器（作为外层 pass 名**必需**） |
| `enable-allobf` | 打开大多数 pass（见下） |
| `enable-bcfobf` | 虚假控制流（BCF） |
| `enable-cffobf` | 控制流平坦化（CFF） |
| `enable-subobf` | 指令替换 |
| `enable-splitobf` | 基本块切分（split） |
| `enable-strcry` | 字符串加密（C 字符串 / Rust 字符串数据） |
| `enable-constenc` | 常量加密（constenc） |
| `enable-indibran` | 间接跳转（indibran） |
| `enable-fco` | 函数调用混淆（`dlopen`/`dlsym` 风格） |
| `enable-funcwra` | 函数包装（已知不稳定） |
| `enable-antihook` | AntiHook（AArch64 inline / antirebind） |
| `enable-adb` | AntiDebugging |
| `enable-vmp` | **IR 虚拟化（VMP）**：把函数翻译成私有字节码加解释器 |

`enable-allobf` 会打开：`bcf`、`cff`、`sub`、`split`、`strcry`、`indibran`、`fco`、`funcwra`。
**不会**打开：`constenc`、`antihook`、`adb`、`vmp`——这些需要显式指定。

环境变量可作为 `hikari()` 参数的替代：`BCFOBF`、`CFFOBF`、`SUBOBF`、`SPLITOBF`、`STRCRY`、`INDIBRAN`、`FCO`、`FUNCWRA`、`ANTIHOOK`、`ADB`、`CONSTENC`、`ALLOBF`、`VMP`。

### VMP（`enable-vmp`）

IR 层虚拟机保护：函数被翻译成私有字节码，外加一个驻留在栈上的可重入解释器。

| 机制 | 含义 |
|---|---|
| 函数注解 | `__attribute__((annotate("vmp")))`；用 `novmp` 排除 |
| Pipeline | `hikari()` 只处理带注解的函数；`hikari(enable-vmp)` 尝试模块中每个可翻译的函数 |
| 环境变量 | `VMP=1` 等价于 `enable-vmp` |
| 加密 | 默认开启，L1 双种子（opcode + 整个基本块）；`VMPNOENC=1` 或 `novmpenc` 注解可关闭；`VMPENCRYPT=1` 或 `vmpenc` 注解强制开启 |
| 与平坦化组合 | `hikari(enable-vmp,enable-cffobf)`：**先 VMP，后 CFF**（对 VMP 目标先做 CFF 会被自动跳过，以避免把随后被整体虚拟化的函数再做平坦化导致的体积膨胀） |
| 加固 | `VMPHARDEN=1` 或 `vmpharden` 注解：等价于对虚拟化后的函数及其辅助函数跑一遍 CFF（可单独使用，无需 `enable-cffobf`） |

**支持的 IR（对 `-O0` 友好）**

- 内存：`alloca` / `load` / `store`（alloca 的结果是一个真实 VA，因此指针可以外传）
- 整数：binop / icmp（有符号与无符号）/ cast / select
- 标量浮点：fadd/fsub/fmul/fdiv、全部 14 种 fcmp 谓词（保留 NaN 语义）、fpext/fptrunc/sitofp/fptosi/fptoui/uitofp；`llvm.fmuladd` 展开为不融合的 fmul+fadd。值以 IEEE 位的形式装入 i64 槽位
- 原子操作：整数 `atomicrmw`（11 种子操作，acq_rel）、`cmpxchg`、以及普通原子 load/store（虚拟化为普通操作 + 尾随 acq_rel fence）
- 控制流：`br` / `ret` / `unreachable`
- `gep`：常量偏移、单个索引、常见的 `[0, i]` 数组形式
- `call`：直接与间接调用，经由 `vmp_ch_*` handler 出栈
- 全局变量 / 函数指针：由 launcher 写入数据槽位

**运行时模型**

- 每次调用：`data`、`ip` 与解密状态都位于栈上，因此 VMP 函数**默认可重入**，包括递归
- 字节码：`@vmp_code_<fn>`；基本块种子表：`@vmp_seeds_<fn>`
- 无法翻译的内容会被**整体跳过**（表现为 `[VMP] skip/translate fail` 日志），而不是破坏模块

**明确不支持（硬性失败跳过）**

- 异常/EH、向量浮点（标量浮点已支持）、复杂的多动态索引 GEP；函数体内使用
  `va_start`/`va_arg` 的（真 varargs 函数）——仅**调用** varargs 函数（如 `printf`）
  是支持的，调用点 ABI 经 `vmp_ch_*` 完整重 emit

目标函数应为 `-O0` / `optnone`。验收测试：`./samples/run_vmp.sh` 与 `bash samples/test_obf_hardening.sh`（19 项 hardening gates：等价性、多线程、varargs 调用点、handler 洗牌、原子长循环 stress、浮点虚拟化、双流种子 KDF、-O2 优化级 IR 覆盖等）。在 LLVM 21 与 LLVM 23 上构建并通过。

**完整文档**（架构 / 字节码 / 开关 / 与 CFF 混用 / 故障排查）：[`docs/VMP.md`](docs/VMP.md)。

### 已移除

- **Objective-C 支持已彻底移除**（没有测试环境）：
  - `enable-acdobf` / AntiClassDump
  - FCO 的 class/sel 重写
  - strcry 的 CFString / NSString
  - antihook 的 ObjC runtime 检查

本仓库面向 **C / Rust / 普通 LLVM IR**。

## 示例

仓库自带对比脚本：

```bash
# 先构建插件（见上文），然后：
./samples/run_demo.sh
./samples/run_vmp.sh    # VMP 正确性 gate
```

见 [`samples/README.md`](samples/README.md)。

## 注意事项

1. **动态加载**要求宿主（`opt` / `rustc`）与插件使用相同的 LLVM 主版本。
2. `enable-strcry` 在部分 Rust 代码上仍可能不稳定；若行为异常，可关闭 strcry 或降低优化级别。
3. `enable-funcwra` 历史上被标记为 Broken，不应默认启用。
4. 控制流类 pass（尤其 `indibran` + `bcf`）会明显增大二进制体积并延长编译时间。

## CI

每个 gate 都是一个脚本，因此人类、本地 runner 与托管 runner 跑的是同一套东西——workflow 只决定*在哪里*跑。见 [`docs/CI.md`](docs/CI.md)。

## 致谢

- 61bcdefg 的 [Hikari-LLVM15](https://github.com/61bcdefg/Hikari-LLVM15)
- 0xlane 的 [ollvm-rust](https://github.com/0xlane/ollvm-rust)
