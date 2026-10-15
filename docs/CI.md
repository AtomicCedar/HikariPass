# CI

每个 gate 都封装在脚本里，因此人、本地 runner 和托管 runner 运行的是同一套东西——workflow 只决定*在哪里*运行。

> 注：下表的 smoke 与 stress 脚本仍随仓库分发、可手动运行；但它们**不再属于任何在线 workflow**——原上游 ci.yml 已删除（smoke 覆盖并入 hardening-gates 的 T 系列，stress 因 4 并行 opt 超 7GB runner 内存 OOM 移除）。当前仓库唯一 CI 为 `hardening-gates`（T1-T19 gates + `run_vmp.sh` 冒烟）。

| Gate | 脚本 | 证明什么 |
|---|---|---|
| Smoke test | `tools/android-toolchain/smoke-test.sh` | 插件能加载，且混淆后的二进制输出与干净二进制一致——覆盖 host、AArch64、一个 `-g`/DWARF 用例，以及 16 个固定种子的重复运行 |
| Differential stress | `tools/stress/stress-test.sh` | 样本 × pass × 种子矩阵，每个 pass 单独运行，输出与干净构建对比 |
| Cross-ABI execution | `tools/stress/cross-run.sh` | 混淆后的 Android 二进制在 qemu 下被*实际运行*（aarch64、armv7a），而不仅是编译 |
| Package verification | `tools/android-toolchain/verify-package.sh` | `dist/*.tar.xz` 在一台既无 NDK 也无系统 LLVM 的机器上解包后可用 |
| Subset sweep | `tools/stress/subset-sweep.sh` | 诊断工具：将 pass 交互 bug 二分定位到最小的可复现 pass 集合 |

它们共同读取的环境变量：`HIKARI_PLUGIN`、`HIKARI_OPT`（LLVM 22 的 `opt`）、`HIKARI_CC`
（host clang）、`HIKARI_NDK`。

## GitHub

仓库中唯一的 CI 是 `.github/workflows/gates.yml`（hardening-gates），包含上述全部
gates。旧的 `.github/workflows/ci.yml`（smoke + stress + .deb 打包）已被删除：
smoke 覆盖已并入 gates，stress 因 OOM 移除，打包不再属于 CI。

## Codeberg

`.forgejo/workflows/ci.yml` 已删除；Codeberg 侧的 CI 同样以 gates.yml 为准。如需
在 Codeberg 上运行 Actions，需要两件事：

1. **为仓库启用 Actions。** 仓库设置 → *Units* → 勾选
   *Enable Actions*。不开启则不会有任何运行。
2. **提供一个 runner。** `gates` 和 `release` job 有意要求
   `self-hosted`（`runs-on: self-hosted`）——原因见下方的限制说明。`lint` job
   在 Codeberg 托管 runner 上即可运行。

### 在 self-hosted runner 上声明工具链

`gates` 和 `package` job 从 runner 的环境中获取工具链，绝不会重复安装已存在的
工具链。Forgejo runner 在启动时读取 `<runner dir>/.env`，在这里声明即可：

```ini
LLVM_PREFIX=<tree with lib/cmake/llvm>       # what the plugin is built against
HIKARI_OPT=<tree with bin/opt>               # the LLVM 22 opt that loads the plugin
LD_LIBRARY_PATH=<dir with libLLVM.so.22.1>   # only if opt has no rpath to it
HIKARI_CC=<ndk>/toolchains/llvm/prebuilt/linux-x86_64/bin/clang
HIKARI_NDK=<ndk>
HIKARI_STRESS_JOBS=1                         # opt is memory-hungry; 1 on a small box
```

`HIKARI_OPT` 和 `LLVM_PREFIX` 是两个不同的目录树，这是正常设计而非需要掩盖的错误：
`opt` 是加载插件的运行时，而 `LLVM_PREFIX` 是插件*构建时*所针对的目录树，需要包含
`lib/cmake/llvm/LLVMConfig.cmake`。由 `package-toolchain.sh` 生成的目录树只有前者
没有后者，而解压出的 `llvm-22-dev` 只有后者没有前者。workflow 会在启动前按各自角色
逐一校验，因此路径写错会在几秒内失败，而不是等到构建之后。

任何机器相关的配置都不应写进 workflow 的 `env:` 块。workflow 级变量会覆盖 runner
导出的值，在那里声明工具链会遮蔽 runner 自身的配置，并导致每次 push 重新下载一个
GB 的依赖。

### 为什么重量级 job 要求 `self-hosted`

Codeberg 共享 runner 对单个 job 的墙钟时间和内存都有上限：

| Label | CPU | RAM | Runtime |
|---|---|---|---|
| `codeberg-tiny` | 1 | 2 GB | 2 min |
| `codeberg-small` | 2 | 4 GB | 5 min |
| `codeberg-medium` | 4 | 8 GB | 10 min |

RAM 配额还把文件系统写入计算在内。安装 LLVM 22 并构建插件就会耗尽 10 分钟预算的
大部分，这还没算 NDK 下载、带种子的 sweep 或 qemu 矩阵——因此把这些 job 指向共享
label 意味着一个总是超时的 workflow，这比一个明确说明限制的 workflow 更糟。应当
在一台已有工具链的机器上注册自己的 runner
（<https://docs.codeberg.org/ci/actions/>）；当工具已存在时，这些 job 会跳过
LLVM/NDK 的安装。

### Push 与 release job

```bash
git remote add codeberg https://codeberg.org/<you>/Hikari.git
git push codeberg master --tags
```

发布 Release 需要一个具有 `write:repository` 权限的 token：

- **浏览器：** Codeberg → *Settings* → *Applications* → 创建 token。
- **CLI：**
  ```bash
  fj auth add-token --host https://codeberg.org   # paste the token at the prompt
  ```
  `fj auth login`（浏览器流程）也可用。`fj` 即 `forgejo-cli`；release job 使用
  `fj release create` / `fj release asset create`，因此同一 token 也可以手动发布
  `dist/*.tar.xz` 和 `libHikari.so`：

  ```bash
  fj release create v0.1 --tag v0.1 \
    --attach dist/hikari-android-toolchain-full.tar.xz \
    --attach dist/hikari-android-toolchain-slim.tar.xz \
    --attach build/obfuscation/libHikari.so \
    --host https://codeberg.org --repo <you>/Hikari
  ```

在 workflow 中，token 是 `CODEBERG_TOKEN` 仓库 secret。
