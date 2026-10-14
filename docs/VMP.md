# Hikari IR-VMP 使用与设计文档

> 基于 LLVM IR 的函数级虚拟机保护（Virtual Machine Protection）。  
> 实现：`obfuscation/Virtualization.cpp`、`obfuscation/vmp/Opcode.h`  
> 调度：`obfuscation/Obfuscation.cpp`（在函数级混淆之后）

---

## 1. 它做什么

将选定函数的 **LLVM IR** 翻译成自定义 **bytecode**，原函数体改写为：

1. 在栈上分配 VM 数据区 / IP / 解密状态  
2. 装入参数与全局指针  
3. 进入 **fetch → decrypt → dispatch → handler** 解释循环  
4. 从数据区读返回值并 `ret`

静态逆向时，业务上的 `add` / `icmp` / `br` / 循环等不再以明文 IR/机器码形态出现，而变成密文字节码 + 通用解释器。

**不是** Android SO 壳、不是自定义 Linker、不是商业 VMProtect 的 x86 字节码级产品；它是 **编译期 IR Pass**，适合 C/C++/Rust 等能产出 LLVM IR 的路径。

---

## 2. 快速开始

### 2.1 构建插件

```bash
# LLVM 21 或 23 均可（两者都被 CI 验收；apt.llvm.org 安装）
cmake -G Ninja -S . -B ./build-llvm21 \
  -DCMAKE_BUILD_TYPE=Release \
  -DLT_LLVM_INSTALL_DIR=/usr/lib/llvm-21
cmake --build ./build-llvm21
# 产物：build-llvm21/obfuscation/libHikari.so
```

LLVM 23 兼容说明：`compat/CallSite.h` 的 DenseMapInfo 哨兵键与
`StringEncryption.cpp` 的 `isNullValue` 已适配 23 的 API 变更；
`BranchInst` 拆分（UncondBr/CondBr）与 `splitBasicBlock` Before 参数移除
对本仓库无影响。

### 2.2 标注需要保护的函数

```c
__attribute__((annotate("vmp")))
int secret_check(int uid, int token) {
  // 建议 -O0 / optnone，GEP/控制流更规整
  ...
}

// 排除（全局 enable-vmp 时）
__attribute__((annotate("novmp")))
int do_not_virtualize(void);
```

### 2.3 跑 Pass

```bash
export PATH=/opt/homebrew/opt/llvm/bin:$PATH
PLUGIN=build-llvm22/obfuscation/libHikari.dylib

clang -O0 -emit-llvm -c secret.c -o secret.bc

# 只处理 annotate("vmp") 的函数
opt -load-pass-plugin="$PLUGIN" --passes='hikari()' \
  secret.bc -o secret_vmp.bc

# 尝试模块内所有可译函数
opt -load-pass-plugin="$PLUGIN" --passes='hikari(enable-vmp)' \
  secret.bc -o secret_vmp.bc

# 推荐：VMP + 后置控制流平坦化（打散解释器）
opt -load-pass-plugin="$PLUGIN" --passes='hikari(enable-cffobf)' \
  secret.bc -o secret_vmp_cff.bc

llc -filetype=obj secret_vmp.bc -o secret.o
clang secret.o -o secret
```

### 2.4 验收脚本

```bash
./samples/run_vmp.sh          # 基础正确性（算术/分支/GEP/call/全局/递归）
bash samples/test_obf_hardening.sh   # 19 项加固验收 gates（T1-T19:
  # BB 名/seed 表多态/parity/多线程/varargs/JNI_OnLoad/handler 洗牌/
  # 全局指针字符串/原子长循环/浮点虚拟化/双流 KDF/bcf 本地谓词/cff 匿名
  # switchVar/strcry 滚动密钥/indibran 非常量表/token entry/影子 binop/
  # 优化级 IR 覆盖）
# 复杂样例源码：samples/c/vmp_complex.c
# 复杂样例对比产物：samples/out/vc_vmp、samples/out/vc_vmp_cff
```

### 2.5 CI（GitHub Actions）

| Workflow | 内容 |
|----------|------|
| `.github/workflows/gates.yml`（`hardening-gates`） | LLVM 21/23 双矩阵，T1-T19 gates + `run_vmp.sh` 冒烟；push/PR 自动触发 |
| `.github/workflows/ci.yml`（上游） | LLVM 22 构建插件 + smoke test（含 16-seed 输出复现 sweep）+ 9×15×3 差分 stress + .deb 打包 |

---

## 3. 开关与标注

### 3.1 管线 / 环境变量

| 机制 | 作用 |
|------|------|
| `hikari()` | 启用调度；**仅**虚拟化带 `vmp` 标注的函数 |
| `hikari(enable-vmp)` | 尝试虚拟化模块内所有可译函数 |
| 环境变量 `VMP=1` | 等同 `enable-vmp` |
| **不在** `enable-allobf` 内 | 需显式打开或靠标注 |

### 3.2 加密

| 机制 | 作用 |
|------|------|
| 默认 | **开启** L1 双 seed 加密 |
| `VMPNOENC=1` | 关闭加密（联调） |
| `VMPENCRYPT=1` | 强制开启 |
| 标注 `novmpenc` | 该函数关闭加密 |
| 标注 `vmpenc` | 该函数强制加密 |

### 3.3 与平坦化（CFF）结合

| 机制 | 作用 |
|------|------|
| `hikari(enable-cffobf)` + `annotate("vmp")` | **先 VMP，再 CFF**（推荐混合） |
| 调度行为 | VMP 目标 **跳过前置 CFF**，避免「先平坦化再整段虚拟化」体积爆炸 |
| `VMPHARDEN=1` / 标注 `vmpharden` | 无 `enable-cffobf` 时也可对 VMP 后函数做后置 CFF |
| 后置 CFF 范围 | `fn` 本体 + `vmp_eval_*` / `vmp_read_var_*` / `vmp_ch_*` / `vmp_seed_*` |

### 3.4 其它标注

| 标注 | 含义 |
|------|------|
| `vmp` | 启用虚拟化 |
| `novmp` | 禁止虚拟化 |
| `vmpharden` | 虚拟化后对该函数做 CFF |
| `vmpenc` / `novmpenc` | 强制 / 关闭该函数字节码加密 |

---

## 4. 架构

### 4.1 编译期三步

```
选中函数 F
    │
    ▼
┌─────────────┐
│ Translator  │  IR → bytecode（value_map / BB map / call sites）
│             │  可选 L1 双 seed 加密
└──────┬──────┘
       ▼
┌─────────────┐
│ Interpreter │  IRBuilder 生成：
│   Builder   │  vmp_loop / handlers / vmp_eval / vmp_ch / vmp_seed
└──────┬──────┘
       ▼
┌─────────────┐
│  Modifier   │  deleteBody → 启动器（装参、调循环、取返回值）
│  (合入同一  │  可选 post-CFF
│   函数体)   │
└─────────────┘
```

### 4.2 运行时布局（每调用独立，可重入）

全部在 **栈上**（非全局单例 data 段）：

| 对象 | 含义 |
|------|------|
| `vmp_data[N]` | 虚拟寄存器 / 参数 / alloca 区 / 返回值槽 |
| `ip` | 字节码偏移（`i32`） |
| `run` | 是否继续解释 |
| `op_state` / `code_state` | L1 解密 PRNG 状态 |
| `@vmp_code_<F>` | 只读密文（或明文）bytecode |
| `@vmp_seeds_<F>` | 每 BB：`{entry_ip, opcode_seed, code_seed}` |

**返回值**默认写在 `vmp_data` 偏移 0。  
**参数**按顺序排在返回值槽之后。  
**`alloca` 结果**存的是 **真实虚地址** `data_base + area_off`，因此可以把指针传给外部 `memcpy` 类函数。

### 4.3 符号命名（每个被 VMP 的函数）

| 符号 | 角色 |
|------|------|
| `@vmp_code_<fn>` | 字节码 |
| `@vmp_seeds_<fn>` | BB seed 表 |
| `@vmp_seed_<fn>` | 按 IP 重载双 seed |
| `@vmp_entry_<fn>` | **解释器本体**（internal，函数类型与 host 相同；token entry 架构） |
| `@vmp_tok_<fn>` | **裸 ptrtoint relocation** 常量（指向 `vmp_entry_<fn>`；任何加载器都可在链接期填对，不依赖 `.init_array`） |
| `@vmp_eval_<fn>` | 解 `PackedValue` 并求值 |
| `@vmp_read_var_<fn>` | 读变量操作数（offset） |
| `@vmp_ch_<fn>` | 出站 call 分发（`call_handler`） |
| 辅助函数带 `novmp` | 避免被二次 VMP |

**Token entry 架构（T17）**：原函数体被清空为一个小桩 ——
`volatile load @vmp_tok_<fn>` → `inttoptr` → 间接 call，参数/返回透传。
全部解释器 BB 挂在 internal 的 `vmp_entry_<fn>` 上。静态反汇编只见一个
token 加载和一个间接跳转；token 是链接期 relocation（R_*_RELATIVE），
自写 MemLoader / dlopen 均可正确加载（**禁止**用全局 ctor 初始化 token ——
自定义内存加载器不跑 `.init_array`，token 会是 0，间接 call 跳野地址）。

### 4.4 主循环（逻辑）

```
seed_reload(entry_ip)
while running:
  op = fetch_op()          # code 层 XOR + opcode 层 XOR
  switch op:
    NOP / FENCE / ALLOCA / LOAD / STORE / BINOP / ICMP / BR / RET /
    GEP / CALL / CAST / SELECT / UNREACHABLE / ATOMICRMW / CMPXCHG /
    COPY / FBINOP / FCMP / FCAST
    default → trap (停机)
BR 修改 ip 后 seed_reload(new_ip)
RET 写返回值槽，running = 0
```

---

## 5. 字节码与操作数

### 5.1 Opcode（`vmp/Opcode.h`）

| 值 | 助记符 | 语义 |
|----|--------|------|
| `0x01` | `OP_ALLOCA` | 栈槽 + 写入真实指针 |
| `0x02` | `OP_LOAD` | 按 VA load |
| `0x03` | `OP_STORE` | 按 VA store |
| `0x04` | `OP_BINOP` | 整数二元运算（子操作码） |
| `0x05` | `OP_ICMP` | 整数比较 |
| `0x06` | `OP_BR` | 无条件 / 有条件跳转 |
| `0x07` | `OP_RET` | 返回 |
| `0x08` | `OP_GEP` | 指针运算 |
| `0x09` | `OP_CALL` | 出站调用（仅 `func_id`） |
| `0x0A` | `OP_CAST` | trunc/zext/sext/… |
| `0x0B` | `OP_SELECT` | 选择 |
| `0x0C` | `OP_FENCE` | 原子 load/store 的尾随内存栅栏（acq_rel） |
| `0x0D` | `OP_ATOMICRMW` | 原子读改写（11 种整数子操作） |
| `0x0E` | `OP_UNREACHABLE` | 停机 |
| `0x0F` | `OP_CMPXCHG` | 原子比较交换（两结果槽：old + i1） |
| `0x10` | `OP_COPY` | cmpxchg 结果的槽间拷贝（extractvalue） |
| `0x11` | `OP_FBINOP` | 浮点二元运算（fadd/fsub/fmul/fdiv） |
| `0x12` | `OP_FCMP` | 浮点比较（LLVM 全部 14 个谓词） |
| `0x13` | `OP_FCAST` | 浮点转换（fpext/fptrunc/sitofp/fptosi/fptoui/uitofp） |

> **wire 值多态**：上表是 opcode 的**逻辑编号**（`vmp/Opcode.h` 常量）。字节码里出现的实际
> wire 字节由 `initOpcodeMap` 按函数名 + `HIKARI_SEED` 派生的洗牌序列逐函数重映射
> （`OP_NOP` 固定为 0），同一逻辑 opcode 在不同函数/不同 seed 下字节不同。
> 解释器 dispatch 消费的是同一映射，且含假 `OP_NOP`（1/4 概率插在指令边界）。

### 5.2 PackedValue

```
size:u8 | type_id:u8 | payload
  type_id == 0 → 变量：payload = u64 data_off
  type_id != 0 → 常量：payload = LE 立即数，长度 = size
```

### 5.3 常见指令布局（摘要）

```
ALLOCA:  op | res_PV(var) | area_off:u64
LOAD:    op | res_PV(var) | ptr_PV
STORE:   op | val_PV      | ptr_PV
BINOP:   op | subop:u8 | res_PV | lhs_PV | rhs_PV
ICMP:    op | pred:u8  | res_PV | lhs_PV | rhs_PV
BR 无条: op | 0 | target:u64
BR 有条: op | 1 | cond_PV | target_t:u64 | target_f:u64
RET:     op | has:u8 [| val_PV]
GEP:     op | kind:u8 | elem_size:u64 | res_PV | base_PV | index_PV
CALL:    op | func_id:u64          # 参数在 vmp_ch_* 内从 data 取
FENCE:   op                                  # 单字节，无操作数
ATOMICRMW: op | subop:u8 | res_PV(var) | ptr_PV | val_PV
CMPXCHG:  op | sz:u8 | ptr_PV | cmp_PV | new_PV | res_off:u32 | flag_off:u32
COPY:    op | res_PV(var) | src_off:u32      # cmpxchg 槽结果搬运
FBINOP:  op | subop:u8 | res_PV | lhs_PV | rhs_PV   # sz4=float / sz8=double
FCMP:    op | pred:u8 | res_PV | lhs_PV | rhs_PV    # pred = LLVM FCMP_* 1..14
FCAST:   op | kind:u8 | res_PV | src_PV             # kind = 6 种转换
```

`BR` 目标在 **加密前** 回填为 BB 入口 code 偏移。

### 5.4 L1 双 seed 加密

对每个 basic block：

1. 记录 `opcode_seed`、`code_seed`  
2. 明文 emit（含 BR patch）  
3. **仅对 opcode 字节** 做 xorshift32 流 XOR（opcode 层）  
4. **对 BB 全区间** 再做 xorshift32 流 XOR（code 层）  

运行时：`get_byte` 解 code 层；`fetch_op` 再解 opcode 层。  
跨 BB：`BR` 后 `vmp_seed_*` 按 `entry_ip` 查表重载两种 seed。

### 5.5 Seed 掩码与 KDF（双流）

`vmp_seeds_<fn>` 表里的明文 seed 用独立掩码流 XOR 保护：

- **KDF**：`fnHashSeed` = 64-bit FNV-1a（函数名盐化域，如 `seeds|<fn>`）→ 两轮
  SplitMix64 雪崩（黄金比例常数）→ xorshift32 白化；`HIKARI_SEED` 在输入端混入，
  改 seed 即改变全部派生流（构建可复现）。
- **双流混叠**：`mask(n) = A(n) ^ rotl(B(n), 7 ^ (n & 15))`。A/B 是两条独立
  xorshift32 链，B 的种子来自第二个盐化域（`stream2|seeds|<fn>`）。单条流被逆向
  不足以还原全部函数的 seed。
- **两端一致**：编译期 emitter（`maskReplayA/B`）与运行时 `vmp_mask_<fn>` 逐位
  相同，改任一侧必须同步另一侧。
- 验收：`test_obf_hardening.sh` 的 T12（vmp_mask IR 必须含 ≥2 个不同流种子常量）。

---

## 6. 支持的 IR 与限制

### 6.1 支持（-O0 友好）

- `alloca`（非 VLA）、`load` / `store`（非 atomic/volatile）  
- 整数 `i1/i8/i16/i32/i64` 的 binop / icmp / cast / select  
- **标量浮点** `float`/`double` 的 binop / fcmp（全 14 谓词，NaN 语义保留）/
  fpext / fptrunc / sitofp / fptosi / fptoui / uitofp；`llvm.fmuladd`/`fma`
  展开为非融合 fmul+fadd。浮点值以 IEEE 位型存 i64 槽
- **原子操作**：`atomicrmw` 的 11 种整数子操作（xchg/add/sub/and/or/xor/nand/
  max/min/umax/umin，acq_rel）；`cmpxchg`（强/弱）；普通 atomic load/store
  虚拟化为普通操作 + 尾随 `OP_FENCE`（acq_rel 保守升级）。volatile 原子拒绝
- `br` / `ret` / `unreachable`  
- `gep`：常量累积偏移、单索引、常见 `0, i` 数组形态  
- `call`：直接 / 间接（经 `vmp_ch_*`）；debug/lifetime 等 intrinsic 丢弃  
- 全局变量 / 函数指针：启动器 `ptrtoint` 写入 data  

译码前会 `fixStack`（消 PHI）并 materialize `ConstantExpr`。

### 6.2 不支持（整函数 skip，不损坏 Module）

日志形如：`[VMP] skip foo (...)` 或 `[VMP] translate fail foo: ...`

- **函数体内使用 `va_start`/`va_arg`**（遍历可变参数自身的函数；仅**调用**
  varargs 函数如 `printf` 是支持的，调用点 ABI 经 `vmp_ch_*` 完整保留）  
- 异常 / EH（`invoke`、landingpad 等）  
- **向量浮点**（vector float；标量浮点已支持）  
- 复杂多动态索引 GEP  
- 未展开的数学 intrinsic（`ctpop`/`ctlz`/`cttz`/`bswap` 等；
  `abs`/`smax`/`smin`/`umax`/`umin`/`fshl`/`fshr` 会自动展开为普通 IR）  
- 构建解释器失败时会尝试从 backup 恢复函数体  

### 6.3 建议

- 保护 **关键路径**（授权、校验、协议），不要无脑全模块 `enable-vmp`  
- 目标函数 `-O0` 或 `optnone` + `noinline`  
- 需要可读联调时用 `VMPNOENC=1`  

---

## 7. 与其它 Hikari Pass 的顺序

```
AntiHook → FCO → AntiDebug → StringEnc
  → Split → BCF
  → CFF（跳过即将 VMP 的函数）
  → SUB
  → ★ VMP（+ 可选 post-CFF）★
  → ConstEnc → IndiBr → FuncWrapper
```

| 组合 | 建议 |
|------|------|
| 仅 VMP | `hikari()` + `annotate("vmp")` |
| VMP + 打散解释器 | `hikari(enable-cffobf)` + `annotate("vmp")` |
| 字符串加密 + VMP | `hikari(enable-strcry)` + 标注；注意字符串在 VMP 外更合适 |
| 全模块 VMP | `enable-vmp`（体积/性能代价大） |

---

## 8. 前后对比（直观）

**VMP 前**（业务 IR 可见）：

```llvm
%12 = xor i32 %uid, %nonce
%15 = icmp slt i32 %i, 8
%24 = call i32 @mix(...)
br i1 %cond, label %then, label %else
```

**VMP 后**（启动器 + 循环 + 密文）：

```llvm
@vmp_code_license_score = constant [3014 x i8] c"\xx\yy..."  ; 密文
@vmp_seeds_license_score = constant [28 x {i32,i32,i32}] ...

define i32 @license_score(...) {
vmp_entry:
  %vmp_data = alloca [516 x i8]
  ; store args → data
  call void @vmp_seed_license_score(i32 0, ...)
  br label %vmp_loop
vmp_loop:
  ; fetch + xorshift decrypt + switch handlers
}
```

复杂样例：`samples/c/vmp_complex.c`  
实测（约）：`license_score` IR 从 ~190 行 → ~2500 行；bytecode ~3KB；text 段从 ~1KB 级涨到十余 KB；再加 CFF 会继续增大。

---

## 9. 样例与产物

| 路径 | 说明 |
|------|------|
| `samples/c/vmp_add.c` | 基础：算术/分支/数组/指针 call/全局/递归 fact/多次调用 |
| `samples/c/vmp_complex.c` | 复杂控制流 + mix 表 |
| `samples/run_vmp.sh` | 自动 clean vs VMP 输出对比 + 标记检查 |
| `samples/out/` | 本地生成的 `.bc` / `.ll` / 可执行文件（gitignore） |

```bash
./samples/run_vmp.sh
# 手动复杂样例
clang -O0 -emit-llvm -c samples/c/vmp_complex.c -o /tmp/c.bc
opt -load-pass-plugin=libHikari.dylib --passes='hikari(enable-cffobf)' \
  /tmp/c.bc -o /tmp/c_obf.bc
llvm-dis /tmp/c_obf.bc -o /tmp/c_obf.ll   # 搜 vmp_loop / switchVar
```

---

## 10. 日志与排障

| 日志 | 含义 |
|------|------|
| `Running Virtualization On X` | 进入 VMP |
| `[VMP] X code=…B data=…B encrypt=0/1` | 译码成功 |
| `Skip pre-CFF for VMP target …` | 混合模式：前置 CFF 已跳过 |
| `[VMP] post-CFF on …` | 后置平坦化 |
| `[VMP] skip X (…)` | 不支持，整函数跳过 |
| `[VMP] translate fail X: …` | 译码失败 |
| `[VMP] build fail, restore X` | 解释器 IR 校验失败，已恢复 |
| `[VMP] fallback … CFF on non-virtualized` | VMP 失败时回退做 CFF |

常见问题：

1. **结果不对**：确认 `-O0`；有符号比较依赖 size 扩展；先 `VMPNOENC=1` 缩小问题面。  
2. **体积过大**：只标注关键函数；慎用全局 `enable-vmp`；CFF 会再增大解释器。  
3. **想看明文业务**：VMP 后业务只在 bytecode 里；对比用 `llvm-dis` 看 clean vs obf。  
4. **递归/多次调用**：默认栈上下文，支持（如 `vmp_fact`）。  

---

## 11. 源码地图

| 文件 | 内容 |
|------|------|
| `obfuscation/Virtualization.cpp` | 译码、加密、解释器生成、启动器、post-CFF |
| `obfuscation/vmp/Opcode.h` | opcode / 子操作码常量 |
| `obfuscation/include/Virtualization.h` | Pass 声明 |
| `obfuscation/Obfuscation.cpp` | 调度顺序、pre-CFF 跳过、postFlatten 标志 |
| `obfuscation/Flattening.cpp` | 后置 CFF 复用 |
| `docs/VMP.md` | 本文档 |

---

## 12. 已知边界与后续方向

**已具备**

- 整数 IR 子集虚拟化、出站 call、常见 GEP、全局指针  
- **标量浮点**（binop/fcmp/fp-cast）与**原子操作**（atomicrmw/cmpxchg/fence）虚拟化  
- L1 双 seed 加密、SplitMix64+双流 seed 掩码 KDF、逐函数 opcode 多态、
  handler 洗牌、假 NOP 指令、IP 越界保护、handler 栈泄漏修复
  （entry 块静态 alloca，**每个用途独立分配** —— 共享单槽会因
  callEval/callReadVar 生命周期重叠产生数据污染，已被 CI seed sweep 实证）
- **Token entry 入口**（T17）：host 体只剩 token 桩 + 间接 call，
  解释器整体藏进 internal `vmp_entry_<fn>`；token 为链接期裸 relocation，
  自写 MemLoader 兼容（Android 实测）
- **影子 binop**（T18）：ADD/SUB/AND/OR/XOR handler 各 2-3 种语义等价实现，
  逐函数按 seed 选型；逆出一个二进制的 handler 模式不能外推
- 反签名加固（T13-T16）：bcf 谓词全局量匿名、cff switchVar/BB 名匿名、
  strcry 密文反馈滚动密钥（`s = rol8(s ^ E[i]) + K[i]`，解密端无 nuw/nsw
  —— i8<<3 溢出 poison 会随滚动状态污染解密字节）、indibran 表随机名+可写
- 失败 skip / restore、验收脚本（`test_obf_hardening.sh` 18 项 gates）  
- LLVM 21 与 LLVM 23 双版本构建验证（LLVM 23: DenseMapInfo<CallSite> 哨兵、
  Constant::isZeroValue 移除两处兼容）
- CI：hardening-gates（LLVM 21/23 矩阵）+ 上游 smoke（16-seed sweep 实证
  抓出过上述 poison 与 alloca 共享两个真实 bug）

**未做 / 非目标（当前）**

- 向量浮点 / 变参 / EH / 完整 IR  
- 商业级 opcode 空间膨胀、多解释器克隆、运行时自修改  
- Android 自定义 Linker / SO 抽取壳  
- 按 BB 拆多段小 VM（降低「大块 bytecode」观感的进一步方案）  
- 字节码逆序（对标 VMPacker；判定性价比低，暂不做）
- round-to-int intrinsic 虚拟化（`llvm.lrint/lround` 家族在 LLVM 20/21 x86
  ISel 不支持，需按版本 gate 到 rint/round+fptosi 降级 —— 参考 amice 的做法；
  Hikari 当前不使用这些 intrinsic，无影响）

---

## 13. 许可证

与仓库主体相同，见根目录 `LICENSE`（Hikari 系 AGPL 相关说明以仓库为准）。
