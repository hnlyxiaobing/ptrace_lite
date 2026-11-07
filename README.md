# hnlyxiaobing/ptrace_lite

**Linux / Android 轻量进程控制库 —— attach、maps 解析、peek/poke、单步与线程枚举的 FFI 契约。**

> 状态：**Round-1 架构与声明可评审**。已写入 1 个 `#external` 句柄、7 个 `extern "C"` shim 签名、`#borrow` 所有权、中性值类型、`MemoryView` trait 及 8 个 `declare` 包装 API，`moon check` 0 error（8 条预期 `0068` 告警）。**无系统调用执行逻辑、无 `/proc` 解析逻辑、无 shim 实现**。
> `preferred_target` 本轮由 `wasm` 改为 `native`（唯一配置改动，理由见 ADR-0007）。
> 排序：作为 L2 **首选验证路径**（`dependency-graph.md` 序 10 / ADR-0005 W1）；与 `frida_gum_ffi` **互斥备选、零互相 import**。

## 定位与为什么存在

路线图「拼图二」复核（2026-11-06）：`ptrace` 的两个注册表命中均为无关包，进程注入与控制能力在 MoonBit 生态完全空白。与 frida-gum 相比，本库**不依赖 devkit、不受 wxWindows 3.1 许可门禁约束**，是「更小替代方案」这一判据的直接落地（`capability-matrix.md` / `dependency-graph.md` K4）。

它对最终目标的贡献是：**在静态线索（`apk`/`axml`/`dex`）指向候选符号后，用最小代价在受限设备上取到该符号的调用参数或内存快照**，把「猜」变成「验证」。因此本轮把它排在 `frida_gum_ffi` 之前，而后者被 ADR-0006 挡到 W2 之后。

## 能力范围 / 非目标

- **做**：`PTRACE_ATTACH` / `PTRACE_DETACH`、`/proc/<pid>/maps` 解析、内存 peek/poke（`process_vm_readv` / `process_vm_writev`）、`PTRACE_SINGLESTEP`、线程枚举（`/proc/<pid>/task`）。
- **不做**：符号解析（配 `dwarfscope`）、指令级 inline hook、断点管理、反汇编、ARM64 指令边界判断、跨平台（仅 Linux / Android）。
- 与 `frida_gum_ffi` 二选一由**组合根**决定；抽象 `MemoryView` 留在本模块内，不新建公共模块，避免 K4 循环。
- 本库不 import `pose` / `apk` / `axml` / `dex` / 任何本地模块（ADR-0002）。

## 公开接口（速览）

`Target::{attach, maps, read_bytes, write_bytes, step, threads, detach}` + 纯函数 `parse_maps(text)`。外部句柄与 shim 清单见 `API.md`。

## 依赖

- **本轮零依赖、零 shim 实现**；独立 `moon.mod`，`moon check` 独立通过。
- 后续轮：`native-stub` C 文件转发 libc `ptrace` / `process_vm_readv` / `process_vm_writev` / `waitpid`，以及 `/proc` 读取；**不需要 frida devkit、不需要 GObject、不需要许可审查**。

## 平台与许可风险

| 风险 | 说明 |
|---|---|
| 权限 | Android SELinux `untrusted_app` 对 `PTRACE_ATTACH` 的限制、`kernel.yama.ptrace_scope` 取值**待实测**（E5，P1）；错误模型已预留 `SelinuxDenied` / `AttachDenied` |
| 内核差异 | 不同内核的 `/proc/<pid>/maps` 字段、ptrace 细节差异；`UnsupportedKernel` 已预留 |
| 指令边界 | ARM64 单步的指令边界判断需要反汇编支持，属明确非目标 |
| 线程 | 单线程控制模型，`Target` 非线程安全；跨线程使用须由调用方串行化 |
| 许可 | 仅调用 libc 系统调用封装，无第三方库许可负担；**这是相对 frida-gum 的主要优势** |
| 平台 | `preferred_target = "native"`；仅 Linux / Android；Windows 主机不可运行（MSVC native 亦无 ptrace） |

## 测试与验收

- **可桌面纯测**：`parse_maps(text)` 的 golden 测试（不需要 attach、不需要 root），覆盖匿名映射、文件映射、权限位、缺 path、畸形行。
- **设备集成**：attach → maps → read → write → step → threads → detach 全链路在受限设备上跑通，记录 errno；负例覆盖 `NotAttached` / `AlreadyAttached` / `ProcessNotFound`；detach 后句柄不悬挂。
- **验收标准（实现轮）**：全链路在目标设备可跑；`parse_maps` golden 全绿；R4 `--deny-warn` 转绿。
- **本轮阻塞（预期）**：`moon build` / `moon test` 会在链接期失败（`mb_ptrace_*` shim 未实现）。

## 当前状态 / 本轮产物

| 项 | 状态 |
|---|---|
| `ptrace_lite.mbt`：`#external` 句柄 ×1、`extern "C"` shim ×7、`declare` API ×8、`MemoryView` trait、`PtraceError`（12 构造） | ✅ |
| `pkg.generated.mbti` API 快照 | ✅ |
| C shim / `/proc` 解析 / 单步 / 线程枚举 / 设备实测 | ❌ 后续轮 |
| `moon check` | ✅ 0 error（8 × `0068`，预期） |

## 文档索引

`DESIGN.md` · `API.md` · `../docs/adr/ADR-0002`（零 import）、`ADR-0006`（备选关系）、`ADR-0007`（native）、`ADR-0009`（回调与线程原则）· `../docs/architecture.md` §6 L2 · `../docs/open-questions.md` E5 / Q1
