# hnlyxiaobing/ptrace_lite

**Linux / Android 轻量进程控制库 —— attach、maps 解析、peek/poke、单步与线程枚举的 FFI 契约。**

> 状态：**实现轮完成（2026-11-07）+ API 冻结前整改**。1 个 `#external` 句柄、7 个 `extern "C"` shim（**包私有，私有实现 ABI，非公共 API**）、中性值类型、`MemoryView` trait 与全部包装 API 均已实现（桌面 `stub/ptrace_stub.c` 双路径）；`moon clean` / `moon check --deny-warn` / `moon build` / `moon test`（18 测试全过）/ `moon fmt --check` 全绿。
> **API 冻结前收紧决策**（详见 `DECISIONS.md`）：`Target.state` 收紧为 `priv` 私有字段 + 只读访问器 `Target::state()`（字段级可见性可用，仅收紧该字段，其余公开方法签名零变化）· 七个 `mb_ptrace_*` shim 移出公开 API · 追认 `pub impl MemoryView for Target`（**冻结后新增 impl 即破坏性变更**）· `detach` 措辞统一为「不会二次释放，重复调用返回明确错误（`NotAttached`）」。
> **真实 libc ptrace / `process_vm_*` 转发与设备实测留待 Linux / 设备阶段**（风险与待验证项见 `DECISIONS.md`）；本轮保持项目内 C stub 双路径，未链接/下载任何外部库。
> `preferred_target` 本轮由 `wasm` 改为 `native`（唯一配置改动，理由见 `DECISIONS.md`）。
> 定位：作为动态侧验证的**首选先行路径**（排序判据：是否阻塞交付 / 是否支撑动态验证闭环 / 可行性与许可 / 维护与可测 / 是否有更小替代，见 `DECISIONS.md`）；与 `frida_gum_ffi` **互斥备选、零互相 import**。

## 定位与为什么存在

选型复核（2026-11-06 检索 mooncakes.io）：`ptrace` 的两个注册表命中均为无关包——进程注入与控制能力在 MoonBit 生态完全空白，ptrace 无可用包。与 frida-gum 相比，本库**不依赖 devkit、少一层许可审查（无 wxWindows 3.1 许可门禁）、体积更小**，正是「更小替代方案」这一判据的落地（选型背景、决策与后果见 `DECISIONS.md`）。

它对最终目标的贡献是：**在静态线索（`apk`/`axml`/`dex`）指向候选符号后，用最小代价在受限设备上取到该符号的调用参数或内存快照**，把「猜」变成「验证」。因此本库排在 `frida_gum_ffi` 之前，而后者因「许可逐项审查 + 更小替代方案评估」两道门禁未解除而排后（见 `DECISIONS.md`）。

## 能力范围 / 非目标

- **做**：`PTRACE_ATTACH` / `PTRACE_DETACH`、`/proc/<pid>/maps` 解析、内存 peek/poke（`process_vm_readv` / `process_vm_writev`）、`PTRACE_SINGLESTEP`、线程枚举（`/proc/<pid>/task`）。
- **不做**：符号解析（配 `dwarfscope`）、指令级 inline hook、断点管理、反汇编、ARM64 指令边界判断、跨平台（仅 Linux / Android）。
- 与 `frida_gum_ffi` 二选一由**组合根**决定；抽象 `MemoryView` 留在本模块内，不新建公共模块，避免循环依赖。
- 本库不 import `pose` / `apk` / `axml` / `dex` / 任何本地模块（零本地模块 import，见 `DECISIONS.md`）。

## 公开接口（速览）

`Target::{attach, state, maps, read_bytes, write_bytes, step, threads, detach}` + 纯函数 `parse_maps(text)`；`state` 字段私有，经 `Target::state()` 只读访问。外部句柄与 shim 清单见 `API.md`。

## 依赖

- **零外部依赖**；独立 `moon.mod`，`moon check --deny-warn` 独立通过。shim 实现仅为**项目内** `stub/ptrace_stub.c` 桌面 stub（7 个 `mb_ptrace_*` 为包私有 ABI，非公共 API），**未链接/下载任何外部库**。
- 后续轮：`native-stub` C 文件转发 libc `ptrace` / `process_vm_readv` / `process_vm_writev` / `waitpid`，以及 `/proc` 读取；**不需要 frida devkit、不需要 GObject、不需要许可审查**。

## 平台与许可风险

| 风险 | 说明 |
|---|---|
| 权限 | Android SELinux `untrusted_app` 对 `PTRACE_ATTACH` 的限制、`kernel.yama.ptrace_scope` 取值**待实测**（见 `DECISIONS.md`「风险与待验证」）；错误模型已预留 `SelinuxDenied` / `AttachDenied` |
| 内核差异 | 不同内核的 `/proc/<pid>/maps` 字段、ptrace 细节差异；`UnsupportedKernel` 已预留 |
| 指令边界 | ARM64 单步的指令边界判断需要反汇编支持，属明确非目标 |
| 线程 | 单线程控制模型，`Target` 非线程安全；跨线程使用须由调用方串行化 |
| 许可 | 仅调用 libc 系统调用封装，无第三方库许可负担；**这是相对 frida-gum 的主要优势** |
| 平台 | `preferred_target = "native"`；仅 Linux / Android；Windows 主机不可运行（MSVC native 亦无 ptrace） |

## 测试与验收

- **可桌面纯测**：`parse_maps(text)` 的 golden 测试（不需要 attach、不需要 root），覆盖匿名映射、文件映射、权限位、缺 path、畸形行。
- **设备集成**：attach → maps → read → write → step → threads → detach 全链路在受限设备上跑通，记录 errno；负例覆盖 `NotAttached` / `AlreadyAttached` / `ProcessNotFound`；`detach` **不会二次释放，重复调用返回明确错误（`NotAttached`）**，detach 后句柄不悬挂。
- **验收标准（实现轮）**：全链路在目标设备可跑；`parse_maps` golden 全绿；验收门禁 `moon check --deny-warn` 转绿（API 冻结前整改起已绿）。
- **桌面 stub 实测（实现轮 + API 冻结前整改）**：`moon build` ✅ / `moon test` ✅ 18/18（全链路、`state()` 访问器、错误映射、shim ABI 白盒、`parse_maps` golden ×4、畸形行负例）；真实 libc 转发与设备实测留待后续轮。

## 当前状态 / 本轮产物

| 项 | 状态 |
|---|---|
| `ptrace_lite.mbt` / `target.mbt` / `maps_parser.mbt`：`#external` 句柄 ×1、`extern "C"` shim ×7（**包私有**）、公开 API ×9（`Target::{attach,state,maps,read_bytes,write_bytes,step,threads,detach}` + `parse_maps`）、`MemoryView` trait（impl 追认见 `API.md`）、`PtraceError`（12 构造） | ✅ |
| `pkg.generated.mbti` API 快照（由工具链 `rr_moon_pkg` 在 `moon check` / `moon build` 时自动同步至整改后公开面：7 个 shim 移除、`Target.state` 私有 + `Target::state()` 新增；维护时以 `moon info` 复核为准） | ✅ |
| 真实 libc 转发 / 设备实测（SELinux、ptrace_scope、W^X） | ❌ 后续阶段（见 `DECISIONS.md`「风险与待验证」） |
| `moon clean` / `moon check --deny-warn` / `moon build` / `moon test` / `moon fmt --check` | ✅ 全绿（18 测试） |

## 文档索引

`DESIGN.md`（设计契约）· `API.md`（公开接口）· `DECISIONS.md`（设计决策记录：轻量选型、无回调设计、native 目标、`parse_maps` 纯函数、`MemoryView` 可替换性、API 冻结前收紧、风险与待验证）· `README.mbt.md`
