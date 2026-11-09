# ptrace_lite · 设计契约（DESIGN.md）

> 实现轮（2026-11-07 完成）+ **API 冻结前整改** ｜ 状态：MoonBit 层 API 全部实现（桌面 C stub 双路径）；无真实 libc 转发、无设备实测（留待 Linux / 设备阶段）

## 1. 分层位置与职责

动态插桩层（本库所在层）的**进程外轻量控制 FFI 封装**。职责：把 libc ptrace / `process_vm_*` 与 `/proc` 文本映射为 MoonBit 值类型与显式错误，用最小依赖换取「候选符号的运行时证据」。是 `frida_gum_ffi` 的**更小备选**，排序在前（选型与排序理由见 `DECISIONS.md`）。

## 2. 模块边界 / 依赖方向 / 数据流

```
组合根（选择插桩方案）
   ├─► ptrace_lite::Target::attach ──► mb_ptrace_* shim（包私有 ABI）──► libc ptrace / process_vm_* / /proc
   └─► frida_gum_ffi::Gum          （互斥备选，排后且设「许可审查 + 更小替代评估」门禁）
```

两库**零互相 import**；`MemoryView` trait 留在本模块、`InstrumentationBackend` 留在 gum 模块，组合根按中性值类型选择，不新建公共抽象模块，避免循环依赖。本库不 import 任何本地模块，`#external` 句柄（`TraceeRaw`）永不跨模块传递（见 `DECISIONS.md`）。

数据流：`Pid` → `Target`（持有 `TraceeRaw`）→ `Array[MemoryRegion]`（maps）→ `Bytes`（read）→ 组合根与 `axml`/`dex` 静态线索关联。

## 3. 核心数据结构

| 类型 | 作用 |
|---|---|
| `TraceeRaw` | 唯一 `#external` 句柄（C `void*`），MoonBit 不引用计数 |
| `Pid` / `Address` | `Int` / `UInt64` 别名，防止裸整数混用 |
| `MemoryProtection { read, write, execute, private }` | maps 权限位 |
| `MemoryRegion { start, end, protection, offset, device, inode, path? }` | `/proc/<pid>/maps` 一行；`path` 为 `String?`（匿名映射） |
| `ThreadInfo { tid, name, state }` | `/proc/<pid>/task` 摘要 |
| `TargetState` | `Detached` / `Attached` / `Stepping` / `Failed` 状态机（四分支均被实际代码路径使用，保留） |
| `Target { pid, handle, state }` | MoonBit 侧包装值；`handle` 只能由 `detach` 释放一次；**`state` 为 `priv` 私有字段（API 冻结前收紧，见 `DECISIONS.md`），经只读访问器 `Target::state()` 读取**，其余公开方法签名零变化 |
| `PtraceError` | `pub suberror`，12 个可判定错误构造 |
| `MemoryView` trait | `read_bytes(Self, Address, Int32)` / `write_bytes(Self, Address, Bytes)`，供组合根做插桩方案替换；**`pub impl MemoryView for Target` 已于 API 冻结前追认（见 `DECISIONS.md`）** |

> 设计取舍：`Target` 是**值类型**而非「不透明对象 + 全局注册表」，因为本轮禁止任何状态管理逻辑；`state` 字段把「未 attach 时拒绝读写」的约束变成可检查的显式数据。实现轮须保证它与 C 侧句柄状态一致。API 冻结前整改起该字段**私有化**，外部只经 `Target::state()` 只读观察，防止包外篡改状态机。

## 4. 错误模型

`PtraceError`：`AttachDenied(Pid, String)`、`DetachFailed(Pid, String)`、`NotAttached(Pid)`、`AlreadyAttached(Pid)`、`ProcessNotFound(Pid)`、`MapsParseFailed(Int32, String)`、`ReadFailed(Address, Int32, String)`、`WriteFailed(Address, Int32, String)`、`StepFailed(Pid, String)`、`ThreadEnumerateFailed(Pid, String)`、`UnsupportedKernel(String)`、`SelinuxDenied(String)`。

全部失败型 API 统一 `-> T raise PtraceError`（不用 `Result[T, E]`）；`String` 参数用于承载 errno / 内核消息，便于设备实测时定位。错误只在本模块内产生，组合根负责映射为上层线索报告。

## 5. 资源生命周期

| 资源 | 获取 | 唯一释放点 | 规则 |
|---|---|---|---|
| `TraceeRaw` | `mb_ptrace_attach(pid)` | `Target::detach` | 返回 0 表示失败且不持有资源；**只能释放一次** |
| 读写缓冲 | `FixedArray[Byte]` / `Bytes` | 调用方持有 | 全部 `#borrow`，C 侧只填充或只读 |
| maps 文本缓冲 | `FixedArray[Byte]` | 调用方持有 | `#borrow(dst)` + `capacity`，返回实际长度 |
| 数组 / 字符串结果 | MoonBit 分配 | GC | 无外部释放义务 |

`Target::detach` **不会二次释放，重复调用返回明确错误（`NotAttached`）**，不得二次 `PTRACE_DETACH`；释放失败进入 `Failed` 并报 `DetachFailed`。状态守卫 `ensure_open` 仅放行 `Attached` / `Stepping`，`Detached` / `Failed` 一律 `NotAttached`（契约写进 `MemoryView` 的文档注释）。

## 6. 线程 / 并发边界

- **单线程控制模型**：`Target` 非线程安全；跨线程使用必须由调用方串行化。ptrace 的「一个 tracee 只能有一个 tracer」在语义上也不允许并发 attach。
- 本模块**没有回调**（与 gum / camera2 不同），因此不触发「被钩线程执行 MoonBit 闭包」的线程安全风险（详见 `DECISIONS.md`「无回调设计」）—— 这正是把它排在前者的理由之一。
- `parse_maps(text)` 为纯函数、无状态，可并发调用。
- `[待验证假设]` 多线程 `PTRACE_ATTACH` 的逐线程停止语义，以及 `/proc/<pid>/task` 在 attach 状态下的可读性，需设备实测。设计侧方案（枚举 → 逐 TID attach + waitpid → `TRACECLONE` 竞态 → 回滚）见 `FORWARDING.md` §5，全部 `[仍需实测]`。

## 7. 平台约束与外部依赖

- `preferred_target = "native"`（本轮由 `wasm` 调整而来，理由见 `DECISIONS.md`）；`extern "C"` 在 wasm 目标被 `E4156` 拒绝。
- 仅 Linux / Android；Windows 主机无法运行（无 ptrace）。Android 需 root 或 `PTRACE_ATTACH` 权限，SELinux / `ptrace_scope` 待实测（见 `DECISIONS.md`「风险与待验证」）。
- 后续依赖：`native-stub` C 文件 + libc；**无第三方库、无 devkit、无许可审查门禁**。
- `[事实]` native 后端不能把 `foreign_library` 导出为可链接 `.so/.dll`，故设备侧仍需「C stub + 宿主 NDK/CMake」路径（MoonBit 产物以 C 源码/对象形式进入宿主 NDK/CMake 工程链接）。

## 8. 外部类型 / 句柄 / shim / 所有权规则

| 类别 | 声明 | 规则 |
|---|---|---|
| 外部类型 | `TraceeRaw`（`#external pub type`） | C `void*`；不引用计数；**永不跨模块传递** |
| 外部函数 | 7 个 `extern "C" fn mb_ptrace_* = "…"`（**包私有，私有实现 ABI、非公共 API**；API 冻结前移出公开 API，见 `DECISIONS.md`） | 统一返回 `Int32` status（0 = 成功，或 0 = 空句柄，按各 shim 语义） |
| 缓冲所有权 | `mb_ptrace_read_mem(#borrow(dst))`、`mb_ptrace_write_mem(#borrow(src))`、`mb_ptrace_read_maps(#borrow(dst))` | 独立属性行写在 fn 之前；MoonBit 保留所有权，C 侧不 decref |
| 地址 / 长度 | `Address` = `UInt64`、`length : Int32` | 调用方校验长度与缓冲容量；C 侧不做越界推断 |

shim 清单：`mb_ptrace_attach` / `mb_ptrace_detach` / `mb_ptrace_read_mem` / `mb_ptrace_write_mem` / `mb_ptrace_step` / `mb_ptrace_read_maps` / `mb_ptrace_task_count`。**7 个均为包私有（私有实现 ABI，非公共 API）**，符号与签名不变、真实 libc 对接无需改 ABI。**无回调 shim**，故不需要 `FuncRef` / `#owned`。

## 9. 可替换性与实现细节不泄漏

上层只看到 `Target` / `MemoryRegion` / `ThreadInfo` / `Bytes`；看不到 fd、waitpid 状态、`process_vm_*` iovec 布局、`/proc` 文本格式。`MemoryView` trait 让组合根可换成 `frida_gum_ffi`、ShadowHook/bhook 或纯静态分析，不改上层线索关联逻辑。注意 `ptrace_lite::MemoryRegion` 与 `frida_gum_ffi::MemoryRegion` **结构同构但名义类型不同**，由组合根适配（名义类型与零 import 决策见 `DECISIONS.md`）。

## 10. 测试策略

| 层次 | 内容 |
|---|---|
| 纯测（桌面） | `parse_maps` golden：文件/匿名映射、rwx 权限、缺 path、偏移/device/inode、畸形行 → `MapsParseFailed` |
| 负例 | 未 attach 读写 → `NotAttached`；重复 attach → `AlreadyAttached`；不存在 pid → `ProcessNotFound`；重复 detach → `NotAttached` |
| 集成（设备） | attach → maps → read → write → step → threads → detach；记录 errno 与 SELinux 拒绝信息 |
| 平台 | x86-64 Linux 桌面先跑通；Android arm64 / armv7 记录权限差异 |
| 门禁 | 四道门禁统一口径：`moon check --deny-warn` / `moon build` / `moon test` / `moon fmt --check`（另加 `moon clean`），API 冻结前整改实测全绿 |

## 11. 验收标准（实现轮）

1. `parse_maps` golden 全绿（无需 root，可在 CI 跑）；2. attach→detach 全链路在受限设备上可跑且无悬挂句柄；3. 所有非法输入返回 `PtraceError` 而非 panic；4. 验收门禁 `moon check --deny-warn` 转绿。

## 12. 未解决问题 / 待验证假设

- **SELinux / `kernel.yama.ptrace_scope`**：Android SELinux `untrusted_app` 域对 `PTRACE_ATTACH` 的实际限制、`ptrace_scope` 取值（0–3）的影响**待设备实测**（高优先待验证项）。
- **W^X 页写入**：目标页写入的 W^X 限制（如 `mprotect(PROT_WRITE|PROT_EXEC)`）待实测。
- **内核差异**：不同内核 `/proc/<pid>/maps` 字段与 ptrace 细节差异待实测，`UnsupportedKernel` 已预留。
- **设备测试基线缺口**：真实 APK 测试资产不在本仓库，设备测试用例缺少基线样本。
- **ARM64 单步指令边界**：需反汇编支持（明确非目标）；多线程 attach 语义待实测。

（以上风险与待验证项的完整内联记录见 `DECISIONS.md`「风险与待验证」。）

## 13. 当前状态与 TODO

`ptrace_lite.mbt` / `target.mbt` / `maps_parser.mbt` 已写入 1 个 `#external` 句柄、7 个**包私有** shim、
值类型、状态机、错误模型、`MemoryView` trait 与全部 MoonBit 层 API 实现（含 `parse_maps` 纯解析、
错误映射、缓冲容量校验）。**API 冻结前整改已落实**（四项收紧的完整记录见 `DECISIONS.md`）：
`Target.state` 私有字段 + 只读访问器 `Target::state()`（字段级可见性可用故仅收紧该字段）、
7 个 shim 移出公开 API、追认 `pub impl MemoryView for Target`（冻结后新增 impl 即破坏性变更）、
detach 幂等措辞统一。
**仍无**真实 libc ptrace / `process_vm_*` 转发与设备实测（留待 Linux / 设备阶段，见 `DECISIONS.md`「风险与待验证」）。

### 13.1 R4 增量（2026-11-09，仅桌面可验证部分）

- **`access_plan.mbt`（新增，包私有）**：跨页访问分段计划。保守 4 KiB 粒度、
  段数上限 fail-closed、按方向映射 `ReadFailed`/`WriteFailed`；
  `Target::read_bytes` / `write_bytes` 已接入逐段调用，任一段失败即整体失败
  （不静默截断），错误携带失败段地址/长度/序号。
- **`errno_map.mbt`（新增，包私有）**：真实转发层 errno 分类映射
  （`ESRCH`/`EPERM`/`EACCES`/`EFAULT`/`EIO`/`EINVAL`/`ENOSYS`/`EINTR`/`EBUSY`/`ECHILD`
  → 12 个 `PtraceError` 构造），定义 `-1000 - errno` 真实状态通道，
  与 stub 合成码 `-1..-8` 隔离；`SelinuxDenied` 仍只由 stub `-4`/显式探测产生。
- **stub fail-closed 修复**：`stub/ptrace_stub.c` 的句柄槽在 detach 后被复用，
  修复「同一进程内第 9 次 attach 假性失败」；stub 仍只模拟 pid 4242，
  未知 pid / 非法地址 / 只读页写入一律显式错误。
- **CLI 骨架**：`cmd/main` 落地 `attach` / `maps` / `read` / `write` / `step`
  子命令与参数解析，退出码 `0=成功 / 1=运行失败 / 2=用法错误`；
  桌面 stub 后端可跑，真实设备实测留待 E5 `[仍需实测]`。
- **测试**：18 项既有基线零删改，新增 31 项（分段计划 11 / errno 7 /
  fail-closed 5 / CLI 5 / 多页 fixture 3），总计 **49/49** 通过（`[已复验-本地等价]`）。
- **真实转发设计**：`FORWARDING.md` 给出 7 个 shim 的 libc 转发规格、
  跨页/部分读写、`mprotect` 写入策略、多线程逐线程停止、`waitpid` 细节、
  内核差异降级；**全部真实路径标 `[仍需实测]`**（E5 未解禁）。

## References

本仓库内文档：`FORWARDING.md`（真实转发层设计，逐条 `[仍需实测]`）· `DECISIONS.md`（设计决策记录：轻量选型、无回调设计、native 目标、`parse_maps` 纯函数、`MemoryView` 可替换性、API 冻结前收紧、分段计划与 errno 通道、CLI 退出码、风险与待验证、平台与集成约束）· `API.md` · `README.md` · `README.mbt.md`
