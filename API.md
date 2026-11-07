# ptrace_lite · 公开 API（API.md）

> **冻结前 P0 整改后（R2 准备轮）**。`preferred_target = "native"`，错误传播统一 `raise PtraceError`。
> MoonBit 侧 API **全部已实现**（桌面 C stub 双路径），无 `declare` 残留、无 `0068` 告警。
> 快照 `pkg.generated.mbti` 已由工具链（`rr_moon_pkg`）在 `moon check` / `moon build` 时**自动同步**为
> 本轮 P0 后公开面（7 个 `mb_ptrace_*` shim 消失、`Target.state` 私有 + 新增 `Target::state()` 等）；
> 本子代理**未运行 `moon info`**，最终快照审阅由主控统一执行。
> 与 `frida_gum_ffi` 互斥备选，两库零互相 import（ADR-0002 / ADR-0006）。

## 外部句柄（`#external` = C `void*`）

| 句柄 | C 侧对应 | 释放点 |
|---|---|---|
| `TraceeRaw` | tracer 持有的 tracee 上下文 | `Target::detach`（唯一一次） |

## 外部 C shim（7 个 · **私有实现 ABI，非公共 API** · 无回调）

> **冻结前 P0 决策 6**：7 个 `mb_ptrace_*` 全部改为**包私有**，不再出现在公开 API / 快照；
> 实现与内部调用（`Target::{attach,maps,read_bytes,write_bytes,step,threads,detach}`）全部保留，
> 符号名与签名不变，R2 真实 libc 对接无需改 ABI。
> 黑盒测试不直接调用 shim；直接调用的白盒用例（capacity `-7`、stale handle `-8`）
> 已转 `ptrace_lite_wbtest.mbt`（**测试总数不变：18**）。
> 下表仅作**内部 ABI 文档**，不构成公共 API 承诺。

| shim（包私有） | 所有权 | 语义 |
|---|---|---|
| `mb_ptrace_attach(pid : Int32) -> TraceeRaw` | — | `PTRACE_ATTACH` + `waitpid` 停住目标；空句柄表示失败 |
| `mb_ptrace_detach(handle : TraceeRaw) -> Int32` | — | `PTRACE_DETACH` 并释放句柄；唯一释放点 |
| `mb_ptrace_read_mem(handle, address : Address, dst : FixedArray[Byte], length : Int32) -> Int32` | `#borrow(dst)` | `process_vm_readv`，C 侧填充 dst |
| `mb_ptrace_write_mem(handle, address : Address, src : Bytes, length : Int32) -> Int32` | `#borrow(src)` | `process_vm_writev`，C 侧只读 src |
| `mb_ptrace_step(handle : TraceeRaw) -> Int32` | — | `PTRACE_SINGLESTEP`，0 = 成功 |
| `mb_ptrace_read_maps(pid : Int32, dst : FixedArray[Byte], capacity : Int32) -> Int32` | `#borrow(dst)` | 读 `/proc/<pid>/maps` 全文，返回实际长度 |
| `mb_ptrace_task_count(pid : Int32) -> Int32` | — | `/proc/<pid>/task` 条目数，供线程枚举分配缓冲 |

> `#borrow` / `#owned` 是**写在 fn 声明之前的独立属性行**，不是参数注解。本模块无回调，因此不需要 `FuncRef` 与 `#owned` 闭包。

## 值类型 / 错误 / 契约

| 类型 | 种类 | 说明 |
|---|---|---|
| `Pid` / `Address` | `pub type` | `Int32` / `UInt64` 别名（与 `pkg.generated.mbti` 一致） |
| `MemoryProtection` | `pub(all) struct` | read / write / execute / private |
| `MemoryRegion` | `pub(all) struct` | start / end / protection / offset / device / inode / `path : String?` |
| `ThreadInfo` | `pub(all) struct` | tid / name / state |
| `TargetState` | `pub(all) enum` | `Detached` / `Attached` / `Stepping` / `Failed` |
| `Target` | `pub(all) struct`（**字段级收紧**：`state` 为 `priv` 私有字段） | `pid` / `handle : TraceeRaw` 保持公开；**`state` 私有**，经只读访问器 `Target::state()` 读取（决策 5） |
| `PtraceError` | `pub suberror` | 12 个错误构造 |
| `MemoryView` | `pub trait` | `read_bytes(Self, Address, Int32)` / `write_bytes(Self, Address, Bytes)`；impl：`pub impl MemoryView for Target`（决策 7 追认） |

## MoonBit 侧公开 API（全部已实现）

| 签名 | 参数与所有权 | 返回 / 错误 | 资源与线程约束 | TODO |
|---|---|---|---|---|
| `Target::attach(pid : Pid) -> Target raise PtraceError` | `pid` 纯值 | `Target` / `AttachDenied`、`ProcessNotFound`、`AlreadyAttached`、`SelinuxDenied` | **获取 C 句柄**；失败时不持有资源；单线程控制模型 | 多线程停止语义、errno 映射 |
| `Target::state(self : Target) -> TargetState` | `self` 只读 | 当前状态快照 | **只读访问器**（冻结前 P0 决策 5：`state` 字段私有化，公开方法签名零变化） | — |
| `Target::maps(self : Target) -> Array[MemoryRegion] raise PtraceError` | `self` 只读 | 按地址升序区间列表 / `MapsParseFailed` | 缓冲由 MoonBit 持有 | `/proc` 文本解析、内核差异降级 |
| `Target::read_bytes(self : Target, address : Address, length : Int32) -> Bytes raise PtraceError` | `self` 只读 | 原始字节 / `NotAttached`、`ReadFailed` | 未 attach 必须拒绝；校验长度 | 跨页读取、部分读处理 |
| `Target::write_bytes(self : Target, address : Address, data : Bytes) -> Unit raise PtraceError` | `data` 只读 | `Unit` / `NotAttached`、`WriteFailed` | 调用方保证目标页可写（W^X） | mprotect 策略 |
| `Target::step(self : Target) -> Unit raise PtraceError` | `self` 只读 | `Unit` / `StepFailed` | `state` 进入 `Stepping` | ARM64 指令边界（需反汇编，非目标） |
| `Target::threads(self : Target) -> Array[ThreadInfo] raise PtraceError` | `self` 只读 | 线程列表 / `ThreadEnumerateFailed` | `/proc/<pid>/task` 枚举 | task 状态读取 |
| `Target::detach(self : Target) -> Unit raise PtraceError` | 消耗释放责任 | `Unit` / `NotAttached`、`DetachFailed` | **唯一释放点；不会二次释放，重复调用返回明确错误（`NotAttached`）** | — |
| `parse_maps(text : String) -> Array[MemoryRegion] raise PtraceError` | 纯文本 | 区间列表 / `MapsParseFailed(Int32, String)` | **纯函数、可并发、无需 attach** | golden 样本与畸形行处理 |

## 错误构造速查

`AttachDenied(pid, msg)` · `DetachFailed(pid, msg)` · `NotAttached(pid)` · `AlreadyAttached(pid)` · `ProcessNotFound(pid)` · `MapsParseFailed(line, msg)` · `ReadFailed(addr, len, msg)` · `WriteFailed(addr, len, msg)` · `StepFailed(pid, msg)` · `ThreadEnumerateFailed(pid, msg)` · `UnsupportedKernel(msg)` · `SelinuxDenied(msg)`

## 冻结前追认记录（决策 7）

- **`pub impl MemoryView for Target`**（`read_bytes` / `write_bytes`，实现见 `target.mbt`）：
  R1 快照 `pkg.generated.mbti` 已含该 impl（`pub impl MemoryView for Target`），
  **冻结前正式追认**——`MemoryView for Target` 属公开面，**冻结后新增 impl 即破坏性变更**。
- 本轮对 `Target` 的字段级收紧（`state` → `priv` + `Target::state()`）与
  7 个 shim 私有化属允许的「私有化」类变化；其余公开方法签名零变化。

## 非目标 / 能力边界

符号解析（`dwarfscope`）· inline hook / trampoline · 断点管理 · 反汇编 · 寄存器上下文快照 · 跨平台（仅 Linux / Android）· Java 方法 hook。

## 状态与已知阻塞

**冻结前 P0 整改（R2 准备轮）实跑**：`moon clean` / `moon check --deny-warn` / `moon build` /
`moon test`（18 测试全过）/ `moon fmt --check` 全部 exit 0（桌面 C stub 环境）。
`parse_maps` 纯测可在桌面 CI 跑；真实 libc ptrace / `process_vm_*` 转发与 attach 相关
设备实测留待 **Linux/设备轮次**（E5）。API 快照：`pkg.generated.mbti`（工具链已自动同步至本轮 P0 后公开面，待主控终审）。
