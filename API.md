# ptrace_lite · 公开 API（API.md）

> 与 `pkg.generated.mbti` 一致。`declare` 函数**无实现**（预期 8 × `0068`）；`extern "C"` 只有声明。
> `preferred_target = "native"`。错误传播统一 `raise PtraceError`。
> 与 `frida_gum_ffi` 互斥备选，两库零互相 import（ADR-0002 / ADR-0006）。

## 外部句柄（`#external` = C `void*`）

| 句柄 | C 侧对应 | 释放点 |
|---|---|---|
| `TraceeRaw` | tracer 持有的 tracee 上下文 | `Target::detach`（唯一一次） |

## 外部 C shim 声明（7 个，无回调）

| shim | 所有权 | 语义 |
|---|---|---|
| `mb_ptrace_attach(pid : Int) -> TraceeRaw` | — | `PTRACE_ATTACH` + `waitpid` 停住目标；空句柄表示失败 |
| `mb_ptrace_detach(handle : TraceeRaw) -> Int` | — | `PTRACE_DETACH` 并释放句柄；唯一释放点 |
| `mb_ptrace_read_mem(handle, address : Address, dst : FixedArray[Byte], length : Int) -> Int` | `#borrow(dst)` | `process_vm_readv`，C 侧填充 dst |
| `mb_ptrace_write_mem(handle, address : Address, src : Bytes, length : Int) -> Int` | `#borrow(src)` | `process_vm_writev`，C 侧只读 src |
| `mb_ptrace_step(handle : TraceeRaw) -> Int` | — | `PTRACE_SINGLESTEP`，0 = 成功 |
| `mb_ptrace_read_maps(pid : Int, dst : FixedArray[Byte], capacity : Int) -> Int` | `#borrow(dst)` | 读 `/proc/<pid>/maps` 全文，返回实际长度 |
| `mb_ptrace_task_count(pid : Int) -> Int` | — | `/proc/<pid>/task` 条目数，供线程枚举分配缓冲 |

> `#borrow` / `#owned` 是**写在 fn 声明之前的独立属性行**，不是参数注解。本模块无回调，因此不需要 `FuncRef` 与 `#owned` 闭包。

## 值类型 / 错误 / 契约

| 类型 | 种类 | 说明 |
|---|---|---|
| `Pid` / `Address` | `pub type` | `Int` / `UInt64` 别名 |
| `MemoryProtection` | `pub(all) struct` | read / write / execute / private |
| `MemoryRegion` | `pub(all) struct` | start / end / protection / offset / device / inode / `path : String?` |
| `ThreadInfo` | `pub(all) struct` | tid / name / state |
| `TargetState` | `pub(all) enum` | `Detached` / `Attached` / `Stepping` / `Failed` |
| `Target` | `pub(all) struct` | `pid` / `handle : TraceeRaw` / `state` |
| `PtraceError` | `pub suberror` | 12 个错误构造 |
| `MemoryView` | `pub trait` | `read_bytes(Self, Address, Int)` / `write_bytes(Self, Address, Bytes)` |

## MoonBit 侧公开 API（全部 `declare`）

| 签名 | 参数与所有权 | 返回 / 错误 | 资源与线程约束 | TODO |
|---|---|---|---|---|
| `Target::attach(pid : Pid) -> Target raise PtraceError` | `pid` 纯值 | `Target` / `AttachDenied`、`ProcessNotFound`、`AlreadyAttached`、`SelinuxDenied` | **获取 C 句柄**；失败时不持有资源；单线程控制模型 | 多线程停止语义、errno 映射 |
| `Target::maps(self : Target) -> Array[MemoryRegion] raise PtraceError` | `self` 只读 | 按地址升序区间列表 / `MapsParseFailed` | 缓冲由 MoonBit 持有 | `/proc` 文本解析、内核差异降级 |
| `Target::read_bytes(self : Target, address : Address, length : Int) -> Bytes raise PtraceError` | `self` 只读 | 原始字节 / `NotAttached`、`ReadFailed` | 未 attach 必须拒绝；校验长度 | 跨页读取、部分读处理 |
| `Target::write_bytes(self : Target, address : Address, data : Bytes) -> Unit raise PtraceError` | `data` 只读 | `Unit` / `NotAttached`、`WriteFailed` | 调用方保证目标页可写（W^X） | mprotect 策略 |
| `Target::step(self : Target) -> Unit raise PtraceError` | `self` 只读 | `Unit` / `StepFailed` | `state` 进入 `Stepping` | ARM64 指令边界（需反汇编，非目标） |
| `Target::threads(self : Target) -> Array[ThreadInfo] raise PtraceError` | `self` 只读 | 线程列表 / `ThreadEnumerateFailed` | `/proc/<pid>/task` 枚举 | task 状态读取 |
| `Target::detach(self : Target) -> Unit raise PtraceError` | 消耗释放责任 | `Unit` / `NotAttached`、`DetachFailed` | **唯一释放点、幂等**；禁止二次 detach | — |
| `parse_maps(text : String) -> Array[MemoryRegion] raise PtraceError` | 纯文本 | 区间列表 / `MapsParseFailed(Int, String)` | **纯函数、可并发、无需 attach** | golden 样本与畸形行处理 |

## 错误构造速查

`AttachDenied(pid, msg)` · `DetachFailed(pid, msg)` · `NotAttached(pid)` · `AlreadyAttached(pid)` · `ProcessNotFound(pid)` · `MapsParseFailed(line, msg)` · `ReadFailed(addr, len, msg)` · `WriteFailed(addr, len, msg)` · `StepFailed(pid, msg)` · `ThreadEnumerateFailed(pid, msg)` · `UnsupportedKernel(msg)` · `SelinuxDenied(msg)`

## 非目标 / 能力边界

符号解析（`dwarfscope`）· inline hook / trampoline · 断点管理 · 反汇编 · 寄存器上下文快照 · 跨平台（仅 Linux / Android）· Java 方法 hook。

## 状态与已知阻塞

`moon check`：✅ 0 error，8 × `0068`。`moon build` / `moon test`：❌ **预期链接期失败**（`mb_ptrace_*` shim 未实现）。`parse_maps` 实现后即可在桌面 CI 做纯测；attach 相关集成测试需目标设备与权限实测（E5）。实现：❌ 后续轮（ADR-0005 W1）。
