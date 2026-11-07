///|
/// Linux / Android 轻量进程控制（ptrace）契约。
///
/// 本文件：外部句柄声明、`extern "C"` 薄 shim 签名、中性值类型、错误模型、`MemoryView` trait。
/// 公开 API 的实现见 `target.mbt`（Target 状态机）与 `maps_parser.mbt`（`parse_maps` 纯解析）。
/// C shim 实现见 `stub/ptrace_stub.c`（桌面 stub，真实 libc 转发留待 Linux/设备轮次）。
///
/// 边界：只做 attach / maps / peek-poke / 单步 / 线程枚举。
/// 不做符号解析（配 `dwarfscope`）、不做指令级 inline hook（与 frida_gum_ffi 互为备选）。
/// 平台约束：仅 `native` 目标，Linux / Android；Android SELinux 与 ptrace_scope 需实测。

///|
#external
pub type TraceeRaw

///|
/// 进程 / 线程 ID。
pub type Pid = Int32

///|
/// 目标进程虚拟地址。
pub type Address = UInt64

///|
/// 内存区域权限。
pub(all) struct MemoryProtection {
  read : Bool
  write : Bool
  execute : Bool
  private : Bool
}

///|
/// `/proc/<pid>/maps` 的一行。
pub(all) struct MemoryRegion {
  start : Address
  end : Address
  protection : MemoryProtection
  offset : UInt64
  device : String
  inode : Int32
  path : String?
}

///|
/// 线程摘要（来自 `/proc/<pid>/task`）。
pub(all) struct ThreadInfo {
  tid : Pid
  name : String
  state : String
}

///|
/// 目标状态机。
pub(all) enum TargetState {
  Detached
  Attached
  Stepping
  Failed
}

///|
/// MoonBit 侧目标包装值。`handle` 为 C 侧裸指针，`pid` 用于 `/proc` 路径构造。
/// `handle` 只能由 `Target::detach` 释放一次。
/// `state` 为可变状态机字段（**私有字段**，冻结前 P0 决策 5，经只读访问器
/// `Target::state()` 读取）：`step` 进入 `Stepping`、`detach` 进入 `Detached`；
/// 释放失败进入 `Failed`。实现保证它与 C 侧句柄状态一致（见 `target.mbt`）。
pub(all) struct Target {
  pid : Pid
  handle : TraceeRaw
  priv mut state : TargetState
}

///|
/// ptrace 错误模型。
#derive(Debug)
pub suberror PtraceError {
  AttachDenied(Pid, String)
  DetachFailed(Pid, String)
  NotAttached(Pid)
  AlreadyAttached(Pid)
  ProcessNotFound(Pid)
  MapsParseFailed(Int32, String)
  ReadFailed(Address, Int32, String)
  WriteFailed(Address, Int32, String)
  StepFailed(Pid, String)
  ThreadEnumerateFailed(Pid, String)
  UnsupportedKernel(String)
  SelinuxDenied(String)
}

///|
pub extend PtraceError with Debug::{to_repr}

///|
/// 内存访问契约；实现必须保证「未 attach 时拒绝读写」。
pub trait MemoryView {
  fn read_bytes(Self, Address, Int32) -> Bytes raise PtraceError
  fn write_bytes(Self, Address, Bytes) -> Unit raise PtraceError
}

///|
/// ---- 外部 C shim 声明（**包私有，非公共 API**；冻结前 P0 决策 6）----
/// 符号由 `stub/ptrace_stub.c`（native-stub）提供：桌面 stub 模拟 tracee 句柄、
/// 内存页与 /proc 文本；真实 libc ptrace / process_vm_readv 转发留待 Linux/设备轮次。
/// 内部状态码与「/proc 文本包」协议见 stub 文件头部注释。
/// 可见性：7 个 `mb_ptrace_*` 均为**私有实现 ABI**（不再出现在公开快照），
/// MoonBit 层只经 `Target::{attach,maps,read_bytes,write_bytes,step,threads,detach}` 调用；
/// 符号名与签名保持不变，R2 真实对接无需改 ABI。

///|
/// `PTRACE_ATTACH` 并 waitpid 停住目标；返回 C 侧句柄（0 表示失败）。
extern "C" fn mb_ptrace_attach(pid : Int32) -> TraceeRaw = "mb_ptrace_attach"

///|
/// `PTRACE_DETACH` 并释放句柄（唯一释放点，且只能一次）。
extern "C" fn mb_ptrace_detach(handle : TraceeRaw) -> Int32 = "mb_ptrace_detach"

///|
/// `process_vm_readv`；`dst` 由 C 侧填充，`#borrow` 表示 MoonBit 保留所有权。
#borrow(dst)
extern "C" fn mb_ptrace_read_mem(
  handle : TraceeRaw,
  address : Address,
  dst : FixedArray[Byte],
  length : Int32,
) -> Int32 = "mb_ptrace_read_mem"

///|
/// `process_vm_writev`；`src` 为 `#borrow`，C 侧只读取。
#borrow(src)
extern "C" fn mb_ptrace_write_mem(
  handle : TraceeRaw,
  address : Address,
  src : Bytes,
  length : Int32,
) -> Int32 = "mb_ptrace_write_mem"

///|
/// 单步（`PTRACE_SINGLESTEP`）；返回 0 成功。
extern "C" fn mb_ptrace_step(handle : TraceeRaw) -> Int32 = "mb_ptrace_step"

///|
/// 读取 `/proc/<pid>/maps` 全文到调用方缓冲；`dst` 为 `#borrow`。
#borrow(dst)
extern "C" fn mb_ptrace_read_maps(
  pid : Int32,
  dst : FixedArray[Byte],
  capacity : Int32,
) -> Int32 = "mb_ptrace_read_maps"

///|
/// 读取 `/proc/<pid>/task` 目录条目数（供线程枚举分配缓冲）。
extern "C" fn mb_ptrace_task_count(pid : Int32) -> Int32 = "mb_ptrace_task_count"

///|
/// ---- MoonBit 侧公开 API ----
/// `Target::{attach,maps,read_bytes,write_bytes,step,threads,detach}` 实现见 `target.mbt`；
/// `parse_maps` 实现见 `maps_parser.mbt`。签名与文档契约见 `API.md`。
