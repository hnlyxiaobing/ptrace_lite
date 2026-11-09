///|
/// 真实转发层的 errno 分类映射（纯逻辑，桌面可测，无需真实 libc）。
///
/// ## shim 状态通道
///
/// - `0` / 正数：成功（读写字节数 / `/proc` 文本所需长度 / 线程数）；
/// - `-1 .. -999`：桌面 stub 合成码（见 `stub/ptrace_stub.c` 头注释，legacy）；
/// - `<= -1001`：真实 libc 路径，编码为 `-1000 - errno`（`errno` 为正 POSIX 值）。
///
/// 为什么真实路径不直接返回 `-errno`：`-2` 在 stub 协议里是「无此进程」，
/// 在 errno 里是 `ENOENT`；`-3` / `-4` / `-5` 同样与 stub 合成码冲突。
/// 加 1000 偏移把两个通道彻底分开，stub 既有 ABI 与 18 项基线测试零改动。
/// 该协议是**设计侧结论**，真实内核路径 **[仍需实测]**（E5）。
///
/// ## 分类口径
///
/// `EPERM` / `EACCES` 无法仅凭 errno 区分 `kernel.yama.ptrace_scope`、
/// SELinux 与普通权限：统一映射为 `AttachDenied` 并在消息里列出候选原因，
/// `SelinuxDenied` 保留给 stub 合成码 `-4` 与将来的显式 SELinux 探测。
/// `ENOSYS`（`process_vm_*` / `ptrace` 缺失）映射 `UnsupportedKernel`。
/// `EINTR` 属应重试项，若被 shim 泄漏则显式报错而不是静默继续。

///|
/// 内部：真实 errno 通道偏移（`status = -1000 - errno`）。
const ERRNO_CHANNEL_BASE : Int32 = 1000

///|
/// 内部：可编码的 errno 上界（Linux errno 实际远小于此）。
const ERRNO_CHANNEL_MAX : Int32 = 4095

///|
const ERRNO_PERM : Int32 = 1

///|
const ERRNO_NOENT : Int32 = 2

///|
const ERRNO_SRCH : Int32 = 3

///|
const ERRNO_INTR : Int32 = 4

///|
const ERRNO_IO : Int32 = 5

///|
const ERRNO_CHLD : Int32 = 10

///|
const ERRNO_ACCES : Int32 = 13

///|
const ERRNO_FAULT : Int32 = 14

///|
const ERRNO_BUSY : Int32 = 16

///|
const ERRNO_INVAL : Int32 = 22

///|
const ERRNO_NOSYS : Int32 = 38

///|
/// 内部：系统调用上下文，决定错误构造与随错误携带的字段。
priv enum SyscallOp {
  Attach
  Detach
  Step
  ProcText
  ThreadEnum
  ReadMem(Address, Int32)
  WriteMem(Address, Int32)
}

///|
/// 内部：从 shim 状态码解出真实 errno；非真实通道返回 `None`。
fn errno_from_status(status : Int32) -> Int32? {
  if status <= -(ERRNO_CHANNEL_BASE + 1) &&
    status >= -(ERRNO_CHANNEL_BASE + ERRNO_CHANNEL_MAX) {
    Some(-(status + ERRNO_CHANNEL_BASE))
  } else {
    None
  }
}

///|
/// 内部：`read_bytes` / `write_bytes` 共用的 errno 分类。
fn classify_mem_errno(
  kind : AccessKind,
  address : Address,
  length : Int32,
  errno : Int32,
  pid : Pid,
  context : String,
) -> PtraceError {
  if errno == ERRNO_SRCH || errno == ERRNO_NOENT {
    PtraceError::ProcessNotFound(pid)
  } else if errno == ERRNO_FAULT {
    access_plan_error(
      kind,
      address,
      length,
      "bad address (EFAULT) [\{context}]",
    )
  } else if errno == ERRNO_INVAL {
    access_plan_error(
      kind,
      address,
      length,
      "invalid address/length (EINVAL) [\{context}]",
    )
  } else if errno == ERRNO_PERM || errno == ERRNO_ACCES {
    access_plan_error(
      kind,
      address,
      length,
      "permission denied (EPERM/EACCES; read-only page / W^X / SELinux / ptrace_scope) [\{context}]",
    )
  } else if errno == ERRNO_IO {
    access_plan_error(kind, address, length, "I/O error (EIO) [\{context}]")
  } else if errno == ERRNO_NOSYS {
    access_plan_error(
      kind,
      address,
      length,
      "process_vm_* unavailable (ENOSYS) [\{context}]",
    )
  } else if errno == ERRNO_INTR {
    access_plan_error(
      kind,
      address,
      length,
      "interrupted (EINTR; shim should retry) [\{context}]",
    )
  } else {
    access_plan_error(
      kind,
      address,
      length,
      "syscall failed (errno \{errno}) [\{context}]",
    )
  }
}

///|
/// 内部：attach 的 errno 分类。
fn classify_attach_errno(
  errno : Int32,
  pid : Pid,
  context : String,
) -> PtraceError {
  if errno == ERRNO_SRCH || errno == ERRNO_NOENT || errno == ERRNO_CHLD {
    PtraceError::ProcessNotFound(pid)
  } else if errno == ERRNO_PERM || errno == ERRNO_ACCES {
    PtraceError::AttachDenied(
      pid,
      "permission denied (EPERM/EACCES; check kernel.yama.ptrace_scope and SELinux) [\{context}]",
    )
  } else if errno == ERRNO_BUSY {
    PtraceError::AlreadyAttached(pid)
  } else if errno == ERRNO_NOSYS {
    PtraceError::UnsupportedKernel("ptrace unavailable (ENOSYS) [\{context}]")
  } else {
    PtraceError::AttachDenied(
      pid,
      "attach failed (errno \{errno}) [\{context}]",
    )
  }
}

///|
/// 内部：detach 的 errno 分类。
fn classify_detach_errno(
  errno : Int32,
  pid : Pid,
  context : String,
) -> PtraceError {
  if errno == ERRNO_SRCH || errno == ERRNO_NOENT || errno == ERRNO_CHLD {
    PtraceError::ProcessNotFound(pid)
  } else {
    PtraceError::DetachFailed(
      pid,
      "detach failed (errno \{errno}) [\{context}]",
    )
  }
}

///|
/// 内部：单步的 errno 分类。
fn classify_step_errno(
  errno : Int32,
  pid : Pid,
  context : String,
) -> PtraceError {
  if errno == ERRNO_SRCH || errno == ERRNO_NOENT || errno == ERRNO_CHLD {
    PtraceError::ProcessNotFound(pid)
  } else if errno == ERRNO_NOSYS {
    PtraceError::UnsupportedKernel(
      "ptrace singlestep unavailable (ENOSYS) [\{context}]",
    )
  } else {
    PtraceError::StepFailed(pid, "step failed (errno \{errno}) [\{context}]")
  }
}

///|
/// 内部：`/proc` 文本读取的 errno 分类。
fn classify_proc_errno(
  errno : Int32,
  pid : Pid,
  context : String,
) -> PtraceError {
  if errno == ERRNO_SRCH || errno == ERRNO_NOENT {
    PtraceError::ProcessNotFound(pid)
  } else if errno == ERRNO_PERM || errno == ERRNO_ACCES {
    PtraceError::AttachDenied(
      pid,
      "read /proc permission denied (EPERM/EACCES; SELinux?) [\{context}]",
    )
  } else if errno == ERRNO_IO || errno == ERRNO_NOSYS {
    PtraceError::UnsupportedKernel(
      "read /proc unavailable (errno \{errno}) [\{context}]",
    )
  } else {
    PtraceError::AttachDenied(
      pid,
      "read /proc failed (errno \{errno}) [\{context}]",
    )
  }
}

///|
/// 内部：线程枚举的 errno 分类。
fn classify_thread_errno(
  errno : Int32,
  pid : Pid,
  context : String,
) -> PtraceError {
  if errno == ERRNO_SRCH || errno == ERRNO_NOENT {
    PtraceError::ProcessNotFound(pid)
  } else if errno == ERRNO_PERM || errno == ERRNO_ACCES {
    PtraceError::ThreadEnumerateFailed(
      pid,
      "thread enumerate permission denied (EPERM/EACCES; SELinux?) [\{context}]",
    )
  } else if errno == ERRNO_IO || errno == ERRNO_NOSYS {
    PtraceError::UnsupportedKernel(
      "thread enumerate unavailable (errno \{errno}) [\{context}]",
    )
  } else {
    PtraceError::ThreadEnumerateFailed(
      pid,
      "thread enumerate failed (errno \{errno}) [\{context}]",
    )
  }
}

///|
/// 内部：统一 errno → `PtraceError` 分类入口。
fn classify_errno(
  op : SyscallOp,
  errno : Int32,
  pid : Pid,
  context : String,
) -> PtraceError {
  match op {
    SyscallOp::ReadMem(address, length) =>
      classify_mem_errno(AccessKind::Read, address, length, errno, pid, context)
    SyscallOp::WriteMem(address, length) =>
      classify_mem_errno(
        AccessKind::Write,
        address,
        length,
        errno,
        pid,
        context,
      )
    SyscallOp::Attach => classify_attach_errno(errno, pid, context)
    SyscallOp::Detach => classify_detach_errno(errno, pid, context)
    SyscallOp::Step => classify_step_errno(errno, pid, context)
    SyscallOp::ProcText => classify_proc_errno(errno, pid, context)
    SyscallOp::ThreadEnum => classify_thread_errno(errno, pid, context)
  }
}

///|
/// 内部：读失败状态 → `PtraceError`。优先走真实 errno 通道，其次兼容
/// stub 合成码（`-8` = 句柄失效 → `NotAttached`，其余 → `ReadFailed`）。
fn read_error_from_status(
  pid : Pid,
  address : Address,
  length : Int32,
  status : Int32,
  context : String,
) -> PtraceError {
  match errno_from_status(status) {
    Some(errno) =>
      classify_errno(SyscallOp::ReadMem(address, length), errno, pid, context)
    None =>
      if status == -8 {
        PtraceError::NotAttached(pid)
      } else {
        PtraceError::ReadFailed(
          address,
          length,
          "\{context} (status \{status})",
        )
      }
  }
}

///|
/// 内部：写失败状态 → `PtraceError`（口径同 `read_error_from_status`）。
fn write_error_from_status(
  pid : Pid,
  address : Address,
  length : Int32,
  status : Int32,
  context : String,
) -> PtraceError {
  match errno_from_status(status) {
    Some(errno) =>
      classify_errno(SyscallOp::WriteMem(address, length), errno, pid, context)
    None =>
      if status == -8 {
        PtraceError::NotAttached(pid)
      } else {
        PtraceError::WriteFailed(
          address,
          length,
          "\{context} (status \{status})",
        )
      }
  }
}

///|
/// 内部：attach 失败状态 → `PtraceError`（句柄有效性探测使用）。
fn attach_error_from_status(
  pid : Pid,
  status : Int32,
  context : String,
) -> PtraceError {
  match errno_from_status(status) {
    Some(errno) => classify_errno(SyscallOp::Attach, errno, pid, context)
    None =>
      if status == -6 {
        PtraceError::AlreadyAttached(pid)
      } else {
        PtraceError::AttachDenied(pid, "\{context} (status \{status})")
      }
  }
}

///|
/// 内部：单步失败状态 → `PtraceError`。
fn step_error_from_status(
  pid : Pid,
  status : Int32,
  context : String,
) -> PtraceError {
  match errno_from_status(status) {
    Some(errno) => classify_errno(SyscallOp::Step, errno, pid, context)
    None =>
      if status == -8 {
        PtraceError::NotAttached(pid)
      } else {
        PtraceError::StepFailed(pid, "\{context} (status \{status})")
      }
  }
}

///|
/// 内部：detach 失败状态 → `PtraceError`。
fn detach_error_from_status(
  pid : Pid,
  status : Int32,
  context : String,
) -> PtraceError {
  match errno_from_status(status) {
    Some(errno) => classify_errno(SyscallOp::Detach, errno, pid, context)
    None => PtraceError::DetachFailed(pid, "\{context} (status \{status})")
  }
}
