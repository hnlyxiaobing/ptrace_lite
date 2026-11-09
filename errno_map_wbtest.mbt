// 白盒测试：真实转发层 errno 分类映射（纯逻辑，无需真实 libc / 设备）。
// 覆盖 errno 通道边界、ESRCH/EPERM/EACCES/EFAULT/EIO/EINVAL/ENOSYS/EINTR/
// EBUSY/ECHILD/未知 errno，以及状态包装函数对 stub 合成码的兼容。

///|
/// 内部：errno 通道编码/解码边界（`status = -1000 - errno`）。
test "internal: errno channel boundaries" {
  assert_eq(errno_from_status(-1001), Some(1))
  assert_eq(errno_from_status(-1003), Some(3))
  assert_eq(errno_from_status(-1005), Some(5))
  assert_eq(errno_from_status(-1014), Some(14))
  assert_eq(errno_from_status(-5095), Some(4095))
  // 非真实通道：stub 合成码 / 越界 / 成功
  assert_eq(errno_from_status(-1000), None)
  assert_eq(errno_from_status(-999), None)
  assert_eq(errno_from_status(-5096), None)
  assert_eq(errno_from_status(-8), None)
  assert_eq(errno_from_status(0), None)
  assert_eq(errno_from_status(16), None)
}

///|
/// 内部：读 errno → `PtraceError`（ESRCH / EPERM / EACCES / EFAULT / EIO /
/// EINVAL / ENOSYS / EINTR / 未知）。
test "internal: classify read errno" {
  let op = SyscallOp::ReadMem(0x1000UL, 4)
  assert_true(
    classify_errno(op, ERRNO_SRCH, 42, "read")
    is PtraceError::ProcessNotFound(42),
  )
  assert_true(
    classify_errno(op, ERRNO_NOENT, 42, "read")
    is PtraceError::ProcessNotFound(42),
  )
  assert_true(
    classify_errno(op, ERRNO_PERM, 42, "read")
    is PtraceError::ReadFailed(0x1000UL, 4, _),
  )
  assert_true(
    classify_errno(op, ERRNO_ACCES, 42, "read")
    is PtraceError::ReadFailed(0x1000UL, 4, _),
  )
  assert_true(
    classify_errno(op, ERRNO_FAULT, 42, "read")
    is PtraceError::ReadFailed(0x1000UL, 4, _),
  )
  assert_true(
    classify_errno(op, ERRNO_IO, 42, "read")
    is PtraceError::ReadFailed(0x1000UL, 4, _),
  )
  assert_true(
    classify_errno(op, ERRNO_INVAL, 42, "read")
    is PtraceError::ReadFailed(0x1000UL, 4, _),
  )
  assert_true(
    classify_errno(op, ERRNO_NOSYS, 42, "read")
    is PtraceError::ReadFailed(0x1000UL, 4, _),
  )
  assert_true(
    classify_errno(op, ERRNO_INTR, 42, "read")
    is PtraceError::ReadFailed(0x1000UL, 4, _),
  )
  assert_true(
    classify_errno(op, 999, 42, "read")
    is PtraceError::ReadFailed(0x1000UL, 4, _),
  )
}

///|
/// 内部：写 errno → `WriteFailed`（方向不串味）。
test "internal: classify write errno" {
  let op = SyscallOp::WriteMem(0x2000UL, 8)
  assert_true(
    classify_errno(op, ERRNO_SRCH, 42, "write")
    is PtraceError::ProcessNotFound(42),
  )
  assert_true(
    classify_errno(op, ERRNO_PERM, 42, "write")
    is PtraceError::WriteFailed(0x2000UL, 8, _),
  )
  assert_true(
    classify_errno(op, ERRNO_FAULT, 42, "write")
    is PtraceError::WriteFailed(0x2000UL, 8, _),
  )
  assert_true(
    classify_errno(op, ERRNO_IO, 42, "write")
    is PtraceError::WriteFailed(0x2000UL, 8, _),
  )
  assert_true(
    classify_errno(op, ERRNO_NOSYS, 42, "write")
    is PtraceError::WriteFailed(0x2000UL, 8, _),
  )
}

///|
/// 内部：attach errno → `PtraceError`（ESRCH / EPERM / EBUSY / ECHILD / ENOSYS）。
test "internal: classify attach errno" {
  assert_true(
    classify_errno(SyscallOp::Attach, ERRNO_SRCH, 42, "attach")
    is PtraceError::ProcessNotFound(42),
  )
  assert_true(
    classify_errno(SyscallOp::Attach, ERRNO_PERM, 42, "attach")
    is PtraceError::AttachDenied(42, _),
  )
  assert_true(
    classify_errno(SyscallOp::Attach, ERRNO_ACCES, 42, "attach")
    is PtraceError::AttachDenied(42, _),
  )
  assert_true(
    classify_errno(SyscallOp::Attach, ERRNO_BUSY, 42, "attach")
    is PtraceError::AlreadyAttached(42),
  )
  assert_true(
    classify_errno(SyscallOp::Attach, ERRNO_CHLD, 42, "attach")
    is PtraceError::ProcessNotFound(42),
  )
  assert_true(
    classify_errno(SyscallOp::Attach, ERRNO_NOSYS, 42, "attach")
    is PtraceError::UnsupportedKernel(_),
  )
  assert_true(
    classify_errno(SyscallOp::Attach, 999, 42, "attach")
    is PtraceError::AttachDenied(42, _),
  )
}

///|
/// 内部：detach / step errno → 对应错误构造。
test "internal: classify detach and step errno" {
  assert_true(
    classify_errno(SyscallOp::Detach, ERRNO_SRCH, 42, "detach")
    is PtraceError::ProcessNotFound(42),
  )
  assert_true(
    classify_errno(SyscallOp::Detach, ERRNO_IO, 42, "detach")
    is PtraceError::DetachFailed(42, _),
  )
  assert_true(
    classify_errno(SyscallOp::Step, ERRNO_SRCH, 42, "step")
    is PtraceError::ProcessNotFound(42),
  )
  assert_true(
    classify_errno(SyscallOp::Step, ERRNO_NOSYS, 42, "step")
    is PtraceError::UnsupportedKernel(_),
  )
  assert_true(
    classify_errno(SyscallOp::Step, ERRNO_PERM, 42, "step")
    is PtraceError::StepFailed(42, _),
  )
}

///|
/// 内部：`/proc` 文本与线程枚举 errno → 对应错误构造。
test "internal: classify proc and thread errno" {
  assert_true(
    classify_errno(SyscallOp::ProcText, ERRNO_NOENT, 42, "proc")
    is PtraceError::ProcessNotFound(42),
  )
  assert_true(
    classify_errno(SyscallOp::ProcText, ERRNO_ACCES, 42, "proc")
    is PtraceError::AttachDenied(42, _),
  )
  assert_true(
    classify_errno(SyscallOp::ProcText, ERRNO_IO, 42, "proc")
    is PtraceError::UnsupportedKernel(_),
  )
  assert_true(
    classify_errno(SyscallOp::ProcText, ERRNO_INVAL, 42, "proc")
    is PtraceError::AttachDenied(42, _),
  )
  assert_true(
    classify_errno(SyscallOp::ThreadEnum, ERRNO_NOENT, 42, "thread")
    is PtraceError::ProcessNotFound(42),
  )
  assert_true(
    classify_errno(SyscallOp::ThreadEnum, ERRNO_ACCES, 42, "thread")
    is PtraceError::ThreadEnumerateFailed(42, _),
  )
  assert_true(
    classify_errno(SyscallOp::ThreadEnum, ERRNO_IO, 42, "thread")
    is PtraceError::UnsupportedKernel(_),
  )
  assert_true(
    classify_errno(SyscallOp::ThreadEnum, ERRNO_INVAL, 42, "thread")
    is PtraceError::ThreadEnumerateFailed(42, _),
  )
}

///|
/// 内部：状态包装函数优先解释真实 errno 通道，并保留 stub 合成码语义。
test "internal: status wrappers prefer errno channel" {
  // 真实通道：ESRCH → ProcessNotFound
  assert_true(
    read_error_from_status(42, 0x1000UL, 4, -1003, "read")
    is PtraceError::ProcessNotFound(42),
  )
  // stub 合成码：-8 → NotAttached，-7 → 方向错误
  assert_true(
    read_error_from_status(42, 0x1000UL, 4, -8, "read")
    is PtraceError::NotAttached(42),
  )
  assert_true(
    read_error_from_status(42, 0x1000UL, 4, -7, "read")
    is PtraceError::ReadFailed(0x1000UL, 4, _),
  )
  assert_true(
    write_error_from_status(42, 0x1000UL, 4, -1014, "write")
    is PtraceError::WriteFailed(0x1000UL, 4, _),
  )
  assert_true(
    write_error_from_status(42, 0x1000UL, 4, -8, "write")
    is PtraceError::NotAttached(42),
  )
  assert_true(
    step_error_from_status(42, -8, "step") is PtraceError::NotAttached(42),
  )
  assert_true(
    step_error_from_status(42, -1001, "step") is PtraceError::StepFailed(42, _),
  )
  assert_true(
    detach_error_from_status(42, -1003, "detach")
    is PtraceError::ProcessNotFound(42),
  )
  assert_true(
    attach_error_from_status(42, -1001, "attach")
    is PtraceError::AttachDenied(42, _),
  )
  assert_true(
    attach_error_from_status(42, -6, "attach")
    is PtraceError::AlreadyAttached(42),
  )
  assert_true(
    attach_error_from_status(42, -8, "attach")
    is PtraceError::AttachDenied(42, _),
  )
}
