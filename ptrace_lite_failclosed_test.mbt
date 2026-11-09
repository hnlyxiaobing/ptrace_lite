// 黑盒测试：无真实 libc（桌面 stub）时的 fail-closed 语义。
// 目标：错误输入/越界访问必须以明确 `PtraceError` 收口，绝不静默成功或截断；
// 零长度访问是唯一合法的「无操作」。真实 libc 路径留待非 Windows 设备轮
// **[仍需实测]**（E5）。

///|
/// detach 后 maps / threads 与读写一样必须拒绝（状态守卫一致性）。
test "fail-closed: maps and threads rejected after detach" {
  let t = @ptrace_lite.Target::attach(4242)
  t.detach()
  let e1 = expect_ptrace_error(() => ignore(t.maps()))
  assert_true(e1 is @ptrace_lite.PtraceError::NotAttached(4242))
  let e2 = expect_ptrace_error(() => ignore(t.threads()))
  assert_true(e2 is @ptrace_lite.PtraceError::NotAttached(4242))
}

///|
/// 跨模拟区间边界的读：分段计划把失败定位到第二段，整体请求失败（不截断）。
test "fail-closed: read across region boundary fails whole request" {
  let t = @ptrace_lite.Target::attach(4242)
  // 0x10FF8..0x11000 合法（heap 末 8 字节），0x11000..0x11008 无映射。
  let e = expect_ptrace_error(() => ignore(t.read_bytes(0x10FF8UL, 0x10)))
  // 请求同时跨页边界 0x11000；失败被定位到第二段（0x11000, 0x10）。
  let e2 = expect_ptrace_error(() => ignore(t.read_bytes(0x10FF0UL, 0x20)))
  t.detach()
  assert_true(e is @ptrace_lite.PtraceError::ReadFailed(0x11000UL, 8, _))
  assert_true(e2 is @ptrace_lite.PtraceError::ReadFailed(0x11000UL, 0x10, _))
}

///|
/// 非可写区间（r--s 共享页 / r-x 代码页）写入必须失败，不能伪造成功。
test "fail-closed: write to non-writable regions rejected" {
  let t = @ptrace_lite.Target::attach(4242)
  let e1 = expect_ptrace_error(() => t.write_bytes(0x30000UL, b"X"))
  let e2 = expect_ptrace_error(() => t.write_bytes(0x20000UL, b"XY"))
  t.detach()
  assert_true(e1 is @ptrace_lite.PtraceError::WriteFailed(0x30000UL, 1, _))
  assert_true(e2 is @ptrace_lite.PtraceError::WriteFailed(0x20000UL, 2, _))
}

///|
/// 零长度访问是合法无操作：不因非法地址报错，也不触碰目标内存。
test "fail-closed: zero length access is a legal no-op" {
  let t = @ptrace_lite.Target::attach(4242)
  let empty = t.read_bytes(0xDEADBEEFUL, 0)
  t.write_bytes(0xDEADBEEFUL, b"")
  // 非零长度在同一非法地址仍然失败
  let e = expect_ptrace_error(() => ignore(t.read_bytes(0xDEADBEEFUL, 1)))
  t.detach()
  assert_eq(empty.length(), 0)
  assert_true(e is @ptrace_lite.PtraceError::ReadFailed(0xDEADBEEFUL, 1, _))
}

///|
/// attach 失败不持有资源：随后仍可正常 attach / detach 其他目标（句柄槽未泄漏）。
test "fail-closed: failed attach leaves no handle behind" {
  let e = expect_ptrace_error(() => ignore(@ptrace_lite.Target::attach(999999)))
  let t = @ptrace_lite.Target::attach(4242)
  let attached = t.state()
  t.detach()
  assert_true(e is @ptrace_lite.PtraceError::ProcessNotFound(999999))
  assert_true(attached is @ptrace_lite.TargetState::Attached)
  assert_true(t.state() is @ptrace_lite.TargetState::Detached)
}
