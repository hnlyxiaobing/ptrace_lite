// Whitebox tests run within the package scope.
// 覆盖内部 shim 协议解析（/proc 文本包拆分）与数字解析辅助函数。

///|
/// 内部：断言回调抛出 `PtraceError` 并返回错误值。
fn expect_ptrace_error(f : () -> Unit raise PtraceError) -> PtraceError raise {
  try f() catch {
    e => e
  } noraise {
    _ => fail("expected PtraceError, but no error is raised")
  }
}

///|
/// 内部：十六进制 / 十进制解析辅助（含溢出与非法字符拒绝）。
test "internal: hex and dec parsers" {
  assert_eq(try_parse_hex_u64("0".to_array(), 0, 1), Some(0UL))
  assert_eq(try_parse_hex_u64("ff".to_array(), 0, 2), Some(255UL))
  assert_eq(
    try_parse_hex_u64("FFFFFFFFFFFFFFFF".to_array(), 0, 16),
    Some(0xFFFFFFFFFFFFFFFFUL),
  )
  // 溢出拒绝
  assert_eq(try_parse_hex_u64("10000000000000000".to_array(), 0, 17), None)
  // 非法字符 / 空段拒绝
  assert_eq(try_parse_hex_u64("g".to_array(), 0, 1), None)
  assert_eq(try_parse_hex_u64("12".to_array(), 0, 0), None)
  assert_eq(try_parse_dec_int("0".to_array(), 0, 1), Some(0))
  assert_eq(try_parse_dec_int("2147483647".to_array(), 0, 10), Some(2147483647))
  // 32 位溢出拒绝
  assert_eq(try_parse_dec_int("2147483648".to_array(), 0, 10), None)
  assert_eq(try_parse_dec_int("12a".to_array(), 0, 3), None)
  assert_eq(try_parse_dec_int("42".to_array(), 0, 0), None)
}

///|
/// 内部：/proc 文本包拆分（maps 全文 + task 段）。
test "internal: split_proc_bundle" {
  let text = "line1\nline2\n__tasks__\n1\ta\tS\n2\tb\tD\n"
  let (maps, tasks) = split_proc_bundle(4242, text)
  assert_eq(maps, "line1\nline2\n")
  assert_eq(tasks, "1\ta\tS\n2\tb\tD\n")
}

///|
/// 内部：文本包缺 task 段时报 ThreadEnumerateFailed。
test "internal: split_proc_bundle missing section" {
  let e = expect_ptrace_error(() => {
    ignore(split_proc_bundle(4242, "only maps\n"))
  })
  assert_true(e is PtraceError::ThreadEnumerateFailed(4242, _))
}

///|
/// 内部：C 状态码 → PtraceError 映射（含 SelinuxDenied / UnsupportedKernel）。
test "internal: map_proc_status" {
  assert_true(map_proc_status(7, -2, "ctx") is PtraceError::ProcessNotFound(7))
  assert_true(map_proc_status(7, -3, "ctx") is PtraceError::AttachDenied(7, _))
  assert_true(map_proc_status(7, -4, "ctx") is PtraceError::SelinuxDenied(_))
  assert_true(
    map_proc_status(7, -5, "ctx") is PtraceError::UnsupportedKernel(_),
  )
  assert_true(map_proc_status(7, -6, "ctx") is PtraceError::AlreadyAttached(7))
  assert_true(map_proc_status(7, -1, "ctx") is PtraceError::AttachDenied(7, _))
  assert_true(map_thread_status(7, -2) is PtraceError::ProcessNotFound(7))
  assert_true(map_thread_status(7, -4) is PtraceError::SelinuxDenied(_))
  assert_true(map_thread_status(7, -5) is PtraceError::UnsupportedKernel(_))
  assert_true(
    map_thread_status(7, -3) is PtraceError::ThreadEnumerateFailed(7, _),
  )
}

///|
/// 内部：task 段解析（tid/name/state）与畸形行拒绝。
test "internal: parse_task_section" {
  let threads = parse_task_section(
    4242, "4242\tsim-tracee\tS\n4250\tsim-worker\tS\n",
  )
  assert_eq(threads.length(), 2)
  assert_eq(threads[0].tid, 4242)
  assert_eq(threads[0].name, "sim-tracee")
  assert_eq(threads[0].state, "S")
  let e = expect_ptrace_error(() => {
    ignore(parse_task_section(4242, "not-a-task-line\n"))
  })
  assert_true(e is PtraceError::ThreadEnumerateFailed(4242, _))
}

///|
/// 内部：shim 容量校验（原黑盒 "capacity checks"，随 `mb_ptrace_*` 私有化
/// 转白盒；冻结前 P0 决策 6）。shim 侧对 capacity / length 超限返回 -7；
/// read_maps 为 snprintf 语义（截断写入 + 返回所需长度）。
test "internal: shim capacity checks" {
  let small : FixedArray[Byte] = FixedArray::make(4, b'\x00')
  // capacity 超出 dst 容量 → -7
  assert_eq(mb_ptrace_read_maps(4242, small, 100), -7)
  // 截断写入 + 返回所需长度
  let need = mb_ptrace_read_maps(4242, small, 4)
  assert_true(need > 4)
  let t = Target::attach(4242)
  let dst : FixedArray[Byte] = FixedArray::make(4, b'\x00')
  // length 超出 dst 容量 → -7
  assert_eq(mb_ptrace_read_mem(t.handle, 0x10000UL, dst, 10), -7)
  // length 超出 src 容量 → -7
  assert_eq(mb_ptrace_write_mem(t.handle, 0x10000UL, b"XY", 10), -7)
  // 零长度读合法
  assert_eq(mb_ptrace_read_mem(t.handle, 0x10000UL, dst, 0), 0)
  t.detach()
}

///|
/// 内部：空句柄 / 失效句柄被 shim 拒绝（-8）（原黑盒 "stale handle rejected"
/// 随 `mb_ptrace_*` 私有化转白盒；冻结前 P0 决策 6）。
test "internal: stale handle rejected" {
  let t = Target::attach(4242)
  let h = t.handle
  t.detach()
  assert_eq(mb_ptrace_step(h), -8)
  assert_eq(mb_ptrace_detach(h), -8)
  assert_eq(mb_ptrace_task_count(4242), 2)
}
