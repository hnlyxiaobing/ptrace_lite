// 白盒测试：跨页分段计划（纯逻辑，无需真实 libc / 设备）。
// 覆盖正常分段、边界、零长度、负长度、非法页大小、地址溢出与 fail-closed 上限。

///|
/// 内部：断言分段计划完整覆盖请求、首尾相接、每段不跨页。
fn assert_plan_covers(
  plan : AccessPlan,
  address : Address,
  length : Int32,
  page_size : Int32,
) -> Unit raise {
  let segs = plan.segments
  let page_u = page_size.to_uint64()
  let mut expect_addr = address
  let mut expect_offset = 0
  for i in 0..<segs.length() {
    let seg = segs[i]
    assert_eq(seg.address, expect_addr)
    assert_eq(seg.offset, expect_offset)
    assert_true(seg.length > 0)
    assert_true(seg.address % page_u + seg.length.to_uint64() <= page_u)
    expect_addr = expect_addr + seg.length.to_uint64()
    expect_offset = expect_offset + seg.length
  }
  assert_eq(expect_offset, length)
  assert_eq(expect_addr, address + length.to_uint64())
}

///|
/// 分段计划：请求完全落在一页内 → 单段。
test "internal: access plan single page" {
  let plan = plan_access(AccessKind::Read, 0x1000UL, 0x100, 4096)
  assert_eq(plan.segments.length(), 1)
  assert_eq(plan.segments[0].address, 0x1000UL)
  assert_eq(plan.segments[0].length, 0x100)
  assert_eq(plan.segments[0].offset, 0)
  assert_plan_covers(plan, 0x1000UL, 0x100, 4096)
}

///|
/// 分段计划：跨一个页边界 → 两段，偏移与地址首尾相接。
test "internal: access plan crosses page boundary" {
  let plan = plan_access(AccessKind::Read, 0xFF8UL, 0x18, 0x1000)
  assert_eq(plan.segments.length(), 2)
  assert_eq(plan.segments[0].address, 0xFF8UL)
  assert_eq(plan.segments[0].length, 8)
  assert_eq(plan.segments[0].offset, 0)
  assert_eq(plan.segments[1].address, 0x1000UL)
  assert_eq(plan.segments[1].length, 0x10)
  assert_eq(plan.segments[1].offset, 8)
  assert_plan_covers(plan, 0xFF8UL, 0x18, 0x1000)
}

///|
/// 分段计划：恰好在页边界结束 → 仍是单段（不产生空段）。
test "internal: access plan exact page end" {
  let plan = plan_access(AccessKind::Read, 0x2000UL, 0x1000, 0x1000)
  assert_eq(plan.segments.length(), 1)
  assert_eq(plan.segments[0].length, 0x1000)
  assert_plan_covers(plan, 0x2000UL, 0x1000, 0x1000)
}

///|
/// 分段计划：跨多页（未对齐起点）→ 段数、覆盖与不跨页性质。
test "internal: access plan multi page coverage" {
  let plan = plan_access(AccessKind::Write, 0xFFFUL, 0x2001, 0x1000)
  assert_eq(plan.segments.length(), 3)
  assert_eq(plan.segments[0].length, 1)
  assert_eq(plan.segments[1].length, 0x1000)
  assert_eq(plan.segments[2].length, 0x1000)
  assert_plan_covers(plan, 0xFFFUL, 0x2001, 0x1000)
}

///|
/// 分段计划：零长度 → 空计划（合法无操作，不报错）。
test "internal: access plan zero length" {
  let plan = plan_access(AccessKind::Read, 0x10000UL, 0, 4096)
  assert_eq(plan.segments.length(), 0)
}

///|
/// 分段计划：负长度按方向映射 `ReadFailed` / `WriteFailed`（不 panic）。
test "internal: access plan negative length" {
  let e1 = expect_ptrace_error(() => {
    ignore(plan_access(AccessKind::Read, 0x1000UL, -1, 4096))
  })
  assert_true(e1 is PtraceError::ReadFailed(0x1000UL, -1, _))
  let e2 = expect_ptrace_error(() => {
    ignore(plan_access(AccessKind::Write, 0x1000UL, -1, 4096))
  })
  assert_true(e2 is PtraceError::WriteFailed(0x1000UL, -1, _))
}

///|
/// 分段计划：非法页大小（0 / 负数）显式报错。
test "internal: access plan invalid page size" {
  let e1 = expect_ptrace_error(() => {
    ignore(plan_access(AccessKind::Read, 0x1000UL, 4, 0))
  })
  assert_true(e1 is PtraceError::ReadFailed(0x1000UL, 4, _))
  let e2 = expect_ptrace_error(() => {
    ignore(plan_access(AccessKind::Write, 0x1000UL, 4, -4096))
  })
  assert_true(e2 is PtraceError::WriteFailed(0x1000UL, 4, _))
}

///|
/// 分段计划：`address + length` 溢出 `UInt64` → 地址溢出错误。
test "internal: access plan address overflow" {
  let e = expect_ptrace_error(() => {
    ignore(plan_access(AccessKind::Read, 0xFFFFFFFFFFFFFFFFUL, 8, 4096))
  })
  assert_true(e is PtraceError::ReadFailed(0xFFFFFFFFFFFFFFFFUL, 8, _))
}

///|
/// 分段计划：超过单请求分段上限 → fail-closed（不静默截断）。
test "internal: access plan segment cap fail-closed" {
  let too_big = MAX_ACCESS_SEGMENTS * 4096 + 1
  let e = expect_ptrace_error(() => {
    ignore(plan_access(AccessKind::Read, 0x1000UL, too_big, 4096))
  })
  assert_true(e is PtraceError::ReadFailed(0x1000UL, _, _))
}
