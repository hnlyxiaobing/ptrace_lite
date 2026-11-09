// Blackbox tests run against the package's public API. Use `@ptrace_lite` to import.
// 桌面 stub 注：走 stub/ptrace_stub.c 的模拟 tracee（pid 4242 正常、7001 SELinux、
// 7002 内核不支持、7003 权限拒绝、其余不存在）；真实 libc 转发留待 Linux / 设备阶段。
//
// API 冻结前收紧（见 DECISIONS.md）：`Target.state` 为私有字段，黑盒经只读访问器
// `Target::state()` 读取；7 个 `mb_ptrace_*` shim 已移出公开 API，
// 直接调用 shim 的用例（capacity -7、stale handle -8）转白盒
// `ptrace_lite_wbtest.mbt`，黑盒保留等价的 MoonBit 层语义断言。

///|
/// 内部：断言回调抛出 `PtraceError` 并返回错误值。
fn expect_ptrace_error(
  f : () -> Unit raise @ptrace_lite.PtraceError,
) -> @ptrace_lite.PtraceError raise {
  try f() catch {
    e => e
  } noraise {
    _ => fail("expected PtraceError, but no error is raised")
  }
}

///|
/// 全链路（走 stub）：attach → maps → read → write → step → threads → detach。
test "full chain: attach->maps->read->write->step->threads->detach" {
  let t = @ptrace_lite.Target::attach(4242)
  assert_true(t.state() is @ptrace_lite.TargetState::Attached)
  // maps：4 个模拟区间，升序
  let regions = t.maps()
  assert_eq(regions.length(), 4)
  assert_eq(regions[0].start, 0x10000UL)
  assert_eq(regions[0].end, 0x11000UL)
  assert_true(
    regions[0].protection.read &&
    regions[0].protection.write &&
    !regions[0].protection.execute &&
    regions[0].protection.private,
  )
  assert_true(regions[0].path is Some("[heap]"))
  assert_eq(regions[1].offset, 0x1000UL)
  assert_eq(regions[1].device, "08:01")
  assert_eq(regions[1].inode, 8888)
  assert_true(regions[1].protection.execute && !regions[1].protection.write)
  // r--s：shared（private = false）
  assert_true(!regions[2].protection.private && regions[2].protection.read)
  assert_true(regions[3].path is Some("[stack]"))
  // read：堆区模拟内容为 'A' + i % 26
  let data = t.read_bytes(0x10000UL, 4)
  assert_eq(data, b"ABCD")
  let data2 = t.read_bytes(0x1001AUL, 4)
  assert_eq(data2, b"ABCD")
  // code 区：byte i = i & 0xff
  let code = t.read_bytes(0x20000UL, 3)
  assert_eq(code, b"\x00\x01\x02")
  // write + 读回
  t.write_bytes(0x10010UL, b"XY")
  let back = t.read_bytes(0x10010UL, 2)
  assert_eq(back, b"XY")
  // step：state 进入 Stepping（API.md 语义：仅未 attach 拒绝读写）
  t.step()
  assert_true(t.state() is @ptrace_lite.TargetState::Stepping)
  let after_step = t.read_bytes(0x10000UL, 1)
  assert_eq(after_step, b"A")
  // threads：与 mb_ptrace_task_count 交叉校验
  let threads = t.threads()
  assert_eq(threads.length(), 2)
  assert_eq(threads[0].tid, 4242)
  assert_eq(threads[0].name, "sim-tracee")
  assert_eq(threads[0].state, "S")
  assert_eq(threads[1].tid, 4250)
  assert_eq(threads[1].name, "sim-worker")
  // detach：唯一释放
  t.detach()
  assert_true(t.state() is @ptrace_lite.TargetState::Detached)
}

///|
/// 未 attach（detach 后）读写必须拒绝。
test "read/write rejected when not attached" {
  let t = @ptrace_lite.Target::attach(4242)
  t.detach()
  let e1 = expect_ptrace_error(() => ignore(t.read_bytes(0x10000UL, 4)))
  assert_true(e1 is @ptrace_lite.PtraceError::NotAttached(4242))
  let e2 = expect_ptrace_error(() => t.write_bytes(0x10000UL, b"X"))
  assert_true(e2 is @ptrace_lite.PtraceError::NotAttached(4242))
  // detach 后单步同样拒绝（原 raw shim 断言 -8 已随 shim 私有化转白盒）
  let e3 = expect_ptrace_error(() => t.step())
  assert_true(e3 is @ptrace_lite.PtraceError::NotAttached(4242))
}

///|
/// 重复 detach 报 `NotAttached`，不会二次释放。
test "detach twice raises NotAttached" {
  let t = @ptrace_lite.Target::attach(4242)
  t.detach()
  let e = expect_ptrace_error(() => t.detach())
  assert_true(e is @ptrace_lite.PtraceError::NotAttached(4242))
}

///|
/// attach 失败路径（stub 参数触发）与 C status → PtraceError 错误映射。
test "attach error mapping" {
  let e1 = expect_ptrace_error(() => ignore(@ptrace_lite.Target::attach(999999)))
  assert_true(e1 is @ptrace_lite.PtraceError::ProcessNotFound(999999))
  let e2 = expect_ptrace_error(() => ignore(@ptrace_lite.Target::attach(7001)))
  assert_true(e2 is @ptrace_lite.PtraceError::SelinuxDenied(_))
  let e3 = expect_ptrace_error(() => ignore(@ptrace_lite.Target::attach(7002)))
  assert_true(e3 is @ptrace_lite.PtraceError::UnsupportedKernel(_))
  let e4 = expect_ptrace_error(() => ignore(@ptrace_lite.Target::attach(7003)))
  assert_true(e4 is @ptrace_lite.PtraceError::AttachDenied(7003, _))
}

///|
/// 重复 attach 同一 pid 报 `AlreadyAttached`。
test "attach twice raises AlreadyAttached" {
  let t = @ptrace_lite.Target::attach(4242)
  let e = expect_ptrace_error(() => ignore(@ptrace_lite.Target::attach(4242)))
  assert_true(e is @ptrace_lite.PtraceError::AlreadyAttached(4242))
  t.detach()
}

///|
/// 缓冲容量校验（shim ABI 语义，API 冻结前随 shim 私有化转白盒：
/// 见 `ptrace_lite_wbtest.mbt` 的 "internal: shim capacity checks"）。
///
/// 黑盒等价语义：MoonBit 层按请求长度自建缓冲，容量由 API 保证，
/// 非法长度/地址仍以 `PtraceError` 可判（见 "illegal address and length"）。

///|
/// 非法地址 / 不可写页 / 负长度 / 地址溢出。
test "illegal address and length" {
  let t = @ptrace_lite.Target::attach(4242)
  let e1 = expect_ptrace_error(() => ignore(t.read_bytes(0x500000UL, 4)))
  assert_true(e1 is @ptrace_lite.PtraceError::ReadFailed(0x500000UL, 4, _))
  // r-x 代码页写入（W^X）→ WriteFailed
  let e2 = expect_ptrace_error(() => t.write_bytes(0x20000UL, b"XY"))
  assert_true(e2 is @ptrace_lite.PtraceError::WriteFailed(0x20000UL, 2, _))
  // 负长度
  let e3 = expect_ptrace_error(() => ignore(t.read_bytes(0x10000UL, -1)))
  assert_true(e3 is @ptrace_lite.PtraceError::ReadFailed(0x10000UL, -1, _))
  // 地址 + 长度溢出
  let e4 = expect_ptrace_error(() => {
    ignore(t.read_bytes(0xFFFFFFFFFFFFFFFFUL, 8))
  })
  assert_true(
    e4 is @ptrace_lite.PtraceError::ReadFailed(0xFFFFFFFFFFFFFFFFUL, 8, _),
  )
  t.detach()
}

///|
/// 空句柄 / 失效句柄被 shim 拒绝（-8）：随 shim 私有化转白盒，
/// 见 `ptrace_lite_wbtest.mbt` 的 "internal: stale handle rejected"；
/// 黑盒等价语义由 "read/write rejected when not attached" 覆盖。

///|
/// parse_maps golden：常规 /proc/pid/maps（文件映射、匿名映射、权限位、偏移、
/// device、inode、64 位地址、缺 path）。
test "parse_maps golden: regular" {
  let text = "00400000-00452000 r-xp 00000000 08:02 173521      /usr/bin/dbus-daemon\n" +
    "00652000-00653000 r--p 00052000 08:02 173521      /usr/bin/dbus-daemon\n" +
    "00653000-00656000 rw-p 00053000 08:02 173521      /usr/bin/dbus-daemon\n" +
    "00e66000-00e87000 rw-p 00000000 00:00 0           [heap]\n" +
    "00e87000-00e88000 ---p 00000000 00:00 0\n" +
    "7f5c8e2f1000-7f5c8e312000 rw-p 00000000 00:00 0\n" +
    "7ffd4a5b0000-7ffd4a5d1000 rw-p 00000000 00:00 0   [stack]\n" +
    "7ffd4a5de000-7ffd4a5e0000 r-xp 00000000 00:00 0   [vdso]\n" +
    "ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0   [vsyscall]\n"
  let regions = @ptrace_lite.parse_maps(text)
  assert_eq(regions.length(), 9)
  assert_eq(regions[0].start, 0x400000UL)
  assert_eq(regions[0].end, 0x452000UL)
  assert_true(
    regions[0].protection.read &&
    regions[0].protection.execute &&
    !regions[0].protection.write &&
    regions[0].protection.private,
  )
  assert_eq(regions[0].offset, 0UL)
  assert_eq(regions[0].device, "08:02")
  assert_eq(regions[0].inode, 173521)
  assert_true(regions[0].path is Some("/usr/bin/dbus-daemon"))
  assert_eq(regions[1].offset, 0x52000UL)
  assert_true(
    regions[1].protection.read &&
    !regions[1].protection.write &&
    !regions[1].protection.execute,
  )
  assert_true(regions[2].protection.write)
  assert_true(regions[3].path is Some("[heap]"))
  assert_eq(regions[3].device, "00:00")
  assert_eq(regions[3].inode, 0)
  // 匿名映射：path = None
  assert_true(regions[4].path is None)
  assert_true(regions[4].protection.read == false)
  assert_true(regions[5].path is None)
  assert_true(regions[6].path is Some("[stack]"))
  assert_true(regions[7].path is Some("[vdso]"))
  // 64 位地址（vsyscall 位于内核空间）
  assert_eq(regions[8].start, 0xffffffffff600000UL)
  assert_eq(regions[8].end, 0xffffffffff601000UL)
  assert_true(regions[8].path is Some("[vsyscall]"))
}

///|
/// parse_maps golden：whitespace 变体（制表符、多空格、path 含空格、缺 path + 行尾空白）。
test "parse_maps golden: whitespace variants" {
  let text = "00400000-00452000\t r-xp   00000000\t08:02   173521\t/usr/bin/app\n" +
    "00652000-00653000 rw-p 00052000 08:02 173521 /usr/bin/dir with space/file name\n" +
    "00e86000-00e87000 r--s 00000000 08:02 173521   \n"
  let regions = @ptrace_lite.parse_maps(text)
  assert_eq(regions.length(), 3)
  assert_true(regions[0].path is Some("/usr/bin/app"))
  // path 含空格：整体保留
  assert_true(regions[1].path is Some("/usr/bin/dir with space/file name"))
  // r--s：shared；缺 path + 行尾空白 → None
  assert_true(!regions[2].protection.private)
  assert_true(regions[2].protection.read && !regions[2].protection.write)
  assert_true(regions[2].path is None)
}

///|
/// parse_maps golden：设备映射（Android 风格）与 \r\n 行尾。
test "parse_maps golden: device mappings and CRLF" {
  let text = "7f0000000000-7f0000001000 rw-s 00000000 00:01 1234 /dev/ashmem\r\n" +
    "12c00000-12c21000 rw-p 00000000 10:45 8892 /dev/kgsl-3d0\r\n"
  let regions = @ptrace_lite.parse_maps(text)
  assert_eq(regions.length(), 2)
  // 按 start 升序（输入未排序）
  assert_eq(regions[0].start, 0x12c00000UL)
  assert_eq(regions[0].device, "10:45")
  assert_eq(regions[0].inode, 8892)
  assert_true(regions[0].path is Some("/dev/kgsl-3d0"))
  assert_eq(regions[1].start, 0x7f0000000000UL)
  assert_eq(regions[1].device, "00:01")
  assert_true(regions[1].path is Some("/dev/ashmem"))
  assert_true(!regions[1].protection.private)
}

///|
/// parse_maps golden：乱序输入按地址升序返回。
test "parse_maps golden: sorted by start" {
  let text = "00500000-00501000 rw-p 00000000 00:00 0\n" +
    "00400000-00401000 r-xp 00000000 00:00 0\n" +
    "00480000-00481000 r--p 00000000 00:00 0\n"
  let regions = @ptrace_lite.parse_maps(text)
  assert_eq(regions.length(), 3)
  assert_eq(regions[0].start, 0x400000UL)
  assert_eq(regions[1].start, 0x480000UL)
  assert_eq(regions[2].start, 0x500000UL)
}

///|
/// parse_maps 负例：畸形行报 MapsParseFailed(行号, 原因)。
test "parse_maps: malformed lines raise MapsParseFailed" {
  // perms 只有 3 字符
  let e1 = expect_ptrace_error(() => {
    ignore(@ptrace_lite.parse_maps("00400000-00452000 r-x 00000000 08:02 1 /a"))
  })
  assert_true(e1 is @ptrace_lite.PtraceError::MapsParseFailed(1, _))
  // 非法十六进制地址
  let e2 = expect_ptrace_error(() => {
    ignore(
      @ptrace_lite.parse_maps("zzz400000-00452000 r-xp 00000000 08:02 1 /a"),
    )
  })
  assert_true(e2 is @ptrace_lite.PtraceError::MapsParseFailed(1, _))
  // 空区间（start >= end）
  let e3 = expect_ptrace_error(() => {
    ignore(
      @ptrace_lite.parse_maps("00452000-00452000 r-xp 00000000 08:02 1 /a"),
    )
  })
  assert_true(e3 is @ptrace_lite.PtraceError::MapsParseFailed(1, _))
  // perms 第 4 字符不是 p/s
  let e4 = expect_ptrace_error(() => {
    ignore(
      @ptrace_lite.parse_maps("00400000-00452000 rwxq 00000000 08:02 1 /a"),
    )
  })
  assert_true(e4 is @ptrace_lite.PtraceError::MapsParseFailed(1, _))
  // 非法 inode
  let e5 = expect_ptrace_error(() => {
    ignore(
      @ptrace_lite.parse_maps("00400000-00452000 r-xp 00000000 08:02 xx /a"),
    )
  })
  assert_true(e5 is @ptrace_lite.PtraceError::MapsParseFailed(1, _))
  // 非法 dev
  let e6 = expect_ptrace_error(() => {
    ignore(@ptrace_lite.parse_maps("00400000-00452000 r-xp 00000000 0802 1 /a"))
  })
  assert_true(e6 is @ptrace_lite.PtraceError::MapsParseFailed(1, _))
  // 缺字段
  let e7 = expect_ptrace_error(() => {
    ignore(@ptrace_lite.parse_maps("00400000-00452000 r-xp 00000000"))
  })
  assert_true(e7 is @ptrace_lite.PtraceError::MapsParseFailed(1, _))
  // 行号传播：第 3 行畸形
  let e8 = expect_ptrace_error(() => {
    ignore(
      @ptrace_lite.parse_maps(
        "00400000-00452000 r-xp 00000000 08:02 1 /a\n" +
        "00500000-00552000 r-xp 00000000 08:02 1 /a\n" +
        "garbage line\n",
      ),
    )
  })
  assert_true(e8 is @ptrace_lite.PtraceError::MapsParseFailed(3, _))
  // 中间空行
  let e9 = expect_ptrace_error(() => {
    ignore(
      @ptrace_lite.parse_maps(
        "00400000-00452000 r-xp 00000000 08:02 1 /a\n" +
        "\n" +
        "00500000-00552000 r-xp 00000000 08:02 1 /a",
      ),
    )
  })
  assert_true(e9 is @ptrace_lite.PtraceError::MapsParseFailed(2, _))
  // 空文本 → 空列表（非错误）
  assert_eq(@ptrace_lite.parse_maps("").length(), 0)
}
