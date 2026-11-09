// 黑盒测试：多页 fixture（stub pid 4243）上的端到端分段拼接。
// 4242 的 4 个单页区保持原样；4243 为 0x40000-0x43000 三页可写区，
// 用于验证「跨页 read/write → 分段计划 → 逐段调用 → 拼接」的真实路径。

///|
/// 跨页读：0x40FF8 起 16 字节跨过 0x41000 页边界，内容须逐字节正确。
test "segmented: multi-page read across page boundary" {
  let t = @ptrace_lite.Target::attach(4243)
  let data = t.read_bytes(0x40FF8UL, 0x10)
  t.detach()
  assert_eq(data.length(), 0x10)
  for i in 0..<0x10 {
    let address = 0x40FF8UL + i.to_uint64()
    let want = (0xA0 + (address % 16UL).to_int()).to_byte()
    assert_eq(data[i], want)
  }
}

///|
/// 跨页写：0x41FFF 起 2 字节跨过 0x42000 页边界，读回须一致。
test "segmented: multi-page write across page boundary" {
  let t = @ptrace_lite.Target::attach(4243)
  t.write_bytes(0x41FFFUL, b"AB")
  let back = t.read_bytes(0x41FFFUL, 2)
  t.detach()
  assert_eq(back, b"AB")
}

///|
/// 多页 fixture 的 maps / threads 与 4242 隔离，且与分段无关的路径仍然正确。
test "segmented: multi-page maps and threads" {
  let t = @ptrace_lite.Target::attach(4243)
  let regions = t.maps()
  let threads = t.threads()
  t.detach()
  assert_eq(regions.length(), 1)
  assert_eq(regions[0].start, 0x40000UL)
  assert_eq(regions[0].end, 0x43000UL)
  assert_eq(threads.length(), 1)
  assert_eq(threads[0].tid, 4243)
  assert_eq(threads[0].name, "sim-big")
}
