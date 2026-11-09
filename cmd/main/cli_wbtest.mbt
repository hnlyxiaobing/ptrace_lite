// 白盒测试：CLI 参数解析与退出码契约（桌面 stub 后端可跑）。
// 覆盖 attach/maps/read/write/step、--help、用法错误 2、运行失败 1、成功 0，
// 以及重复 attach/detach 不耗尽 stub 句柄表（stub 槽位复用回归）。

///|
/// 内部：期望解析成功。
fn parse_ok(args : Array[String]) -> CliCommand raise {
  parse_args(args) catch {
    CliError::Usage(msg) => fail("unexpected usage error: \{msg}")
  }
}

///|
/// 内部：期望用法错误并返回消息。
fn expect_usage(args : Array[String]) -> String raise {
  let mut message = ""
  let mut raised = false
  try {
    let _ = parse_args(args)
  } catch {
    CliError::Usage(msg) => {
      message = msg
      raised = true
    }
  }
  if !raised {
    fail("expected CliError::Usage")
  }
  message
}

///|
/// 子命令解析：attach / maps / read / write / step / help。
test "cli: parse subcommands" {
  assert_true(parse_ok(["attach", "4242"]) is CliCommand::Attach(4242))
  assert_true(parse_ok(["maps", "4242"]) is CliCommand::Maps(4242))
  assert_true(parse_ok(["step", "4242"]) is CliCommand::Step(4242))
  assert_true(parse_ok(["--help"]) is CliCommand::Help)
  assert_true(parse_ok(["help"]) is CliCommand::Help)
  assert_true(parse_ok(["-h"]) is CliCommand::Help)
  match parse_ok(["read", "4242", "0x10000", "4"]) {
    CliCommand::Read(pid, address, length) => {
      assert_eq(pid, 4242)
      assert_eq(address, 0x10000UL)
      assert_eq(length, 4)
    }
    _ => fail("expected Read command")
  }
  match parse_ok(["write", "4242", "0x10010", "41 42"]) {
    CliCommand::Write(pid, address, data) => {
      assert_eq(pid, 4242)
      assert_eq(address, 0x10010UL)
      assert_eq(data, b"AB")
    }
    _ => fail("expected Write command")
  }
}

///|
/// 数字格式：地址可带 / 不带 `0x`，字节串可含空白；非法值走用法错误。
test "cli: numeric formats" {
  match parse_ok(["read", "4242", "10000", "16"]) {
    CliCommand::Read(_, address, length) => {
      assert_eq(address, 0x10000UL)
      assert_eq(length, 16)
    }
    _ => fail("expected Read command")
  }
  match parse_ok(["write", "4242", "0X20000", "41\t42"]) {
    CliCommand::Write(_, address, data) => {
      assert_eq(address, 0x20000UL)
      assert_eq(data, b"AB")
    }
    _ => fail("expected Write command")
  }
  // 空地址 / 17 位十六进制（溢出）
  ignore(expect_usage(["read", "4242", "0x", "4"]))
  ignore(expect_usage(["read", "4242", "0x10000000000000000", "4"]))
}

///|
/// 用法错误：缺命令 / 未知命令 / 缺参 / 多参 / 非法 pid / 非法长度 / 非法字节。
test "cli: usage errors" {
  ignore(expect_usage([]))
  ignore(expect_usage(["bogus"]))
  ignore(expect_usage(["attach"]))
  ignore(expect_usage(["attach", "4242", "extra"]))
  ignore(expect_usage(["attach", "0"]))
  ignore(expect_usage(["attach", "-1"]))
  ignore(expect_usage(["attach", "abc"]))
  ignore(expect_usage(["attach", "2147483648"]))
  ignore(expect_usage(["read", "4242", "0x10000"]))
  ignore(expect_usage(["read", "4242", "zz", "4"]))
  ignore(expect_usage(["read", "4242", "-0x10000", "4"]))
  ignore(expect_usage(["write", "4242", "0x10010", ""]))
  ignore(expect_usage(["write", "4242", "0x10010", "4"]))
  ignore(expect_usage(["write", "4242", "0x10010", "4g"]))
  ignore(expect_usage(["write", "4242", "0x10010", "4142", "extra"]))
  ignore(expect_usage(["step"]))
  ignore(expect_usage(["help", "extra"]))
}

///|
/// 退出码契约：0=成功 / 1=运行失败（PtraceError）/ 2=用法错误。
test "cli: exit code contract on stub backend" {
  assert_eq(run(["ptrace-cli", "--help"]), 0)
  assert_eq(run(["ptrace-cli"]), 2)
  assert_eq(run(["ptrace-cli", "bogus"]), 2)
  assert_eq(run(["ptrace-cli", "attach"]), 2)
  // stub 模拟 pid 4242：五个子命令全部成功并 detach
  assert_eq(run(["ptrace-cli", "attach", "4242"]), 0)
  assert_eq(run(["ptrace-cli", "maps", "4242"]), 0)
  assert_eq(run(["ptrace-cli", "read", "4242", "0x10000", "4"]), 0)
  assert_eq(run(["ptrace-cli", "write", "4242", "0x10010", "4142"]), 0)
  assert_eq(run(["ptrace-cli", "step", "4242"]), 0)
  // 运行失败：不存在 pid / 越界地址 / 只读代码页写入
  assert_eq(run(["ptrace-cli", "attach", "999999"]), 1)
  assert_eq(run(["ptrace-cli", "maps", "999999"]), 1)
  assert_eq(run(["ptrace-cli", "read", "4242", "0x500000", "4"]), 1)
  assert_eq(run(["ptrace-cli", "write", "4242", "0x20000", "41"]), 1)
  // 错误后仍可正常使用（无句柄泄漏）
  assert_eq(run(["ptrace-cli", "attach", "4242"]), 0)
}

///|
/// 回归：反复 attach/detach 不得耗尽 stub 句柄表（槽位复用）。
test "cli: repeated attach/detach does not exhaust stub handles" {
  for _ in 0..<12 {
    assert_eq(run(["ptrace-cli", "attach", "4242"]), 0)
  }
}
