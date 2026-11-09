///|
/// ptrace-cli：ptrace_lite 的轻量 CLI 骨架（attach / maps / read / write / step）。
///
/// 退出码契约（与工作区 R2 三核心 CLI、ADR-0011 D6 同口径）：
/// - `0` = 成功（命令完成并已 detach）
/// - `1` = 运行失败（库层 `PtraceError`：attach 失败、非法地址、W^X 只读页等）
/// - `2` = 用法错误（未知命令 / 缺参 / 非法数字 / 非法十六进制）
///
/// 后端：桌面 stub（`stub/ptrace_stub.c`）仅模拟 pid 4242；真实 libc
/// `ptrace` / `process_vm_*` / `waitpid` 转发与 Linux/Android 设备实测
/// 留待非 Windows 平台 **[仍需实测]**（E5）。

///|
let tool_name = "ptrace-cli"

///|
/// 解析后的 CLI 命令。
priv enum CliCommand {
  Attach(@ptrace_lite.Pid)
  Maps(@ptrace_lite.Pid)
  Read(@ptrace_lite.Pid, @ptrace_lite.Address, Int32)
  Write(@ptrace_lite.Pid, @ptrace_lite.Address, Bytes)
  Step(@ptrace_lite.Pid)
  Help
}

///|
/// CLI 用法错误（退出码 2）；库层错误仍走 `PtraceError`（退出码 1）。
priv suberror CliError {
  Usage(String)
}

///|
/// 帮助文本（stdout，退出码 0）。
fn usage_text() -> String {
  join_lines([
    "\{tool_name} —— ptrace_lite 轻量进程控制 CLI（桌面 stub 后端）",
    "",
    "用法:",
    "  \{tool_name} <command> <pid> [args]",
    "  \{tool_name} --help",
    "",
    "命令:",
    "  attach <pid>               attach 并打印状态，随后 detach",
    "  maps <pid>                 attach 后打印 /proc/<pid>/maps 区间，随后 detach",
    "  read <pid> <addr> <len>    attach 后读取内存（addr 十六进制，len 十进制），随后 detach",
    "  write <pid> <addr> <hex>   attach 后写入十六进制字节（如 4142 / 41 42），随后 detach",
    "  step <pid>                 attach 后单步一次并打印状态，随后 detach",
    "",
    "退出码: 0=成功 1=运行失败（PtraceError） 2=用法错误",
    "平台: 桌面 stub 后端仅模拟 pid 4242；真实 libc ptrace / process_vm_* / waitpid",
    "      转发与 Linux/Android 设备实测留待非 Windows 平台 [仍需实测]（E5）",
  ])
}

///|
/// 内部：解析十进制非负 Int32（空串 / 非法字符 / 溢出返回 None）。
fn parse_dec_i32(text : String) -> Int32? {
  let chars = text.to_array()
  if chars.length() == 0 {
    return None
  }
  let mut acc = 0
  for c in chars {
    if c < '0' || c > '9' {
      return None
    }
    let d = c.to_int() - '0'
    if acc > 214748364 {
      return None
    }
    if acc == 214748364 && d > 7 {
      return None
    }
    acc = acc * 10 + d
  }
  Some(acc)
}

///|
/// 内部：解析十六进制地址（可带 `0x` / `0X`；空串 / 非法字符 / 溢出返回 None）。
fn parse_address(text : String) -> @ptrace_lite.Address? {
  let chars = text.to_array()
  let n = chars.length()
  let mut i = 0
  if n >= 2 && chars[0] == '0' && (chars[1] == 'x' || chars[1] == 'X') {
    i = 2
  }
  if i >= n {
    return None
  }
  let mut acc = 0UL
  while i < n {
    let c = chars[i]
    let d = if c >= '0' && c <= '9' {
      c.to_int() - '0'
    } else if c >= 'a' && c <= 'f' {
      c.to_int() - 'a' + 10
    } else if c >= 'A' && c <= 'F' {
      c.to_int() - 'A' + 10
    } else {
      return None
    }
    if acc > 0x0FFFFFFFFFFFFFFFUL {
      return None
    }
    acc = acc * 16UL + d.to_uint64()
    i = i + 1
  }
  Some(acc)
}

///|
/// 内部：解析单个十六进制数字。
fn hex_digit(c : Char) -> Int32? {
  if c >= '0' && c <= '9' {
    Some(c.to_int() - '0')
  } else if c >= 'a' && c <= 'f' {
    Some(c.to_int() - 'a' + 10)
  } else if c >= 'A' && c <= 'F' {
    Some(c.to_int() - 'A' + 10)
  } else {
    None
  }
}

///|
/// 内部：解析十六进制字节串（接受空格 / 制表符分隔，必须偶数个数字）。
fn parse_hex_bytes(text : String) -> Bytes? {
  let digits : Array[Int32] = []
  for c in text.to_array() {
    if c == ' ' || c == '\t' {
      continue
    }
    match hex_digit(c) {
      None => return None
      Some(d) => digits.push(d)
    }
  }
  if digits.length() == 0 || digits.length() % 2 != 0 {
    return None
  }
  let out : FixedArray[Byte] = FixedArray::make(digits.length() / 2, b'\x00')
  let mut i = 0
  while i < digits.length() {
    out[i / 2] = (digits[i] * 16 + digits[i + 1]).to_byte()
    i = i + 2
  }
  Some(Bytes::from_array(out))
}

///|
/// 内部：必需 pid（正整数）。
fn require_pid(text : String) -> @ptrace_lite.Pid raise CliError {
  match parse_dec_i32(text) {
    Some(pid) =>
      if pid <= 0 {
        raise CliError::Usage(
          "pid must be a positive decimal integer, got \"\{text}\"",
        )
      } else {
        pid
      }
    None =>
      raise CliError::Usage(
        "invalid pid \"\{text}\" (expected positive decimal integer)",
      )
  }
}

///|
/// 内部：必需地址（十六进制，可带 0x）。
fn require_address(text : String) -> @ptrace_lite.Address raise CliError {
  match parse_address(text) {
    Some(address) => address
    None =>
      raise CliError::Usage(
        "invalid address \"\{text}\" (expected hexadecimal, optional 0x prefix)",
      )
  }
}

///|
/// 内部：必需长度（十进制非负）。
fn require_length(text : String) -> Int32 raise CliError {
  match parse_dec_i32(text) {
    Some(length) => length
    None =>
      raise CliError::Usage(
        "invalid length \"\{text}\" (expected non-negative decimal integer)",
      )
  }
}

///|
/// 内部：必需十六进制字节串。
fn require_bytes(text : String) -> Bytes raise CliError {
  match parse_hex_bytes(text) {
    Some(data) =>
      if data.length() == 0 {
        raise CliError::Usage("empty hex byte string")
      } else {
        data
      }
    None =>
      raise CliError::Usage(
        "invalid hex bytes \"\{text}\" (expected pairs like 4142 or 41 42)",
      )
  }
}

///|
/// 解析 argv（不含程序名）为命令；非法输入一律 `CliError::Usage`，不 panic。
fn parse_args(args : Array[String]) -> CliCommand raise CliError {
  if args.length() == 0 {
    raise CliError::Usage("missing command")
  }
  let command = args[0]
  if command == "--help" || command == "-h" || command == "help" {
    if args.length() != 1 {
      raise CliError::Usage("help takes no operands")
    }
    return CliCommand::Help
  }
  if command == "attach" {
    if args.length() != 2 {
      raise CliError::Usage("usage: attach <pid>")
    }
    return CliCommand::Attach(require_pid(args[1]))
  }
  if command == "maps" {
    if args.length() != 2 {
      raise CliError::Usage("usage: maps <pid>")
    }
    return CliCommand::Maps(require_pid(args[1]))
  }
  if command == "read" {
    if args.length() != 4 {
      raise CliError::Usage("usage: read <pid> <address> <length>")
    }
    return CliCommand::Read(
      require_pid(args[1]),
      require_address(args[2]),
      require_length(args[3]),
    )
  }
  if command == "write" {
    if args.length() != 4 {
      raise CliError::Usage("usage: write <pid> <address> <hex-bytes>")
    }
    return CliCommand::Write(
      require_pid(args[1]),
      require_address(args[2]),
      require_bytes(args[3]),
    )
  }
  if command == "step" {
    if args.length() != 2 {
      raise CliError::Usage("usage: step <pid>")
    }
    return CliCommand::Step(require_pid(args[1]))
  }
  raise CliError::Usage(
    "unknown command \"\{command}\" (expected attach|maps|read|write|step|--help)",
  )
}

///|
/// attach，失败时打印库层错误并返回 None（由调用方收口退出码 1）。
fn attach_or_fail(pid : @ptrace_lite.Pid) -> @ptrace_lite.Target? {
  Some(@ptrace_lite.Target::attach(pid)) catch {
    e => {
      eprintln("error: attach pid=\{pid} failed: \{e.to_repr()}")
      None
    }
  }
}

///|
/// detach（唯一释放点）；失败打印错误并返回 false。
fn detach_or_fail(t : @ptrace_lite.Target) -> Bool {
  try {
    t.detach()
    true
  } catch {
    e => {
      eprintln("error: detach failed: \{e.to_repr()}")
      false
    }
  }
}

///|
/// `attach` 子命令。
fn run_attach(pid : @ptrace_lite.Pid) -> Int32 {
  match attach_or_fail(pid) {
    None => 1
    Some(t) => {
      let state = t.state()
      let detached = detach_or_fail(t)
      if detached {
        println("attach pid=\{pid} state=\{state_name(state)}")
        println("detach pid=\{pid}")
        0
      } else {
        1
      }
    }
  }
}

///|
/// `maps` 子命令：打印区间（升序）与权限位。
fn run_maps(pid : @ptrace_lite.Pid) -> Int32 {
  match attach_or_fail(pid) {
    None => 1
    Some(t) => {
      let regions = Some(t.maps()) catch {
        e => {
          eprintln("error: maps pid=\{pid} failed: \{e.to_repr()}")
          None
        }
      }
      let detached = detach_or_fail(t)
      match regions {
        None => 1
        Some(rs) =>
          if !detached {
            1
          } else {
            println("maps pid=\{pid} regions=\{rs.length()}")
            for r in rs {
              let path = match r.path {
                Some(p) => p
                None => ""
              }
              println(
                "0x\{r.start.to_string(radix=16)}-0x\{r.end.to_string(radix=16)} \{protection_string(r.protection)} offset=0x\{r.offset.to_string(radix=16)} dev=\{r.device} inode=\{r.inode} path=\{path}",
              )
            }
            0
          }
      }
    }
  }
}

///|
/// `read` 子命令：读取并打印十六进制字节。
fn run_read(
  pid : @ptrace_lite.Pid,
  address : @ptrace_lite.Address,
  length : Int32,
) -> Int32 {
  match attach_or_fail(pid) {
    None => 1
    Some(t) => {
      let data = Some(t.read_bytes(address, length)) catch {
        e => {
          eprintln("error: read pid=\{pid} failed: \{e.to_repr()}")
          None
        }
      }
      let detached = detach_or_fail(t)
      match data {
        None => 1
        Some(bytes) =>
          if !detached {
            1
          } else {
            println(
              "read pid=\{pid} address=0x\{address.to_string(radix=16)} length=\{bytes.length()} hex=\{bytes_hex(bytes)}",
            )
            0
          }
      }
    }
  }
}

///|
/// `write` 子命令：写入十六进制字节。
fn run_write(
  pid : @ptrace_lite.Pid,
  address : @ptrace_lite.Address,
  data : Bytes,
) -> Int32 {
  match attach_or_fail(pid) {
    None => 1
    Some(t) => {
      let ok = try {
        t.write_bytes(address, data)
        true
      } catch {
        e => {
          eprintln("error: write pid=\{pid} failed: \{e.to_repr()}")
          false
        }
      }
      let detached = detach_or_fail(t)
      if ok && detached {
        println(
          "write pid=\{pid} address=0x\{address.to_string(radix=16)} bytes=\{data.length()} hex=\{bytes_hex(data)}",
        )
        0
      } else {
        1
      }
    }
  }
}

///|
/// `step` 子命令：单步一次并打印状态机。
fn run_step(pid : @ptrace_lite.Pid) -> Int32 {
  match attach_or_fail(pid) {
    None => 1
    Some(t) => {
      let ok = try {
        t.step()
        true
      } catch {
        e => {
          eprintln("error: step pid=\{pid} failed: \{e.to_repr()}")
          false
        }
      }
      let state = t.state()
      let detached = detach_or_fail(t)
      if ok && detached {
        println("step pid=\{pid} state=\{state_name(state)}")
        0
      } else {
        1
      }
    }
  }
}

///|
/// 执行解析后的命令，返回进程退出码。
fn execute(cmd : CliCommand) -> Int32 {
  match cmd {
    CliCommand::Help => {
      println(usage_text())
      0
    }
    CliCommand::Attach(pid) => run_attach(pid)
    CliCommand::Maps(pid) => run_maps(pid)
    CliCommand::Read(pid, address, length) => run_read(pid, address, length)
    CliCommand::Write(pid, address, data) => run_write(pid, address, data)
    CliCommand::Step(pid) => run_step(pid)
  }
}

///|
/// CLI 主流程（可测试入口）：`args` 为完整 argv（含程序名）。
fn run(args : Array[String]) -> Int32 {
  if args.length() <= 1 {
    eprintln("error: missing command")
    eprintln(usage_text())
    return 2
  }
  let rest : Array[String] = []
  for i in 1..<args.length() {
    rest.push(args[i])
  }
  let parsed = Some(parse_args(rest)) catch {
    CliError::Usage(msg) => {
      eprintln("error: \{msg}")
      eprintln("运行 \{tool_name} --help 查看用法")
      None
    }
  }
  match parsed {
    None => 2
    Some(cmd) => execute(cmd)
  }
}

///|
fn main {
  let code = run(@env.args())
  if code != 0 {
    @env.exit(code)
  }
}
