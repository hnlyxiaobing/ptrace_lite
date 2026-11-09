///|
/// ptrace-cli 内部辅助：帮助文本拼接、十六进制渲染、权限位渲染。
/// 只依赖 `moonbitlang/core` 与 `ptrace_lite` 公开 API。

///|
/// 文本行拼接（`\n` 分隔，帮助文本用）。
fn join_lines(lines : Array[String]) -> String {
  let mut s = ""
  let mut first = true
  for line in lines {
    if first {
      first = false
    } else {
      s = s + "\n"
    }
    s = s + line
  }
  s
}

///|
/// `Bytes` 渲染为小写十六进制（空格分隔），供 `read` 输出。
fn bytes_hex(data : Bytes) -> String {
  let mut s = ""
  for i in 0..<data.length() {
    if i > 0 {
      s = s + " "
    }
    s = s + data[i].to_hex()
  }
  s
}

///|
/// maps 权限位渲染为 `rwxp` / `r--s` 形式（与 `/proc/<pid>/maps` 同构）。
fn protection_string(p : @ptrace_lite.MemoryProtection) -> String {
  let r = if p.read { "r" } else { "-" }
  let w = if p.write { "w" } else { "-" }
  let x = if p.execute { "x" } else { "-" }
  let s = if p.private { "p" } else { "s" }
  r + w + x + s
}

///|
/// 状态机文本名（CLI 输出用）。
fn state_name(s : @ptrace_lite.TargetState) -> String {
  match s {
    @ptrace_lite.TargetState::Detached => "Detached"
    @ptrace_lite.TargetState::Attached => "Attached"
    @ptrace_lite.TargetState::Stepping => "Stepping"
    @ptrace_lite.TargetState::Failed => "Failed"
  }
}
