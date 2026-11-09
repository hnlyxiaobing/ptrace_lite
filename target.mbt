///|
/// Target 实现：状态机、错误映射（C status → PtraceError）、缓冲容量校验、
/// shim 内部「/proc 文本包」协议。shim 协议与状态码见 `stub/ptrace_stub.c` 头注释。
///
/// 桌面 stub 提供模拟 tracee；真实 libc 转发留待 Linux / 设备阶段。
/// UTF-8 解码经 `moonbitlang/core/encoding/utf8`（见 `moon.pkg` import）。

///|
/// ---- 内部：C 状态码 → PtraceError 映射 ----
/// 状态码约定（与 stub 一致）：-1 通用失败、-2 无此进程、-3 权限拒绝、
/// -4 SELinux 拒绝、-5 内核不支持、-6 已被本 tracer attach、
/// -7 参数/地址非法、-8 句柄为空或已失效。

///|
/// 内部：进程级错误映射（attach 就绪性探测与 /proc 读取共用）。
/// 先走真实 errno 通道（`<= -1001`），再兼容 stub 合成码。
fn map_proc_status(pid : Pid, code : Int32, context : String) -> PtraceError {
  match errno_from_status(code) {
    Some(errno) => classify_errno(SyscallOp::ProcText, errno, pid, context)
    None =>
      if code == -2 {
        PtraceError::ProcessNotFound(pid)
      } else if code == -3 {
        PtraceError::AttachDenied(
          pid,
          "\{context}: permission denied (status \{code})",
        )
      } else if code == -4 {
        PtraceError::SelinuxDenied(
          "\{context}: SELinux denied (pid \{pid}, status \{code})",
        )
      } else if code == -5 {
        PtraceError::UnsupportedKernel(
          "\{context}: unsupported kernel (pid \{pid}, status \{code})",
        )
      } else if code == -6 {
        PtraceError::AlreadyAttached(pid)
      } else {
        PtraceError::AttachDenied(pid, "\{context}: failed (status \{code})")
      }
  }
}

///|
/// 内部：线程枚举的错误映射（同样先走真实 errno 通道）。
fn map_thread_status(pid : Pid, code : Int32) -> PtraceError {
  match errno_from_status(code) {
    Some(errno) =>
      classify_errno(SyscallOp::ThreadEnum, errno, pid, "thread enumerate")
    None =>
      if code == -2 {
        PtraceError::ProcessNotFound(pid)
      } else if code == -4 {
        PtraceError::SelinuxDenied(
          "thread enumerate: SELinux denied (pid \{pid}, status \{code})",
        )
      } else if code == -5 {
        PtraceError::UnsupportedKernel(
          "thread enumerate: unsupported kernel (pid \{pid}, status \{code})",
        )
      } else {
        PtraceError::ThreadEnumerateFailed(
          pid,
          "thread enumerate failed (status \{code})",
        )
      }
  }
}

///|
/// 内部：状态守卫——只有 `Attached` / `Stepping` 允许操作；
/// `Detached` / `Failed`（未 attach 或句柄已释放）一律 `NotAttached`。
fn Target::ensure_open(self : Target) -> Unit raise PtraceError {
  match self.state {
    TargetState::Attached | TargetState::Stepping => ()
    _ => raise PtraceError::NotAttached(self.pid)
  }
}

///|
/// ---- 内部：shim「/proc 文本包」协议 ----
/// `mb_ptrace_read_maps` 为 snprintf 语义（写入 min(所需, capacity)，返回所需长度）；
/// 内容为 `<maps 全文>\n__tasks__\n<每线程一行 tid\tname\tstate\n>`。

///|
/// 内部：读取 /proc 文本包；容量不足时按返回所需长度扩容重试。
fn read_proc_text(pid : Pid) -> String raise PtraceError {
  let mut cap = 4096
  let mut attempt = 0
  let mut done = false
  let mut text = ""
  while !done {
    let buf : FixedArray[Byte] = FixedArray::make(cap, b'\x00')
    let n = mb_ptrace_read_maps(pid, buf, cap)
    if n < 0 {
      raise map_proc_status(pid, n, "read /proc text")
    }
    if n <= cap {
      text = @utf8.decode_lossy(Bytes::from_array(buf[0:n]))
      done = true
    } else {
      cap = n
      attempt = attempt + 1
      if attempt > 4 {
        raise PtraceError::MapsParseFailed(0, "proc text length unstable")
      }
    }
  }
  text
}

///|
/// 内部：拆分文本包为 (maps 全文, task 段)。段界为独立一行 `__tasks__`。
fn split_proc_bundle(
  pid : Pid,
  text : String,
) -> (String, String) raise PtraceError {
  let chars = text.to_array()
  let n = chars.length()
  let marker : Array[Char] = [
    '\n', '_', '_', 't', 'a', 's', 'k', 's', '_', '_', '\n',
  ]
  let m = marker.length()
  let mut idx = -1
  let mut i = 0
  while i <= n - m && idx < 0 {
    let mut ok = true
    let mut j = 0
    while j < m {
      if chars[i + j] != marker[j] {
        ok = false
      }
      j = j + 1
    }
    if ok {
      idx = i
    }
    i = i + 1
  }
  if idx < 0 {
    raise PtraceError::ThreadEnumerateFailed(
      pid, "proc text bundle missing task section",
    )
  }
  (text[0:idx + 1].to_owned(), text[idx + m:n].to_owned())
}

///|
/// 内部：解析 task 段（每行 `tid<TAB>name<TAB>state`）。
fn parse_task_section(
  pid : Pid,
  task_text : String,
) -> Array[ThreadInfo] raise PtraceError {
  let result : Array[ThreadInfo] = []
  let lines = Array::from_iter(task_text.split("\n"))
  for i in 0..<lines.length() {
    let line = lines[i].to_owned()
    if i == lines.length() - 1 && line == "" {
      continue // 行末换行产生的空段
    }
    let chars = line.to_array()
    let n = chars.length()
    let mut tab1 = -1
    let mut tab2 = -1
    let mut k = 0
    while k < n {
      if chars[k] == '\t' {
        if tab1 < 0 {
          tab1 = k
        } else if tab2 < 0 {
          tab2 = k
        }
      }
      k = k + 1
    }
    if tab1 <= 0 || tab2 <= tab1 + 1 || tab2 >= n - 1 {
      raise PtraceError::ThreadEnumerateFailed(
        pid,
        "malformed task line \{i + 1}: \"\{line}\"",
      )
    }
    let tid = try_parse_dec_int(chars, 0, tab1)
    match tid {
      None =>
        raise PtraceError::ThreadEnumerateFailed(
          pid,
          "malformed tid on task line \{i + 1}",
        )
      Some(t) => {
        let name = line[tab1 + 1:tab2].to_owned()
        let state = line[tab2 + 1:n].to_owned()
        result.push(ThreadInfo::{ tid: t, name, state, })
      }
    }
  }
  result
}

///|
/// ---- MoonBit 侧公开 API ----

///|
/// 只读访问目标状态机当前状态（`Target.state` 为**私有字段**，
/// 经此访问器读取；API 冻结前收紧决策：字段级可见性收紧 + 只读访问器，
/// 其余公开方法签名零变化）。
pub fn Target::state(self : Target) -> TargetState {
  self.state
}

///|
/// attach 到目标进程并停住所有线程。
///
/// - 获取资源：C 侧 tracee 句柄；失败时不持有任何资源。
/// - 错误：`ProcessNotFound` / `AttachDenied` / `SelinuxDenied` /
///   `UnsupportedKernel` / `AlreadyAttached`，经由就绪性探测映射 C 状态码。
/// - 线程：单线程控制模型；`Target` 非线程安全，跨线程使用须由调用方串行化。
/// - 非目标：不做符号解析、不做 inline hook、不做断点管理、不追求跨平台。
/// - TODO(设备实测): 多线程 attach 语义、ARM64 指令边界判断实测。
pub fn Target::attach(pid : Pid) -> Target raise PtraceError {
  // 1) 就绪性探测：capacity = 0 的 read_maps（不写任何缓冲），区分失败类别。
  let empty : FixedArray[Byte] = FixedArray::make(0, b'\x00')
  let probe = mb_ptrace_read_maps(pid, empty, 0)
  if probe < 0 {
    raise map_proc_status(pid, probe, "attach probe")
  }
  // 2) 获取 C 侧句柄；失败时返回空句柄且不持有资源。
  let handle = mb_ptrace_attach(pid)
  // 3) 句柄有效性探测：零长度读无副作用；空句柄返回 -8。
  let handle_probe = mb_ptrace_read_mem(handle, 0, empty, 0)
  if handle_probe < 0 {
    raise attach_error_from_status(pid, handle_probe, "attach handle probe")
  }
  Target::{ pid, handle, state: TargetState::Attached, }
}

///|
/// 解析 `/proc/<pid>/maps`，返回按地址升序的内存区间列表。
pub fn Target::maps(self : Target) -> Array[MemoryRegion] raise PtraceError {
  self.ensure_open()
  let text = read_proc_text(self.pid)
  let (maps_text, _task_text) = split_proc_bundle(self.pid, text)
  parse_maps(maps_text)
}

///|
/// 读取目标进程内存，返回原始字节。
/// 未 attach 必须拒绝（`NotAttached`）；`length` 为负数或地址溢出报 `ReadFailed`；
/// 零长度读返回空 `Bytes`。
pub fn Target::read_bytes(
  self : Target,
  address : Address,
  length : Int32,
) -> Bytes raise PtraceError {
  target_read_bytes(self, address, length)
}

///|
/// 写入目标进程内存；长度以 `data` 为准，空数据为无操作。
/// 未 attach 必须拒绝（`NotAttached`）；地址非法/不可写报 `WriteFailed`。
pub fn Target::write_bytes(
  self : Target,
  address : Address,
  data : Bytes,
) -> Unit raise PtraceError {
  target_write_bytes(self, address, data)
}

///|
/// 单步执行一条指令；成功后 `state` 进入 `Stepping`。
pub fn Target::step(self : Target) -> Unit raise PtraceError {
  self.ensure_open()
  let r = mb_ptrace_step(self.handle)
  if r < 0 {
    raise step_error_from_status(self.pid, r, "step")
  }
  self.state = TargetState::Stepping
}

///|
/// 枚举目标进程的线程（`/proc/<pid>/task` 摘要）；
/// 线程条目数与 `mb_ptrace_task_count` 交叉校验，不一致报 `ThreadEnumerateFailed`。
pub fn Target::threads(self : Target) -> Array[ThreadInfo] raise PtraceError {
  self.ensure_open()
  let expected = mb_ptrace_task_count(self.pid)
  if expected < 0 {
    raise map_thread_status(self.pid, expected)
  }
  let text = read_proc_text(self.pid)
  let (_maps_text, task_text) = split_proc_bundle(self.pid, text)
  let threads = parse_task_section(self.pid, task_text)
  if threads.length() != expected {
    raise PtraceError::ThreadEnumerateFailed(
      self.pid,
      "task count mismatch (task_count \{expected}, listing \{threads.length()})",
    )
  }
  threads
}

///|
/// detach 并释放 C 句柄（唯一释放点）。
/// **不会二次释放，重复调用返回明确错误（`NotAttached`）**：
/// 状态为 `Detached` / `Failed`（未 attach 或句柄已释放）时直接拒绝；
/// 释放失败进入 `Failed` 并报 `DetachFailed`。
pub fn Target::detach(self : Target) -> Unit raise PtraceError {
  match self.state {
    TargetState::Detached | TargetState::Failed =>
      raise PtraceError::NotAttached(self.pid)
    _ => ()
  }
  let r = mb_ptrace_detach(self.handle)
  if r < 0 {
    self.state = TargetState::Failed
    raise detach_error_from_status(self.pid, r, "detach")
  }
  self.state = TargetState::Detached
}

///|
/// ---- 内部：读写实现（公开方法与 `MemoryView` 共用）----

///|
/// 内部：读实现。先把请求按保守 4 KiB 边界拆成不跨页分段（`plan_access`），
/// 再逐段调用 shim；任一段失败即整体失败（不静默截断），错误携带失败段的
/// 地址/长度与段序号。`length == 0` 返回空 `Bytes`（合法无操作）。
fn target_read_bytes(
  t : Target,
  address : Address,
  length : Int32,
) -> Bytes raise PtraceError {
  t.ensure_open()
  let plan = plan_access(AccessKind::Read, address, length, ACCESS_GRANULARITY)
  if length == 0 {
    return b""
  }
  let segments = plan.segments
  let dst : FixedArray[Byte] = FixedArray::make(length, b'\x00')
  for i in 0..<segments.length() {
    let seg = segments[i]
    let tmp : FixedArray[Byte] = FixedArray::make(seg.length, b'\x00')
    let r = mb_ptrace_read_mem(t.handle, seg.address, tmp, seg.length)
    if r < 0 {
      raise read_error_from_status(
        t.pid,
        seg.address,
        seg.length,
        r,
        "read segment \{i + 1}/\{segments.length()}",
      )
    }
    if r != seg.length {
      raise PtraceError::ReadFailed(
        seg.address,
        seg.length,
        "partial read at segment \{i + 1}/\{segments.length()} (\{r} of \{seg.length} bytes)",
      )
    }
    dst.blit_from_bytes(seg.offset, Bytes::from_array(tmp), 0, seg.length)
  }
  Bytes::from_array(dst)
}

///|
/// 内部：写实现。分段口径同 `target_read_bytes`；`data` 为空为无操作。
/// shim 侧对 `src` 容量二次校验（返回 -7）；真实路径下只读页返回 EFAULT/EPERM，
/// 本层不做隐式 `mprotect`（见 `FORWARDING.md` 的 W^X 写入策略）。
fn target_write_bytes(
  t : Target,
  address : Address,
  data : Bytes,
) -> Unit raise PtraceError {
  t.ensure_open()
  let length = data.length()
  let plan = plan_access(AccessKind::Write, address, length, ACCESS_GRANULARITY)
  if length == 0 {
    return ()
  }
  let segments = plan.segments
  for i in 0..<segments.length() {
    let seg = segments[i]
    let chunk = data[seg.offset:seg.offset + seg.length].to_owned()
    let r = mb_ptrace_write_mem(t.handle, seg.address, chunk, seg.length)
    if r < 0 {
      raise write_error_from_status(
        t.pid,
        seg.address,
        seg.length,
        r,
        "write segment \{i + 1}/\{segments.length()}",
      )
    }
    if r != seg.length {
      raise PtraceError::WriteFailed(
        seg.address,
        seg.length,
        "partial write at segment \{i + 1}/\{segments.length()} (\{r} of \{seg.length} bytes)",
      )
    }
  }
}

///|
/// 内存访问契约实现；未 attach 时拒绝读写（见 `target_read_bytes`）。
pub impl MemoryView for Target with fn read_bytes(self, address, length) -> Bytes raise PtraceError {
  target_read_bytes(self, address, length)
}

///|
/// 内存访问契约实现；未 attach 时拒绝读写（见 `target_write_bytes`）。
pub impl MemoryView for Target with fn write_bytes(self, address, data) -> Unit raise PtraceError {
  target_write_bytes(self, address, data)
}
