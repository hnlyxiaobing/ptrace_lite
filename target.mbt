///|
/// Target 实现：状态机、错误映射（C status → PtraceError）、缓冲容量校验、
/// shim 内部「/proc 文本包」协议。shim 协议与状态码见 `stub/ptrace_stub.c` 头注释。
///
/// 桌面 stub 提供模拟 tracee；真实 libc 转发留待 Linux/设备轮次。
/// UTF-8 解码经 `moonbitlang/core/encoding/utf8`（见 `moon.pkg` import）。

///|
/// ---- 内部：C 状态码 → PtraceError 映射 ----
/// 状态码约定（与 stub 一致）：-1 通用失败、-2 无此进程、-3 权限拒绝、
/// -4 SELinux 拒绝、-5 内核不支持、-6 已被本 tracer attach、
/// -7 参数/地址非法、-8 句柄为空或已失效。

///|
/// 内部：进程级错误映射（attach 就绪性探测与 /proc 读取共用）。
fn map_proc_status(pid : Pid, code : Int32, context : String) -> PtraceError {
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

///|
/// 内部：线程枚举的错误映射。
fn map_thread_status(pid : Pid, code : Int32) -> PtraceError {
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
/// 经此访问器读取；冻结前 P0 决策 5：字段级可见性收紧 + 只读访问器，
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
/// - TODO(设备轮次): 多线程 attach 语义、ARM64 指令边界判断实测。
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
  if mb_ptrace_read_mem(handle, 0, empty, 0) < 0 {
    raise PtraceError::AttachDenied(pid, "attach failed: empty handle")
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
    if r == -8 {
      raise PtraceError::NotAttached(self.pid)
    }
    raise PtraceError::StepFailed(self.pid, "step failed (status \{r})")
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
    raise PtraceError::DetachFailed(self.pid, "detach failed (status \{r})")
  }
  self.state = TargetState::Detached
}

///|
/// ---- 内部：读写实现（公开方法与 `MemoryView` 共用）----

///|
/// 内部：读实现。容量校验：`length` 与地址区间在调用 shim 前校验，
/// shim 侧对 `dst` 容量二次校验（返回 -7）。
fn target_read_bytes(
  t : Target,
  address : Address,
  length : Int32,
) -> Bytes raise PtraceError {
  t.ensure_open()
  if length < 0 {
    raise PtraceError::ReadFailed(address, length, "negative length")
  }
  if length == 0 {
    return b""
  }
  let end = address + length.to_uint64()
  if end < address {
    raise PtraceError::ReadFailed(address, length, "address overflow")
  }
  let dst : FixedArray[Byte] = FixedArray::make(length, b'\x00')
  let r = mb_ptrace_read_mem(t.handle, address, dst, length)
  if r < 0 {
    if r == -8 {
      raise PtraceError::NotAttached(t.pid)
    }
    raise PtraceError::ReadFailed(address, length, "read failed (status \{r})")
  }
  if r != length {
    raise PtraceError::ReadFailed(
      address,
      length,
      "partial read (\{r} of \{length} bytes)",
    )
  }
  Bytes::from_array(dst[0:length])
}

///|
/// 内部：写实现。容量校验：长度以 `data` 为准，shim 侧对 `src` 容量二次校验（返回 -7）。
fn target_write_bytes(
  t : Target,
  address : Address,
  data : Bytes,
) -> Unit raise PtraceError {
  t.ensure_open()
  let length = data.length()
  if length == 0 {
    return ()
  }
  let end = address + length.to_uint64()
  if end < address {
    raise PtraceError::WriteFailed(address, length, "address overflow")
  }
  let r = mb_ptrace_write_mem(t.handle, address, data, length)
  if r < 0 {
    if r == -8 {
      raise PtraceError::NotAttached(t.pid)
    }
    raise PtraceError::WriteFailed(
      address,
      length,
      "write failed (status \{r})",
    )
  }
  if r != length {
    raise PtraceError::WriteFailed(
      address,
      length,
      "partial write (\{r} of \{length} bytes)",
    )
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
