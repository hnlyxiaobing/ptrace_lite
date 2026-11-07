///|
/// `parse_maps`：`/proc/<pid>/maps` 纯文本解析（纯函数、可并发、无需 attach）。
///
/// 行格式：`addr-addr perms offset dev inode [path]`。
/// - addr / offset 为十六进制，dev 为 `major:minor` 十六进制，inode 为十进制；
/// - 字段间空白可为任意空格 / 制表符组合，行末空白（含 `\r`）先整体裁剪；
/// - perms 恰为 4 字符：`[r-][w-][x-][ps]`，`p` = private、`s` = shared；
/// - path 可选、可含空格；缺省（匿名映射）为 `None`；
/// - 行末换行产生的末尾空段忽略；其余空行 / 畸形行报
///   `MapsParseFailed(行号, 原因)`（行号从 1 开始）。
/// 结果按 `start` 升序（同 `start` 按 `end` 升序）返回。

///|
/// 内部：解析 [from, to) 的十六进制 UInt64；空段 / 非法字符 / 溢出返回 None。
fn try_parse_hex_u64(chars : Array[Char], from : Int32, to : Int32) -> UInt64? {
  if from >= to {
    return None
  }
  let mut acc = 0UL
  for i in from..<to {
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
      return None // 16 * acc 将溢出
    }
    acc = acc * 16UL + d.to_uint64()
  }
  Some(acc)
}

///|
/// 内部：解析 [from, to) 的十进制非负 Int；空段 / 非法字符 / 溢出返回 None。
fn try_parse_dec_int(chars : Array[Char], from : Int32, to : Int32) -> Int32? {
  if from >= to {
    return None
  }
  let mut acc = 0
  for i in from..<to {
    let c = chars[i]
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
/// 内部：必选十六进制字段。
fn require_hex(
  chars : Array[Char],
  from : Int32,
  to : Int32,
  line_no : Int32,
  what : String,
) -> UInt64 raise PtraceError {
  match try_parse_hex_u64(chars, from, to) {
    None => raise PtraceError::MapsParseFailed(line_no, "invalid \{what}")
    Some(v) => v
  }
}

///|
/// 内部：跳过空格 / 制表符。
fn skip_spaces(chars : Array[Char], i : Int32, end : Int32) -> Int32 {
  let mut j = i
  while j < end && (chars[j] == ' ' || chars[j] == '\t') {
    j = j + 1
  }
  j
}

///|
/// 内部：取下一个空白分隔 token 的结束位置。
fn scan_token(chars : Array[Char], i : Int32, end : Int32) -> Int32 {
  let mut j = i
  while j < end && chars[j] != ' ' && chars[j] != '\t' {
    j = j + 1
  }
  j
}

///|
/// 内部：解析一行 maps 文本（[0, end) 为已裁剪行尾空白的内容）。
fn parse_maps_line(
  line : String,
  chars : Array[Char],
  end : Int32,
  line_no : Int32,
) -> MemoryRegion raise PtraceError {
  let mut i = 0
  // 地址区间
  i = skip_spaces(chars, i, end)
  let addr_start = i
  i = scan_token(chars, i, end)
  let addr_end = i
  // 权限
  i = skip_spaces(chars, i, end)
  let perms_start = i
  i = scan_token(chars, i, end)
  let perms_end = i
  // offset
  i = skip_spaces(chars, i, end)
  let off_start = i
  i = scan_token(chars, i, end)
  let off_end = i
  // dev
  i = skip_spaces(chars, i, end)
  let dev_start = i
  i = scan_token(chars, i, end)
  let dev_end = i
  // inode
  i = skip_spaces(chars, i, end)
  let ino_start = i
  i = scan_token(chars, i, end)
  let ino_end = i
  // path（可选，可含空格）
  i = skip_spaces(chars, i, end)
  let path_start = i

  if addr_start == addr_end ||
    perms_start == perms_end ||
    off_start == off_end ||
    dev_start == dev_end ||
    ino_start == ino_end {
    raise PtraceError::MapsParseFailed(line_no, "missing field(s)")
  }

  // 地址区间：恰好一个 '-'，两侧为十六进制，start < end
  let mut dash = -1
  let mut t = addr_start
  while t < addr_end {
    if chars[t] == '-' {
      if dash >= 0 {
        raise PtraceError::MapsParseFailed(line_no, "invalid address range")
      }
      dash = t
    }
    t = t + 1
  }
  if dash <= addr_start || dash >= addr_end - 1 {
    raise PtraceError::MapsParseFailed(line_no, "invalid address range")
  }
  let start = require_hex(chars, addr_start, dash, line_no, "start address")
  let finish = require_hex(chars, dash + 1, addr_end, line_no, "end address")
  if start >= finish {
    raise PtraceError::MapsParseFailed(line_no, "empty address range")
  }

  // 权限：恰好 4 字符 [r-][w-][x-][ps]
  if perms_end - perms_start != 4 {
    raise PtraceError::MapsParseFailed(line_no, "malformed permissions")
  }
  let p0 = chars[perms_start]
  let p1 = chars[perms_start + 1]
  let p2 = chars[perms_start + 2]
  let p3 = chars[perms_start + 3]
  if (p0 != 'r' && p0 != '-') ||
    (p1 != 'w' && p1 != '-') ||
    (p2 != 'x' && p2 != '-') ||
    (p3 != 'p' && p3 != 's') {
    raise PtraceError::MapsParseFailed(line_no, "malformed permissions")
  }
  let protection = MemoryProtection::{
    read: p0 == 'r',
    write: p1 == 'w',
    execute: p2 == 'x',
    private: p3 == 'p',
  }

  // offset
  let offset = require_hex(chars, off_start, off_end, line_no, "offset")

  // dev：hex:hex，原文保留
  let mut colon = -1
  t = dev_start
  while t < dev_end {
    if chars[t] == ':' {
      if colon >= 0 {
        raise PtraceError::MapsParseFailed(line_no, "malformed device")
      }
      colon = t
    }
    t = t + 1
  }
  if colon <= dev_start || colon >= dev_end - 1 {
    raise PtraceError::MapsParseFailed(line_no, "malformed device")
  }
  ignore(require_hex(chars, dev_start, colon, line_no, "device major"))
  ignore(require_hex(chars, colon + 1, dev_end, line_no, "device minor"))
  let device = line[dev_start:dev_end].to_owned()

  // inode：十进制
  let inode = match try_parse_dec_int(chars, ino_start, ino_end) {
    None => raise PtraceError::MapsParseFailed(line_no, "invalid inode")
    Some(v) => v
  }

  // path：可选
  let path = if path_start < end {
    Some(line[path_start:end].to_owned())
  } else {
    None
  }

  MemoryRegion::{ start, end: finish, protection, offset, device, inode, path, }
}

///|
/// 纯函数式解析 `/proc/<pid>/maps` 文本（便于 golden 测试，无需 attach）。
/// 返回按地址升序的内存区间列表；畸形行报 `MapsParseFailed(行号, 原因)`。
pub fn parse_maps(text : String) -> Array[MemoryRegion] raise PtraceError {
  let regions : Array[MemoryRegion] = []
  let lines = Array::from_iter(text.split("\n"))
  for i in 0..<lines.length() {
    let raw = lines[i].to_owned()
    if i == lines.length() - 1 && raw == "" {
      continue // 行末换行产生的末尾空段
    }
    let chars = raw.to_array()
    let mut end = chars.length()
    while end > 0 {
      let c = chars[end - 1]
      if c == ' ' || c == '\t' || c == '\r' {
        end = end - 1
      } else {
        break
      }
    }
    if end == 0 {
      raise PtraceError::MapsParseFailed(i + 1, "empty line")
    }
    regions.push(parse_maps_line(raw, chars, end, i + 1))
  }
  regions.sort_by(fn(a, b) {
    if a.start < b.start {
      -1
    } else if a.start > b.start {
      1
    } else if a.end < b.end {
      -1
    } else if a.end > b.end {
      1
    } else {
      0
    }
  })
  regions
}
