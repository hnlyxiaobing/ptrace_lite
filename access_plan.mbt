///|
/// 跨页访问的分段计划（纯逻辑，可在桌面 / CI 验证，无需真实 ptrace）。
///
/// 真实 `process_vm_readv` / `process_vm_writev` 允许一个 iovec 跨页，但
/// `EFAULT` 只会告诉调用方「某处不可访问」，无法定位到具体页；分段后每次
/// 只访问一个不跨页的区间，可以把失败定位到段，并决定部分读写如何收口
/// （本库当前契约：任一段失败即整体失败，不做静默截断）。
///
/// 设计约束（真实转发层，见 `docs/FORWARDING.md`，均 **[仍需实测]**）：
/// - 粒度取保守的 4 KiB：真实页大小可能是 16 KiB / 64 KiB（arm64），
///   按更小的 4 KiB 边界切分**永远不会跨真实页边界**，只多产生 syscall；
/// - 真实页大小应在设备轮由 C shim 的 `sysconf(_SC_PAGESIZE)` 校准；
/// - 分段数上限 fail-closed，避免畸形大请求把分段计划本身变成内存放大攻击面。

///|
/// 内部：分段粒度（保守 4 KiB，见文件头注释）。
const ACCESS_GRANULARITY : Int32 = 4096

///|
/// 内部：单请求分段数上限（65536 段 × 4 KiB = 256 MiB）。
const MAX_ACCESS_SEGMENTS : Int32 = 65536

///|
/// 内部：访问方向，决定错误构造用 `ReadFailed` 还是 `WriteFailed`。
priv enum AccessKind {
  Read
  Write
}

///|
/// 内部：一个不跨页的访问分段。
///
/// - `address`：该段在目标进程中的起始虚拟地址；
/// - `length`：段长度（> 0）；
/// - `offset`：该段在**整个请求**内的字节偏移（首段为 0，末段 offset + length == 请求长度）。
priv struct AccessSegment {
  address : Address
  length : Int32
  offset : Int32
}

///|
/// 内部：分段计划。`segments` 按地址升序、首尾相接，且每段不跨 `page_size` 边界。
priv struct AccessPlan {
  segments : Array[AccessSegment]
}

///|
/// 内部：构造分方向的分段错误（不引入新的 `PtraceError` 变体）。
fn access_plan_error(
  kind : AccessKind,
  address : Address,
  length : Int32,
  message : String,
) -> PtraceError {
  match kind {
    AccessKind::Read => PtraceError::ReadFailed(address, length, message)
    AccessKind::Write => PtraceError::WriteFailed(address, length, message)
  }
}

///|
/// 内部：把一次 `[address, address + length)` 访问拆成不跨页的分段计划。
///
/// 错误（均走 `PtraceError`，不 panic）：
/// - `length < 0` → 负长度；
/// - `page_size <= 0` → 非法页大小；
/// - `address + length` 溢出 `UInt64` → 地址溢出；
/// - 请求超过分段上限 → fail-closed（不做截断）。
///
/// `length == 0` 返回空计划（零长度访问是合法无操作）。
fn plan_access(
  kind : AccessKind,
  address : Address,
  length : Int32,
  page_size : Int32,
) -> AccessPlan raise PtraceError {
  if length < 0 {
    raise access_plan_error(kind, address, length, "negative length")
  }
  let segments : Array[AccessSegment] = []
  if length == 0 {
    return AccessPlan::{ segments, }
  }
  if page_size <= 0 {
    raise access_plan_error(
      kind,
      address,
      length,
      "invalid page size (\{page_size})",
    )
  }
  let page_u = page_size.to_uint64()
  let len_u = length.to_uint64()
  if address + len_u < address {
    raise access_plan_error(kind, address, length, "address overflow")
  }
  if len_u > MAX_ACCESS_SEGMENTS.to_uint64() * page_u {
    raise access_plan_error(
      kind,
      address,
      length,
      "request too large to segment (cap \{MAX_ACCESS_SEGMENTS} segments, page \{page_size})",
    )
  }
  let mut cursor = address
  let mut consumed = 0
  while consumed < length {
    if segments.length() >= MAX_ACCESS_SEGMENTS {
      raise access_plan_error(
        kind,
        address,
        length,
        "request too large to segment (cap \{MAX_ACCESS_SEGMENTS} segments, page \{page_size})",
      )
    }
    let remaining = (length - consumed).to_uint64()
    let to_page_end = page_u - cursor % page_u
    let chunk = if to_page_end > remaining {
      length - consumed
    } else {
      to_page_end.to_int()
    }
    segments.push(AccessSegment::{
      address: cursor,
      length: chunk,
      offset: consumed,
    })
    cursor = cursor + chunk.to_uint64()
    consumed = consumed + chunk
  }
  AccessPlan::{ segments, }
}
