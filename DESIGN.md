# ptrace_lite · 设计契约（DESIGN.md）

> Round-1 / 2026-11-06 ｜ 状态：架构与声明可评审，无系统调用逻辑、无 shim 实现

## 1. 分层位置与职责

L2 动态插桩层的**进程外轻量控制 FFI 封装**。职责：把 libc ptrace / `process_vm_*` 与 `/proc` 文本映射为 MoonBit 值类型与显式错误，用最小依赖换取「候选符号的运行时证据」。是 `frida_gum_ffi` 的**更小备选**，本轮排序在前（ADR-0005 / ADR-0006）。

## 2. 模块边界 / 依赖方向 / 数据流

```
组合根（选择插桩方案）
   ├─► ptrace_lite::Target::attach ──► mb_ptrace_* shim ──► libc ptrace / process_vm_* / /proc
   └─► frida_gum_ffi::Gum          （互斥备选，W2 之后且有门禁）
```

两库**零互相 import**；`MemoryView` trait 留在本模块、`InstrumentationBackend` 留在 gum 模块，组合根按 Wire 值类型选择，不新建公共抽象模块（K4）。本库不 import 任何本地模块，也不产生 Frame/Rgb/Tensor 之外的跨模块值。

数据流：`Pid` → `Target`（持有 `TraceeRaw`）→ `Array[MemoryRegion]`（maps）→ `Bytes`（read）→ 组合根与 `axml`/`dex` 静态线索关联。

## 3. 核心数据结构

| 类型 | 作用 |
|---|---|
| `TraceeRaw` | 唯一 `#external` 句柄（C `void*`），MoonBit 不引用计数 |
| `Pid` / `Address` | `Int` / `UInt64` 别名，防止裸整数混用 |
| `MemoryProtection { read, write, execute, private }` | maps 权限位 |
| `MemoryRegion { start, end, protection, offset, device, inode, path? }` | `/proc/<pid>/maps` 一行；`path` 为 `String?`（匿名映射） |
| `ThreadInfo { tid, name, state }` | `/proc/<pid>/task` 摘要 |
| `TargetState` | `Detached` / `Attached` / `Stepping` / `Failed` 状态机 |
| `Target { pid, handle, state }` | MoonBit 侧包装值；`handle` 只能由 `detach` 释放一次 |
| `PtraceError` | `pub suberror`，12 个可判定错误构造 |
| `MemoryView` trait | `read_bytes(Self, Address, Int)` / `write_bytes(Self, Address, Bytes)`，供组合根做插桩方案替换 |

> 设计取舍：`Target` 是**值类型**而非「不透明对象 + 全局注册表」，因为本轮禁止任何状态管理逻辑；`state` 字段把「未 attach 时拒绝读写」的约束变成可检查的显式数据。实现轮须保证它与 C 侧句柄状态一致。

## 4. 错误模型

`PtraceError`：`AttachDenied(Pid, String)`、`DetachFailed(Pid, String)`、`NotAttached(Pid)`、`AlreadyAttached(Pid)`、`ProcessNotFound(Pid)`、`MapsParseFailed(Int, String)`、`ReadFailed(Address, Int, String)`、`WriteFailed(Address, Int, String)`、`StepFailed(Pid, String)`、`ThreadEnumerateFailed(Pid, String)`、`UnsupportedKernel(String)`、`SelinuxDenied(String)`。

全部失败型 API 统一 `-> T raise PtraceError`（不用 `Result[T, E]`）；`String` 参数用于承载 errno / 内核消息，便于设备实测时定位。错误只在本模块内产生，组合根负责映射为上层线索报告。

## 5. 资源生命周期

| 资源 | 获取 | 唯一释放点 | 规则 |
|---|---|---|---|
| `TraceeRaw` | `mb_ptrace_attach(pid)` | `Target::detach` | 返回 0 表示失败且不持有资源；**只能释放一次** |
| 读写缓冲 | `FixedArray[Byte]` / `Bytes` | 调用方持有 | 全部 `#borrow`，C 侧只填充或只读 |
| maps 文本缓冲 | `FixedArray[Byte]` | 调用方持有 | `#borrow(dst)` + `capacity`，返回实际长度 |
| 数组 / 字符串结果 | MoonBit 分配 | GC | 无外部释放义务 |

`Target::detach` 幂等；重复调用返回 `NotAttached`，不得二次 `PTRACE_DETACH`。所有 read/write 在 `state != Attached` 时必须拒绝（契约写进 `MemoryView` 的文档注释）。

## 6. 线程 / 并发边界

- **单线程控制模型**：`Target` 非线程安全；跨线程使用必须由调用方串行化。ptrace 的「一个 tracee 只能有一个 tracer」在语义上也不允许并发 attach。
- 本模块**没有回调**（与 gum / camera2 不同），因此不触发 ADR-0009 的「MoonBit 运行时在被钩线程执行闭包」E1 风险 —— 这正是把它排在前者的理由之一。
- `parse_maps(text)` 为纯函数、无状态，可并发调用。
- `[待验证假设]` 多线程 `PTRACE_ATTACH` 的逐线程停止语义，以及 `/proc/<pid>/task` 在 attach 状态下的可读性，需设备实测。

## 7. 平台约束与外部依赖

- `preferred_target = "native"`（本轮调整，ADR-0007）；`extern "C"` 在 wasm 目标被 `E4156` 拒绝。
- 仅 Linux / Android；Windows 主机无法运行（无 ptrace）。Android 需 root 或 `PTRACE_ATTACH` 权限，SELinux / `ptrace_scope` 待实测（E5）。
- 后续依赖：`native-stub` C 文件 + libc；**无第三方库、无 devkit、无许可审查门禁**。
- `[事实]` native 后端不能把 `foreign_library` 导出为可链接 `.so/.dll`，故设备侧仍需「C stub + 宿主 NDK/CMake」路径（`architecture.md` §5.4）。

## 8. 外部类型 / 句柄 / shim / 所有权规则

| 类别 | 声明 | 规则 |
|---|---|---|
| 外部类型 | `TraceeRaw`（`#external pub type`） | C `void*`；不引用计数；**永不跨模块传递** |
| 外部函数 | 7 个 `pub extern "C" fn mb_ptrace_* = "…"` | 统一返回 `Int` status（0 = 成功，或 0 = 空句柄，按各 shim 语义） |
| 缓冲所有权 | `mb_ptrace_read_mem(#borrow(dst))`、`mb_ptrace_write_mem(#borrow(src))`、`mb_ptrace_read_maps(#borrow(dst))` | 独立属性行写在 fn 之前；MoonBit 保留所有权，C 侧不 decref |
| 地址 / 长度 | `Address` = `UInt64`、`length : Int` | 调用方校验长度与缓冲容量；C 侧不做越界推断 |

shim 清单：`mb_ptrace_attach` / `mb_ptrace_detach` / `mb_ptrace_read_mem` / `mb_ptrace_write_mem` / `mb_ptrace_step` / `mb_ptrace_read_maps` / `mb_ptrace_task_count`。**无回调 shim**，故不需要 `FuncRef` / `#owned`。

## 9. 可替换性与实现细节不泄漏

上层只看到 `Target` / `MemoryRegion` / `ThreadInfo` / `Bytes`；看不到 fd、waitpid 状态、`process_vm_*` iovec 布局、`/proc` 文本格式。`MemoryView` trait 让组合根可换成 `frida_gum_ffi`、ShadowHook/bhook 或纯静态分析，不改上层线索关联逻辑。注意 `ptrace_lite::MemoryRegion` 与 `frida_gum_ffi::MemoryRegion` **结构同构但名义类型不同**，由组合根适配（ADR-0002）。

## 10. 测试策略

| 层次 | 内容 |
|---|---|
| 纯测（桌面） | `parse_maps` golden：文件/匿名映射、rwx 权限、缺 path、偏移/device/inode、畸形行 → `MapsParseFailed` |
| 负例 | 未 attach 读写 → `NotAttached`；重复 attach → `AlreadyAttached`；不存在 pid → `ProcessNotFound`；重复 detach → `NotAttached` |
| 集成（设备） | attach → maps → read → write → step → threads → detach；记录 errno 与 SELinux 拒绝信息 |
| 平台 | x86-64 Linux 桌面先跑通；Android arm64 / armv7 记录权限差异 |
| 门禁 | `moon fmt --check` / `moon check`（本轮不加 `--deny-warn`，ADR-0007） |

## 11. 验收标准（实现轮）

1. `parse_maps` golden 全绿（无需 root，可在 CI 跑）；2. attach→detach 全链路在受限设备上可跑且无悬挂句柄；3. 所有非法输入返回 `PtraceError` 而非 panic；4. R4 `--deny-warn` 转绿。

## 12. 未解决问题 / 待验证假设

E5（P1）W^X / SELinux / `ptrace_scope` 实测 · Q1（未解决）`mvp/` 与真实 APK 资产不在本工作区，设备测试用例缺少基线 · ARM64 单步指令边界需反汇编支持（明确非目标）· 多线程 attach 语义待实测。

## 13. 当前状态与 TODO

`ptrace_lite.mbt` 已写入 1 个 `#external` 句柄、7 个 shim 声明、值类型、状态机、错误模型、`MemoryView` trait 与 8 个 `declare` API，公开 API 有 `///` 文档注释与 `TODO(实现轮)`。**未实现任何系统调用、`/proc` 解析或反汇编**。

## References

`../docs/architecture.md` §6 L2、§7 · `../docs/adr/ADR-0002`、`ADR-0006`、`ADR-0007`、`ADR-0009` · `../docs/dependency-graph.md` K4 / O3 · `../docs/open-questions.md` E5 / Q1
