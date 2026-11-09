# ptrace_lite · 真实转发层设计（FORWARDING.md）

> **状态**：设计侧（2026-11-09，R4 增量轮）。本机为 Windows，**无法实测**
> `ptrace` / `process_vm_readv` / `process_vm_writev` / `waitpid` 真实链路；
> E5 解禁条件（非 Windows 平台）未满足。
> 本文所有真实内核路径条目均标 **[仍需实测]**；桌面可纯逻辑验证的部分
> （分段计划、errno 分类、stub fail-closed、CLI 骨架）已在 R4 实现并有测试，
> 不在此文冒充「已跑通」。
>
> 证据等级沿用工作区口径：`[已复验]` 本机命令/文件实测 · `[已复验-本地等价]`
> 同序本地实跑（非目标平台）· `[仅据文档]` 来自文档/内核规范 · `[仍需实测]`
> 尚无证据。

---

## 0. 结论摘要

| 项 | 本轮状态 | 证据等级 |
|---|---|---|
| 7 个 shim 的符号/签名/调用点 | 保持不变（包私有 ABI） | `[已复验]` 本机 `moon check --deny-warn` / `moon test` |
| 跨页分段计划（4 KiB 保守粒度、上限 fail-closed） | 已实现 + 白盒测试 | `[已复验-本地等价]` |
| errno → `PtraceError` 分类（ESRCH/EPERM/EFAULT/EIO/…） | 已实现 + 白盒测试 | `[已复验-本地等价]` |
| stub 无真实 libc 时 fail-closed | 已实现 + 黑盒测试（含句柄槽复用修复） | `[已复验-本地等价]` |
| CLI `attach/maps/read/write/step` + 退出码 0/1/2 | 已实现 + 白盒测试，可 `moon run` | `[已复验-本地等价]` |
| 真实 libc 转发（`PTRACE_*` / `process_vm_*` / `waitpid`） | **未实现、未编译、未运行** | `[仍需实测]` |
| `mprotect` 写入策略 / 多线程逐线程停止 / 内核降级 | 设计完成，未实测 | `[仍需实测]` |
| SELinux `untrusted_app` / `kernel.yama.ptrace_scope` | 设计完成，未实测 | `[仍需实测]` |

---

## 1. 双路径与 shim ABI

### 1.1 编译期双路径（不做运行时 `dlopen`）

真实转发层与桌面 stub **共用同一组 7 个 C 符号**，在 C 翻译单元内以编译期
条件切换，不引入运行时动态加载：

```c
/* 设计形态；真实实现留待非 Windows 设备轮 [仍需实测] */
#if defined(__linux__) && !defined(MB_PTRACE_FORCE_STUB)
  /* real: libc ptrace / process_vm_* / waitpid / /proc */
#else
  /* stub: ../stub/ptrace_stub.c 的模拟实现 */
#endif
```

- 与 `tflite_ffi` 的「运行时动态加载真实 `.so`」不同：`ptrace` / `process_vm_*`
  是 **libc/内核系统调用**，没有可选的第三方 `.so`，编译期平台分支即可；
  `[仅据文档]` `process_vm_readv` 自 Linux 3.2 起在 libc 中提供。
- `../moon.pkg` 的 `"native-stub"` 列表、`../moon.mod` 的 `preferred_target`
  均不需要改动；真实实现应替换/新增 `native/` 下的 C 源文件，
  **不得**把任何第三方 `.so` 入库（本库本来也不依赖）。
- 未知平台（macOS / wasm / 其他）一律落到 stub 分支并保持 fail-closed 语义，
  不伪造真实系统调用成功。`[已复验]` 当前 Windows/MSVC 走 stub。

### 1.2 状态通道 v2（stub 合成码 + 真实 errno 通道）

现有 stub 状态码（`-1..-8`）与 POSIX errno 冲突：`-2` 在 stub 是「无此进程」，
在 errno 是 `ENOENT`；`-3`/`-4`/`-5` 同样冲突。因此真实路径**不得**直接返回
`-errno`。设计如下（MoonBit 侧已实现 `../errno_map.mbt`）：

| 返回值 | 含义 | 生产者 |
|---|---|---|
| `0` / 正数 | 成功（字节数 / `/proc` 文本所需长度 / 线程数） | stub + real |
| `-1 .. -999` | stub 合成码（legacy，语义见 `../stub/ptrace_stub.c` 头注释） | stub |
| `-1000 - errno`（`<= -1001`） | 真实 libc 路径的 POSIX errno | real |

- 解码：`errno = -(status + 1000)`，有效范围 `1..4095`；越界视为非法通道值。
- 该协议**不改变公开 API / 快照**：7 个 shim 仍是包私有 ABI。
- 真实路径的 errno 透传点是**设计结论**，尚未在 Linux/Android 编译运行
  `[仍需实测]`。
- `[已复验-本地等价]` 白盒测试覆盖通道边界与全部映射分支
  （`../errno_map_wbtest.mbt`）。

### 1.3 errno → `PtraceError` 分类表（已实现）

| errno | 值 | 读/写内存 | attach | detach | step | `/proc` 文本 | 线程枚举 |
|---|---|---|---|---|---|---|---|
| `ESRCH` | 3 | `ProcessNotFound` | `ProcessNotFound` | `ProcessNotFound` | `ProcessNotFound` | `ProcessNotFound` | `ProcessNotFound` |
| `ENOENT` | 2 | `ProcessNotFound` | `ProcessNotFound` | `ProcessNotFound` | `ProcessNotFound` | `ProcessNotFound` | `ProcessNotFound` |
| `EPERM` | 1 | `ReadFailed`/`WriteFailed`（权限） | `AttachDenied` | `DetachFailed` | `StepFailed` | `AttachDenied` | `ThreadEnumerateFailed` |
| `EACCES` | 13 | 同上 | `AttachDenied` | `DetachFailed` | `StepFailed` | `AttachDenied` | `ThreadEnumerateFailed` |
| `EFAULT` | 14 | `ReadFailed`/`WriteFailed`（bad address） | `AttachDenied` | `DetachFailed` | `StepFailed` | `AttachDenied` | `ThreadEnumerateFailed` |
| `EIO` | 5 | `ReadFailed`/`WriteFailed`（I/O） | `AttachDenied` | `DetachFailed` | `StepFailed` | `UnsupportedKernel` | `UnsupportedKernel` |
| `EINVAL` | 22 | `ReadFailed`/`WriteFailed`（非法地址/长度） | `AttachDenied` | `DetachFailed` | `StepFailed` | `AttachDenied` | `ThreadEnumerateFailed` |
| `ENOSYS` | 38 | 方向错误（`process_vm_*` 缺失） | `UnsupportedKernel` | `DetachFailed` | `UnsupportedKernel` | `UnsupportedKernel` | `UnsupportedKernel` |
| `EINTR` | 4 | 方向错误（应重试） | — | — | — | — | — |
| `EBUSY` | 16 | — | `AlreadyAttached` | — | — | — | — |
| `ECHILD` | 10 | — | `ProcessNotFound` | `ProcessNotFound` | `ProcessNotFound` | — | — |
| 其他 | — | 方向错误（带 errno） | `AttachDenied` | `DetachFailed` | `StepFailed` | `AttachDenied` | `ThreadEnumerateFailed` |

口径说明：

- `EPERM` / `EACCES` **无法仅凭 errno 区分** Yama、SELinux 与普通权限；
  统一映射为 `AttachDenied`，消息里列出候选原因。`SelinuxDenied` 只由 stub
  合成码 `-4` 或未来的显式 SELinux 探测产生。`[仍需实测]` Android
  `untrusted_app` 下实际返回哪个 errno。
- `EINTR` 属应重试项：真实 shim 必须在 C 侧对 `waitpid` / `process_vm_*`
  做 `EINTR` 重试；若泄漏到 MoonBit 层，显式报错而不是静默继续。
- `ENOSYS` 触发降级（见 §7），降级仍失败才映射 `UnsupportedKernel`。
- 每条映射的**真实触发**均 `[仍需实测]`；本轮只验证纯函数分类。

---

## 2. 7 个 shim 的转发规格（逐条 `[仍需实测]`）

> 以下伪代码是**设计规格**，不是已实现代码。真实实现必须保持返回值语义
> 与 §1.2 通道一致。

### 2.1 `mb_ptrace_attach(pid) -> void*`

设计步骤：

1. `open("/proc/<pid>/task", O_RDONLY|O_DIRECTORY)` 枚举 TID；失败按 errno
   映射（`ENOENT/ESRCH` → `-1002`/`-1003`，`EACCES` → `-1013`）。
2. 对每个 TID 调 `ptrace(PTRACE_SEIZE, tid, 0, PTRACE_O_TRACECLONE)`
   （内核 < 3.4 无 `SEIZE` → 降级 `PTRACE_ATTACH`，见 §7）。
3. 对每个 TID `waitpid(tid, &st, __WALL)`，`EINTR` 重试；要求 `WIFSTOPPED`。
4. 枚举与 attach 之间存在竞态：attach 完成后**重新枚举** `/proc/<pid>/task`，
   对新增 TID 重复步骤 2–3，直到一轮无新增（有上限，防止 fork 炸弹）。
   `PTRACE_O_TRACECLONE` 捕获 attach 期间新建线程的事件，需在同一
   `waitpid` 循环中处理。
5. 任一步失败：对已 attach 的 TID 逐个 `PTRACE_DETACH` 回滚，返回 errno
   通道码；**不得**留下半 attach 状态。
6. 成功：`malloc` 句柄，保存 `pid`、`tid[]`、`tid_count`、`options`、
   `attached_at`；返回句柄。

关键语义与风险：

- `PTRACE_ATTACH` 会向目标发 `SIGSTOP`，目标可能进入 **group-stop**；
  `PTRACE_SEIZE` 不发送停止信号，需 `PTRACE_INTERRUPT` 才停止。
  选用哪种、以及 group-stop 的 `waitpid` 状态如何识别，`[仍需实测]`。
- 多线程语义是「逐线程 attach + 逐线程 waitpid」，不是一次 attach 全进程；
  `[仍需实测]` 逐线程停止的完成顺序、是否出现 `PTRACE_EVENT_STOP`。
- `PTRACE_O_EXITKILL` 可选：tracer 崩溃时杀死 tracee，是否启用需产品决策
  `[仍需实测]`。
- 单 tracer 约束：同一 tracee 已被别的 tracer attach 时，内核返回 `EPERM`
  （而非 `EBUSY`），因此 `AlreadyAttached` 只能由本进程句柄表判断；
  `[仍需实测]`。
- Android `untrusted_app` 可能直接 `EPERM`；root / `run-as` / debuggable
  App / 同 uid 的差异 `[仍需实测]`。

### 2.2 `mb_ptrace_detach(handle) -> int32`

1. 遍历句柄保存的 TID 列表，对每个 TID `ptrace(PTRACE_DETACH, tid, 0, 0)`。
2. `ESRCH`（线程已退出）视为**已释放**，继续处理其余 TID；`EINTR` 重试。
3. 全部处理完 `free(tid[])`，释放句柄；返回 `0`。
4. 句柄已失效（重复 detach / 悬挂）返回 `-8`；真实路径同样以句柄表判重，
   **不得**二次 `PTRACE_DETACH`。

`[仍需实测]`：主线程与工作线程的 detach 顺序、detach 后目标是否恢复运行、
group-stop 下 detach 的行为、部分线程已退出时的返回值取舍。

### 2.3 `mb_ptrace_read_mem(handle, address, dst, length) -> int32`

设计为**逐段调用**（MoonBit 侧已按 4 KiB 分段，见 §3）：

1. 对段 `[seg.address, seg.address + seg.length)` 构造单个 `iovec`：
   `local = {dst + seg.offset, seg.length}`，`remote = {seg.address, seg.length}`。
2. `process_vm_readv(pid, &local, 1, &remote, 1, 0)`。
3. 返回值 `n`：
   - `n == seg.length` → 成功；
   - `0 < n < seg.length` → **部分读**，返回 `n`，由 MoonBit 层按
     「整体失败」收口（不静默截断）；
   - `-1` → 按 `errno` 返回 `-1000 - errno`。
4. 降级链（仅在 `ENOSYS` / `EPERM` 时）：`/proc/<pid>/mem` 的
   `pread(fd, dst, len, address)` → `PTRACE_PEEKDATA` 逐字读。
   `[仍需实测]` 每级的行为与 errno。

约束（`[仅据文档]` + `[仍需实测]`）：

- `process_vm_readv` 的 `iovec` 个数上限 `IOV_MAX`（Linux 通常 1024），
  总长度受 `ssize_t` 限制；本设计每段一个 iovec，天然低于上限。
- 一个 iovec 可以跨页；但跨到未映射页会整体 `EFAULT`，因此分段是
  **定位失败页**与**避免一个坏页毁掉整个请求**的前提。
- 对不可读页（`PROT_NONE`）返回 `EFAULT`；对只写页同样 `EFAULT`。
- `/proc/<pid>/mem` 需要 `ptrace` 权限且受 `ptrace_scope` 约束。
- `PTRACE_PEEKDATA` 以 word 为单位、返回 `-1` 时需清 `errno` 区分真实值；
  未对齐地址在不同架构上行为不同 `[仍需实测]`。

### 2.4 `mb_ptrace_write_mem(handle, address, src, length) -> int32`

1. 逐段 `process_vm_writev(pid, &local, 1, &remote, 1, 0)`，`src` 为
   `#borrow`，C 侧只读。
2. 部分写 / `errno` 处理同 §2.3。
3. 降级链：`/proc/<pid>/mem` 的 `pwrite` → `PTRACE_POKEDATA`（仅 word，
   需 read-modify-write 处理首尾非对齐字节）`[仍需实测]`。
4. **不做隐式 `mprotect`**（默认策略，见 §4）；只读页写入返回 `EFAULT` /
   `EPERM`，由 MoonBit 层映射为 `WriteFailed` 并在消息中提示 W^X / 权限。

### 2.5 `mb_ptrace_step(handle) -> int32`

1. 选一个当前处于 ptrace-stop 的 TID（单线程控制模型下通常是主线程）。
2. `ptrace(PTRACE_SINGLESTEP, tid, 0, 0)`；`EINTR` 重试。
3. `waitpid(tid, &st, __WALL)`；`WIFSTOPPED` 才成功，`WIFEXITED`/`WIFSIGNALED`
   映射为 `StepFailed` / `ProcessNotFound`。
4. 返回 `0`；真正的「一条指令」边界由架构决定。

`[仍需实测]`：

- ARM64 上单步的指令边界（含 IT 块、SVC、原子指令）需要反汇编判断，
  本库明确非目标；只能保证「内核报告一次单步停止」。
- 目标收到信号时的 `PTRACE_SINGLESTEP` 语义：是否注入信号、如何转发，
  需按 `PTRACE_SINGLESTEP` 的 `data` 参数设计；本轮不实现信号转发。
- 多线程下「单步哪个线程」没有唯一答案；单线程控制模型下调用方需
  自行保证目标只有主线程或显式选择 TID `[仍需实测]`。

### 2.6 `mb_ptrace_read_maps(pid, dst, capacity) -> int32`

1. 打开并读取 `/proc/<pid>/maps` 全文（`read` 循环，处理 `EINTR`）；
   文本长度用 `snprintf` 语义返回所需长度。
2. 读取 `/proc/<pid>/task` 目录，逐 TID 读 `/proc/<pid>/task/<tid>/stat`
   取 `comm` 与 `state`，按现有 `__tasks__` 协议拼接
   `<tid>\t<name>\t<state>\n`。
3. `capacity == 0` 仍作为 attach 前就绪性探测（权限/存在性），不打日志、
   不写入调用方缓冲。
4. 文本在读取期间可能变化（进程创建/退出/映射变化）；本库按
   「一次快照」语义处理，不保证与后续 syscall 一致 `[仍需实测]`。

`[仍需实测]`：不同内核字段差异、`comm` 含空格/括号、`stat` 的 `state`
取值、Android `/proc` 可见性、SELinux 对 `/proc/<pid>/task` 的限制。

### 2.7 `mb_ptrace_task_count(pid) -> int32`

`opendir("/proc/<pid>/task")` 数条目（跳过 `.`/`..`）；失败按 errno 映射。
与 §2.6 的 task 段做交叉校验（数量不一致 → `ThreadEnumerateFailed`），
防止读取期间线程增减造成静默错配。`[仍需实测]` 目录枚举的权限与竞态。

---

## 3. 跨页 / 部分读写拆分（已实现的部分）

### 3.1 算法

`../access_plan.mbt` 的 `plan_access(kind, address, length, page_size)`：

- 从 `address` 起，每次取 `min(页尾距离, 剩余长度)` 作为一段；
- 段记录 `{address, length, offset}`，`offset` 是段在请求内的偏移；
- 段按地址升序、首尾相接，总长等于请求长度；
- `length == 0` 返回空计划；`length < 0` / `page_size <= 0` /
  `address + length` 溢出 → `ReadFailed`/`WriteFailed`（按方向）；
- 段数上限 `MAX_ACCESS_SEGMENTS = 65536`（4 KiB 粒度 ≈ 256 MiB），
  超限 fail-closed，不截断。

示例（`page_size = 0x1000`）：

| 请求 | 段 |
|---|---|
| `addr=0x1000, len=0x100` | `(0x1000, 0x100, off 0)` |
| `addr=0xFF8, len=0x18` | `(0xFF8, 8, 0)`, `(0x1000, 0x10, 8)` |
| `addr=0xFFF, len=0x2001` | `(0xFFF, 1, 0)`, `(0x1000, 0x1000, 1)`, `(0x2000, 0x1000, 0x1001)` |
| `addr=任意, len=0` | 空 |

### 3.2 与 `read_bytes` / `write_bytes` 的接线

- `Target::read_bytes`：为每段分配临时 `FixedArray[Byte]`，调用 shim，
  校验返回 `== 段长`，再 `blit_from_bytes` 拼进结果；任一段失败立即
  `raise`，**不返回部分结果**。
- `Target::write_bytes`：按 `seg.offset` 切出 `Bytes` 片段逐段调用；
  任一段失败立即 `raise`。
- 失败错误携带**失败段**的地址/长度与段序号（例：
  `ReadFailed(0x11000, 8, "read segment 2/2 (status -7)")`），
  便于设备轮定位坏页。
- `[已复验-本地等价]`：9 项分段计划白盒测试 + 2 项跨页/跨区间黑盒失败测试。

### 3.3 粒度与真实页大小

- 采用 **4 KiB 保守粒度**：真实页大小若为 16 KiB / 64 KiB（arm64），
  4 KiB 边界是其子集，**永远不会跨真实页**，只增加 syscall 次数。
- 设备轮应由 C shim 用 `sysconf(_SC_PAGESIZE)` 返回真实页大小，并在
  MoonBit 侧按真实值分段（可选；4 KiB 始终正确）。`[仍需实测]`
- 不采用「一个 iovec 覆盖整个请求」的原因：`EFAULT` 无法定位坏页，
  且部分读写无法与「整体失败」契约对齐；内核也允许一个 iovec 跨多个
  VMA，但任一 VMA 不可访问即整体失败 `[仍需实测]`。

### 3.4 部分读写契约

- 本库公开契约是**全有或全无**：`read_bytes` 成功返回完整 `length`，
  否则 `ReadFailed`；`write_bytes` 同理。
- C shim 可以返回 `0 < n < length`（真实内核的部分读写）；MoonBit 层
  显式识别为 `partial read/write at segment ...` 并报错，绝不静默截断。
- 若未来需要「尽力读」语义，应新增独立 API，而不是改变现有契约
  （API 冻结语义见工作区 `../../COMPATIBILITY.md` §10）。

---

## 4. `mprotect` 写入策略（设计侧）

### 4.1 事实与约束

- `process_vm_writev` / `/proc/<pid>/mem` 的 `pwrite` 都**遵守目标页权限**：
  对只读页（`r-xp`、`r--p`、`r--s`）写入返回 `EFAULT` 或 `EPERM`，
  **不会**临时提升权限 `[仅据文档]` `[仍需实测]`。
- `ptrace(PTRACE_POKEDATA)` 同样受页权限约束（写只读页会失败）`[仍需实测]`。
- W^X / SELinux `execmod` / Android 的 `PROT_EXEC` 限制使
  「先 `mprotect(PROT_WRITE|PROT_EXEC)` 再写」在 `untrusted_app` 下
  可能直接 `EPERM`，且属于侵入性修改 `[仍需实测]`。

### 4.2 默认策略：不做隐式 `mprotect`（fail-closed）

- `write_bytes` 的公开契约是「调用方保证目标页可写」（见 `API.md`）。
- 真实转发层**默认不修改**目标页权限：
  - 写只读页 → 立即 `WriteFailed`，消息包含 W^X / 权限候选原因；
  - 不尝试 `mprotect`，不注入代码，不改变目标内存布局。
- 理由：静默改权限会破坏目标进程安全假设、可能触发 SELinux 审计/崩溃，
  且与「轻量、无侵入」定位冲突。

### 4.3 可选策略（未来 opt-in，未实现）

若要写只读页，需要**远程系统调用注入**：

1. `PTRACE_GETREGS` 保存寄存器；
2. 在可写可执行页写入 `mprotect` / `mmap` 桩（或复用 `__NR_mprotect`
   的 syscall 指令序列）；
3. 设置 PC/参数，`PTRACE_SINGLESTEP` 执行，读返回值；
4. 写入数据后恢复原权限与寄存器。

风险：架构相关（x86-64 / arm64 / armv7 指令编码不同）、需要可执行页
（W^X 下可能不可得）、会留下可观测痕迹、失败可能使目标崩溃。
**本轮不实现**，仅登记设计；是否提供 opt-in API 由后续 ADR 裁决
`[仍需实测]`。

### 4.4 设备轮验证清单

- [ ] `process_vm_writev` 写 `r-xp` 页的实际 errno；
- [ ] 写 `r--s` 共享页的实际 errno；
- [ ] `mprotect` 注入在 `untrusted_app` / root 下的可行性；
- [ ] 写后是否需要 `__builtin___clear_cache` / 指令缓存刷新（代码页）；
- [ ] SELinux 审计日志与 `execmod` 拒绝。

均 `[仍需实测]`。

---

## 5. 多线程 attach 逐线程停止语义（设计侧）

### 5.1 语义

- Linux 的 `ptrace` 是**按线程（TID）**attach 的；attach 进程只 attach
  主线程不会自动停止其他线程。
- 本库的 `attach` 目标是「停住目标进程的所有线程」：
  1. 枚举 `/proc/<pid>/task` 得到 TID 集合；
  2. 逐 TID attach + waitpid，直到每个 TID 都处于 ptrace-stop；
  3. 处理枚举后新建线程（`PTRACE_O_TRACECLONE` + 重新枚举）；
  4. 任一 TID 失败 → 回滚已 attach 的 TID，整体失败。
- 单线程控制模型不变：`Target` 非线程安全，跨线程调用由调用方串行化；
  一个 tracee 只能有一个 tracer。

### 5.2 停止状态判定

| 场景 | 设计判定 | 证据 |
|---|---|---|
| `PTRACE_ATTACH` 后 `waitpid` | `WIFSTOPPED` + `WSTOPSIG == SIGSTOP`（可能 group-stop） | `[仍需实测]` |
| `PTRACE_SEIZE` + `PTRACE_INTERRUPT` | `WIFSTOPPED` + `PTRACE_EVENT_STOP` | `[仍需实测]` |
| 线程已自行停止（`SIGSTOP`） | 可能不产生新的 stop 事件 | `[仍需实测]` |
| 线程正在 fork/clone | `PTRACE_EVENT_CLONE/FORK`，需 `waitpid` 新 TID | `[仍需实测]` |
| 线程在枚举与 attach 间退出 | `ESRCH`，视为已终止并从集合移除 | `[仍需实测]` |
| attach 期间新建线程 | 重新枚举 + `TRACECLONE` 事件 | `[仍需实测]` |

### 5.3 detach 语义

- 对每个仍存活的 TID `PTRACE_DETACH`；`ESRCH` 视为已退出。
- 是否先恢复主线程、是否向目标注入信号、group-stop 下是否需要
  `PTRACE_LISTEN`/`SIGCONT` 恢复，均 `[仍需实测]`。
- 重复 detach 必须返回明确错误（`NotAttached`），不二次释放。

### 5.4 并发边界

- `Target` 无锁；同一 `Target` 的并发调用未定义。
- 两个进程同时 attach 同一 tracee：内核拒绝第二个（`EPERM`），
  本库映射为 `AttachDenied` `[仍需实测]`。
- `threads()` 的 `/proc/<pid>/task` 读取与 attach 状态可并存，
  但读取期间线程可能变化，已用 `task_count` 交叉校验 `[仍需实测]`。

---

## 6. `waitpid` 细节（设计侧）

真实转发层的每次等待都必须：

1. 使用 `waitpid(tid, &status, __WALL)`（`__WALL` 让 clone 线程也可等待；
   不用 `__WCLONE`）`[仅据文档]`。
2. `EINTR` 重试；不把 `EINTR` 当失败。
3. `ECHILD` → 目标已不是本 tracer 的子进程 / 已退出 → `ProcessNotFound`
   或 `DetachFailed`（按上下文）。
4. 状态解码：
   - `WIFSTOPPED`：ptrace-stop / group-stop / 信号 stop；
   - `WIFEXITED`：目标退出 → `ProcessNotFound` / `StepFailed`；
   - `WIFSIGNALED`：目标被信号杀死 → 同上；
   - `WSTOPSIG == SIGTRAP`：可能对应 `PTRACE_EVENT_*`，需
     `status >> 16` 取 event。
5. 不做忙等：`waitpid` 阻塞等待，或 `WNOHANG` + 外部超时；
   本库当前无超时参数，设备轮需确认阻塞边界 `[仍需实测]`。
6. attach 期间若有 `SIGCHLD` 处理 / `SA_NOCLDSTOP`，需避免与宿主
   信号处理竞争 `[仍需实测]`。

---

## 7. 内核差异与降级路径（设计侧）

### 7.1 能力矩阵

| 能力 | 内核/平台 | 缺失时降级 | 证据 |
|---|---|---|---|
| `process_vm_readv` / `writev` | Linux ≥ 3.2，glibc/bionic 提供 | `ENOSYS` → `/proc/<pid>/mem` `pread`/`pwrite` → `PTRACE_PEEKDATA`/`POKEDATA` | `[仅据文档]` / `[仍需实测]` |
| `PTRACE_SEIZE` / `INTERRUPT` | Linux ≥ 3.4 | `EINVAL`/`ENOSYS` → `PTRACE_ATTACH` | `[仅据文档]` / `[仍需实测]` |
| `/proc/<pid>/mem` | Linux ≥ 3.2（读/写） | `PTRACE_PEEKDATA`/`POKEDATA` | `[仅据文档]` / `[仍需实测]` |
| `PTRACE_O_TRACECLONE` | Linux ≥ 2.5.46 | 无 → attach 后重新枚举 | `[仅据文档]` / `[仍需实测]` |
| Yama `ptrace_scope` | Linux ≥ 3.4（可选） | 无 Yama → 仅 DAC/SELinux | `[仅据文档]` / `[仍需实测]` |
| 16 KiB / 64 KiB 页（arm64） | 内核配置相关 | 4 KiB 保守分段始终正确 | `[仍需实测]` |
| 32 位 compat tracee | x86-64 / arm64 内核 | 需 `__WALL` + compat 寄存器布局 | `[仍需实测]` |
| Android SELinux 域 | Android 4.4+ | 无降级；`EPERM`/`EACCES` → 显式错误 | `[仍需实测]` |

### 7.2 降级决策树（读/写）

```
process_vm_* 调用
  ├─ 成功 → 返回
  ├─ EINTR → 重试（C 侧，有限次）
  ├─ ENOSYS / EPERM(内核不支持) → /proc/<pid>/mem pread/pwrite
  │     ├─ 成功 → 返回
  │     ├─ EPERM / EACCES → PTRACE_PEEKDATA/POKEDATA（仅 word；读写需 RMW）
  │     └─ 其他 errno → -1000 - errno
  └─ 其他 errno → -1000 - errno
```

- 降级**不改变**公开语义：仍然全有或全无；仍按 4 KiB 分段。
- 每次降级都记录实际路径到句柄（供诊断/CLI `--info` 可选输出）
  `[仍需实测]`。
- 若所有级都失败 → `UnsupportedKernel`（`ENOSYS`）或方向错误
  （`EFAULT`/`EIO`），**绝不**伪造成功。

### 7.3 内核差异风险

- `PTRACE_GETREGSET` / `PTRACE_SETREGSET` 的寄存器布局随架构不同；
  未来远程 syscall 注入需要逐架构实现 `[仍需实测]`。
- Android 内核可能裁剪 `/proc/<pid>/task/<tid>/stat` 字段 `[仍需实测]`。
- `seccomp` 可能拦截 `process_vm_*` / `ptrace`，表现为 `EPERM`
  而非 `ENOSYS`，需在错误消息中提示 `[仍需实测]`。
- `kernel.yama.ptrace_scope` 取值 0–3 对 attach 的影响：
  `0` 宽松、`1` 仅父子、`2` 仅 CAP_SYS_PTRACE、`3` 完全禁止
  `[仅据文档]` `[仍需实测]`。

---

## 8. SELinux / 权限模型（设计侧）

- Android `untrusted_app` 域默认禁止 `ptrace` 其他 App；可 attach 的
  典型条件：root、`debuggable` 且同 uid、`run-as`、系统域
  `[仍需实测]`。
- 错误面：SELinux 拒绝通常表现为 `EPERM` / `EACCES`，**没有独立 errno**；
  因此 `SelinuxDenied` 只能由显式探测（如读取
  `/proc/self/attr/current`、`dmesg`/`logcat` 审计）产生，本库本轮
  不实现该探测 `[仍需实测]`。
- `ptrace_scope` 与 SELinux 可能叠加；错误消息应同时列出两者，
  避免误导用户只改一个开关。
- CLI 在真实设备上应把 `PtraceError` 原样打印（含 errno 候选原因），
  不吞错、不改写为成功。

---

## 9. 测试与证据计划

### 9.1 本轮已完成的桌面验证（`[已复验-本地等价]`）

| 层 | 测试 |
|---|---|
| 分段计划 | 单页 / 跨页 / 页末 / 多页覆盖 / 零长度 / 负长度 / 非法页大小 / 溢出 / 上限 |
| 端到端分段 | 多页 fixture（stub pid 4243）跨页读/写拼接、maps/threads 隔离 |
| errno 分类 | 通道边界 + 读 / 写 / attach / detach / step / `/proc` / 线程 + 状态包装 |
| stub fail-closed | detach 后 maps/threads、跨区间读、只读页写、零长度、失败 attach 不留句柄 |
| CLI | 子命令解析、数字格式、用法错误、退出码 0/1/2、重复 attach/detach 句柄复用 |
| 基线 | 既有 18 项测试零删改，全部仍通过（总 49） |

### 9.2 设备轮（E5 解禁后，均 `[仍需实测]`）

1. Linux x86-64 桌面：attach → maps → read → write → step → threads →
   detach 全链路；记录 errno 与降级路径。
2. 多线程目标（pthread 创建 N 线程）：验证逐线程停止、线程创建竞态、
   detach 恢复。
3. 跨页读/写：真实 4 KiB / 16 KiB 页；跨未映射页的 `EFAULT` 定位。
4. W^X：只读代码页写入的实际 errno；`mprotect` 注入可行性。
5. Android arm64 / armv7：SELinux 域、`ptrace_scope`、`/proc` 可见性、
   `process_vm_*` 可用性。
6. CLI 在设备上的端到端退出码与错误文本。
7. 真实页大小（`sysconf`）与 4 KiB 保守分段的 syscall 次数对比。

### 9.3 记录纪律

- 未执行的项目一律保留 `[仍需实测]`，不得写成「已跑通」。
- 每个实测项记录：命令、退出码、errno、内核版本、Android API/ABI、
  SELinux 模式、是否 root。
- 失败项登记为缺口（而不是删除测试）。

---

## 10. 未决问题 / 待验证（登记）

| # | 问题 | 状态 |
|---|---|---|
| F1 | `PTRACE_SEIZE` vs `PTRACE_ATTACH` 的最终选择与 group-stop 处理 | `[仍需实测]` |
| F2 | 多线程 attach 的逐线程停止顺序与 `TRACECLONE` 竞态 | `[仍需实测]` |
| F3 | `process_vm_*` 部分读写的确切行为与降级 errno | `[仍需实测]` |
| F4 | 只读页写入的 errno（`EFAULT` vs `EPERM`）与 `mprotect` 注入可行性 | `[仍需实测]` |
| F5 | Android `untrusted_app` / `ptrace_scope` 的实际限制 | `[仍需实测]`（E5） |
| F6 | arm64 16 KiB/64 KiB 页与 4 KiB 分段的最优粒度 | `[仍需实测]` |
| F7 | 32 位 compat tracee 的寄存器/等待语义 | `[仍需实测]` |
| F8 | `/proc/<pid>/maps` / `task` 的内核字段差异 | `[仍需实测]` |
| F9 | CLI 在真实设备上的输出/退出码一致性 | `[仍需实测]` |

---

## References

- Linux `ptrace(2)`：<https://man7.org/linux/man-pages/man2/ptrace.2.html>
- `process_vm_readv(2)`：<https://man7.org/linux/man-pages/man2/process_vm_readv.2.html>
- `waitpid(2)`：<https://man7.org/linux/man-pages/man2/waitpid.2.html>
- `proc(5)`（`/proc/<pid>/maps`、`task`）：<https://man7.org/linux/man-pages/man5/proc.5.html>
- Yama LSM：<https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html>
- 本仓库：`DESIGN.md`（设计契约）· `API.md`（公开接口）· `DECISIONS.md`（决策记录）·
  `../access_plan.mbt` / `../errno_map.mbt`（本轮纯逻辑实现）· `../stub/ptrace_stub.c`（桌面 stub）
