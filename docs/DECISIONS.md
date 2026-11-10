# ptrace_lite · 设计决策记录（DECISIONS.md）

> 本文是本库设计决策的**自足记录**（每条按「背景 → 决策 → 理由 → 后果」展开），内容已全部内联，**不引用本仓库之外的任何文件**。配套文档：`../README.md`（概览与验收）、`DESIGN.md`（设计契约）、`API.md`（公开接口）。

## 1. 轻量路线选型：只封装 libc ptrace / process_vm_* 与 /proc 解析

**背景**：动态侧验证需要在受限设备上 attach 目标进程、读取内存与 maps。2026-11-06 检索 mooncakes.io，`ptrace` 关键词的两个注册表命中均为无关包——进程注入与控制能力在 MoonBit 生态完全空白，需要自研封装。候选路线有二：

- 封装 frida-gum devkit：许可为 **wxWindows Library Licence 3.1**（含「可按自己的条款分发基于该库的二进制对象代码」例外），但其 `subprojects/*.wrap` 打包约 15 个上游组件（capstone / glib / quickjs / openssl / v8 / xz 等），许可须逐项核对、上线前须法务复核；devkit 体积数 MB；Android 注入依赖 root 或 `PTRACE_ATTACH` 权限。
- 更小替代方案调研：ShadowHook / bhook / xHook（均 MIT、免 root）、Dobby（Apache-2.0）、And64InlineHook（MIT）均比 gum 小且免 root；LSPlant 为 LGPL-3.0 且无静态链接例外，合规负担更重。若只需函数级 inline hook，存在比 gum 更小的方案。

**决策**：本库**只封装 libc `ptrace` / `process_vm_readv` / `process_vm_writev` / `waitpid` 与 `/proc/<pid>/maps`、`/proc/<pid>/task` 文本解析**；不引入 frida-gum devkit，不链接/下载任何第三方库。本库作为动态侧验证的**先行路径**；与 `frida_gum_ffi` **互斥备选、零互相 import**，运行时二选一由**组合根**（未来应用工程中的适配代码，不是本仓库模块）决定。抽象 trait 留在各自模块内，不新建公共抽象模块。

**理由**：

- 2026-11-06 检索 mooncakes.io，`ptrace` 无可用包；比 frida-gum **少一层许可审查**（无 wxWindows 3.1 许可门禁）、体积最小，是「更小替代方案」判据的直接落地。
- `/proc` 文本解析可写成纯 MoonBit 纯函数（见本文第 6 节），先在桌面验证「动态侧是否可行」，不等设备与 root。
- 排序判据（是否阻塞交付 / 是否支撑动态验证闭环 / 可行性与许可 / 维护与可测 / 是否有更小替代）五项综合评估下，本库胜出为动态侧验证的首选先行路径；frida-gum 路线因「许可逐项审查」与「更小替代方案评估」两道门禁未解除而排后。

**后果**：

- 正面：零第三方许可负担（仅调用 libc 系统调用封装）；桌面即可构建、测试；动态闭环可先行验证。
- 负面：无 inline hook、无回调（见本文第 3 节），无法覆盖函数级参数观测。若后续确需 Java 方法 hook 或 Stalker 级插桩，仍需引入 frida-gum + frida-java-bridge/ART 方案，届时须先完成许可逐项审查。
- 互斥备选约束：两库零互相 import、组合根二选一；`ptrace_lite::MemoryRegion` 与 `frida_gum_ffi::MemoryRegion` 结构同构但名义类型不同（见本文第 5 节）。

## 2. 零本地模块 import 与组合根二选一

**背景**：本库处于「静态线索（apk / axml / dex）→ 动态验证」链路的动态侧，但各模块均为独立 MoonBit 模块（各自 `../moon.mod`）。编译期互相 import 会造成循环依赖风险；`#external` 句柄跨模块传递会泄漏实现细节。

**决策**：本库**不 import `pose` / `apk` / `axml` / `dex` / 任何本地模块**；`#external` 句柄（`TraceeRaw`）永不跨模块传递，只留在本模块内部。跨模块交互只经组合根传中性纯值（`Pid` / `Address` / `Bytes` / `MemoryRegion` 等）。与 `frida_gum_ffi` 的二选一由组合根决定，不新建公共模块、不新建公共抽象层。

**理由**：零 import 使每个模块可独立 `moon check` / `moon build` / `moon test`，避免模块循环依赖；名义类型边界迫使公开 API 写成中性值类型，天然满足「后端可替换、实现细节不泄漏」。

**后果**：组合根需少量显式适配代码（值类型转换 + 后端选择）；上层线索关联逻辑不依赖具体插桩后端；本库公开面只含值类型与 `MemoryView` trait。

## 3. 无回调设计：不触发「被钩线程执行 MoonBit 闭包」的线程安全风险

**背景**：frida-gum 的 `on_enter` / `on_leave` 回调同步跑在**被钩线程**且可重入；MoonBit 运行时在被钩线程上执行闭包的线程安全（GC、引用计数、重入）**未经实测**，是动态插桩路线中优先级最高的待验证风险。若回调签名使用 `FuncRef` + `#owned` 闭包，C shim 还须承担闭包引用计数与线程编排。

**决策**：本模块**没有回调**——不提供 hook 回调 shim，不需要 `FuncRef` / `#owned`。控制模型为**单线程**：`Target` 非线程安全，跨线程使用必须由调用方串行化（ptrace 语义上「一个 tracee 只能有一个 tracer」，也不允许并发 attach）。

**理由**：attach / peek / poke / 单步 / 线程枚举全部是调用方发起的同步系统调用，**不需要在被钩线程上执行 MoonBit 闭包**，因此不触发上述线程安全风险——这正是把它排在 frida-gum 路线之前的理由之一。

**后果**：能力边界明确为 attach / maps 解析 / peek-poke / 单步 / 线程枚举，不含函数级参数观测；不需要 JNI 线程编排与闭包生命周期管理，C shim 只做 ABI 转发；`parse_maps` 纯函数可并发调用。

## 4. `preferred_target` 由 wasm 改为 native

**背景**：骨架的 `../moon.mod` 默认 `preferred_target = "wasm"`。本机探针实测：在 wasm 目标下写 `extern "C" fn` 会被编译器以 `E4156`（`extern "C" is unsupported in wasm backend`）拒绝；而本库的全部价值就是外部 C ABI。

**决策**：`../moon.mod` 的 `preferred_target` 由 `"wasm"` 改为 `"native"`（唯一配置改动，不改目录结构、不改 `../moon.pkg` 其它字段）。

**理由**：wasm 后端无法表达 `extern "C"` 外部接口；native 目标下 `#external` / `extern "C"` / `#borrow` 声明可被真实编译器检查。

**后果**：默认构建走 native 后端；仅 Linux / Android 可运行（Windows 主机无 ptrace，MSVC native 亦无 ptrace）；native 后端无法把 `foreign_library` 导出为可链接 `.so`，设备侧集成需「C stub + 宿主 NDK/CMake」路径（见「平台与集成约束」）。

## 5. `MemoryView` trait：内存访问后端可替换

**背景**：组合根需要在插桩后端之间替换（本库 / frida-gum 封装 / ShadowHook、bhook 等更小替代 / 纯静态分析），而不改上层线索关联逻辑。

**决策**：定义 `MemoryView` trait（`read_bytes` / `write_bytes`），并提供 `pub impl MemoryView for Target`；trait 留在本模块（消费方侧），实现方不反向依赖。`ptrace_lite::MemoryRegion` 与 `frida_gum_ffi::MemoryRegion` **结构同构但名义类型不同（不同名）**，由组合根适配。

**理由**：trait 使内存访问后端可替换；MoonBit 是名义类型系统，两个模块各自定义同构值类型即可零互相 import；不新建公共抽象模块，避免循环依赖。

**后果**：`pub impl MemoryView for Target` 属公开面（API 冻结前已追认，见本文第 7 节）——冻结后新增 impl 即破坏性变更；上层只看到 `Target` / `MemoryRegion` / `ThreadInfo` / `Bytes`，看不到 fd、waitpid 状态、`process_vm_*` iovec 布局与 `/proc` 文本格式。

## 6. `/proc/maps` 解析为纯 MoonBit 纯函数

**背景**：动态验证需要 `/proc/<pid>/maps` 的内存区间视图。文本读取必须经 C shim（或设备侧 `/proc` 读取），但解析不必依赖它。

**决策**：解析写成纯函数 `parse_maps(text : String) -> Array[MemoryRegion] raise PtraceError`：无状态、不依赖 attach、可并发调用；畸形行显式报 `MapsParseFailed(行号, 消息)`，不 panic。

**理由**：纯函数可**桌面 golden 测试**——不需要 root、不需要 attach、可在 CI 跑；解析逻辑与 `/proc` 读取解耦后，内核差异只需在读取侧降级。

**后果**：`parse_maps` golden ×4 覆盖文件映射 / 匿名映射 / 权限位 / 缺 path / 偏移、device、inode / 64 位地址，另有畸形行负例；不同内核 `/proc/<pid>/maps` 的字段差异成为待验证风险（见「风险与待验证」）。

## 7. API 冻结前的四项收紧

API 冻结前对公开面做了四项收紧/追认，其余公开方法签名零变化：

1. **`Target.state` 收紧为 `priv` 私有字段 + 只读访问器 `Target::state()`**（字段级可见性可用，仅收紧该字段）——防止包外篡改状态机。
2. **七个 `mb_ptrace_*` shim 移出公开 API**（包私有、私有实现 ABI、非公共 API）——符号名与签名不变，后续真实 libc 对接无需改 ABI；直接调用 shim 的用例（capacity `-7`、stale handle `-8`）转白盒，**测试总数不变（18）**。
3. **追认 `pub impl MemoryView for Target` 为公开面**——冻结后新增 impl 即破坏性变更。
4. **`detach` 措辞统一**为「不会二次释放，重复调用返回明确错误（`NotAttached`）」。

**理由**：冻结前把「可收紧的可见性」一次收紧到位（私有化属允许的非破坏性变化），把已在 API 快照中出现的 impl 显式追认为公开面，避免冻结后出现隐性破坏性变更；detach 幂等语义统一为可断言的明确契约。

**后果**：公开面 = 9 个公开 API（`Target::{attach, state, maps, read_bytes, write_bytes, step, threads, detach}` + `parse_maps`）+ 值类型 + `MemoryView` trait + `PtraceError`（12 个错误构造）；7 个 shim 保持包私有 ABI，符号与签名稳定；测试 18 项不变（黑盒等价语义断言 + 白盒 shim ABI 断言）。

## 8. 风险与待验证

- **SELinux**：Android SELinux `untrusted_app` 域对 `PTRACE_ATTACH` 的实际限制**待设备实测**；错误模型已预留 `SelinuxDenied` / `AttachDenied`。
- **`kernel.yama.ptrace_scope`**：取值（0–3）对 attach 的实际影响**待实测**；同类工具的官方排错文档同样提示需要 root 或 `ptrace_scope = 0`。
- **W^X 页写入**：目标页写入受 W^X 限制（如 `mprotect(PROT_WRITE|PROT_EXEC)` 一类）的依据来自技术博客，**待实测**；`write_bytes` 由调用方保证目标页可写，mprotect 策略未定。
- **内核差异**：不同内核的 `/proc/<pid>/maps` 字段与 ptrace 细节差异；错误模型已预留 `UnsupportedKernel`。
- **设备测试基线缺口**：真实 APK 测试资产不在本仓库，设备集成测试缺少基线样本（目标 App 许可不明，未入库）。
- **多线程 attach 语义**：多线程 `PTRACE_ATTACH` 的逐线程停止语义、`/proc/<pid>/task` 在 attach 状态下的可读性，需设备实测。
- **ARM64 单步指令边界**：需要反汇编支持，属明确非目标。
- **真实 libc 转发**：当前 C shim 为项目内桌面 stub（`../stub/ptrace_stub.c`）；真实 libc `ptrace` / `process_vm_*` / `waitpid` 转发与设备实测留待 Linux / 设备阶段。

## 9. 平台与集成约束

- `preferred_target = "native"`；仅 Linux / Android；Windows 主机不可运行（无 ptrace，MSVC native 亦无 ptrace）。
- **native 后端无法把 `foreign_library` 导出为可链接 `.so`，设备侧需「C stub + 宿主 NDK/CMake」路径**：MoonBit 产物以 C 源码 / 对象形式进入宿主 NDK/CMake 工程链接，不存在「导出 .so 给宿主链接」的形态。
- 错误传播统一 `raise PtraceError`（12 个可判定错误构造）；C 侧状态码约定：`-1` 通用失败、`-2` 无此进程、`-3` 权限拒绝、`-4` SELinux 拒绝、`-5` 内核不支持、`-6` 已被本 tracer attach、`-7` 参数/地址非法、`-8` 句柄为空或已失效。真实转发层新增 `-1000 - errno` 通道（见本文第 11 节），与上述合成码隔离。

## 10. 跨页访问分段计划（4 KiB 保守粒度、全有或全无）

**背景**：真实 `process_vm_readv` / `process_vm_writev` 允许单个 iovec 跨页，但
跨到未映射/不可读页时只返回 `EFAULT`，无法定位坏页；同时内核可能返回部分读写
（`0 < n < length`），与公开 API「成功返回完整长度、否则报错」的契约冲突。
本机 Windows 无法实测真实内核行为，但分段算法本身是纯逻辑，可在桌面验证。

**决策**：新增包私有 `../access_plan.mbt`：

1. 以 **4 KiB 保守粒度**把 `[address, address + length)` 拆成不跨页的段，
   记录每段 `{address, length, offset}`；4 KiB 是 16 KiB/64 KiB 页的子集，
   永远不会跨真实页（只多 syscall）。
2. 段数上限 `65536`（≈256 MiB，4 KiB 粒度）fail-closed，超限报错而非截断。
3. `length < 0` / `page_size <= 0` / `address + length` 溢出 → 按方向映射
   `ReadFailed` / `WriteFailed`；零长度返回空计划（合法无操作）。
4. `Target::read_bytes` / `write_bytes` 逐段调用 shim；任一段失败立即
   `raise`，**不返回部分结果**；错误携带失败段地址/长度与段序号。
5. 真实页大小设备轮由 C shim `sysconf(_SC_PAGESIZE)` 校准（可选，4 KiB 始终正确）。

**理由**：纯逻辑可桌面测试；分段把 `EFAULT` 定位到页/段；全有或全无契约不因
真实内核的部分读写而改变；上限防止畸形大请求放大内存。

**后果**：正面——错误可定位、可测试、无需真实 libc；负面——多页请求的 syscall
次数增加（每页/每段一次），设备轮需评估性能；真实页大小与部分读写行为
`[仍需实测]`。

## 11. 真实 errno 通道与分类映射（`-1000 - errno`）

**背景**：stub 合成码 `-1..-8` 与 POSIX errno 数值冲突（`-2`：stub「无此进程」
vs errno `ENOENT`；`-3`/`-4`/`-5` 同样冲突）。若真实路径直接返回 `-errno`，
MoonBit 层无法区分「stub 合成码」与「真实 errno」，错误分类会串味。

**决策**：新增真实通道 `status = -1000 - errno`（`<= -1001`；有效 errno 1..4095），
由 `../errno_map.mbt` 解码；`-1..-999` 仍属 stub 合成码。分类映射（节选）：

- `ESRCH`/`ENOENT`/`ECHILD` → `ProcessNotFound`（按上下文）；
- `EPERM`/`EACCES` → `AttachDenied` / `ReadFailed` / `WriteFailed` / `StepFailed`
  / `ThreadEnumerateFailed`（消息列出 `ptrace_scope`、SELinux、W^X 候选）；
- `EFAULT` → `ReadFailed`/`WriteFailed`（bad address，带失败段）；
- `EIO` → 方向错误 / `/proc` 与线程枚举的 `UnsupportedKernel`；
- `EINVAL` → 方向错误 / `AttachDenied`；
- `ENOSYS` → attach/step/proc/thread 操作报 `UnsupportedKernel`；read/write 内存操作报方向错误（`ReadFailed`/`WriteFailed`）；
- `EINTR` → 显式错误（真实 shim 应重试，不得静默吞掉）；
- `EBUSY` → `AlreadyAttached`；未知 errno → 方向错误并带 errno。

**理由**：通道隔离使 stub 18 项基线零改动、真实路径可细粒度分类；
`SelinuxDenied` 不凭 errno 猜测（保留给 stub `-4`/显式探测），避免误导。

**后果**：正面——错误模型可扩展、测试可纯逻辑覆盖；负面——真实 shim 必须
正确编码 errno，且 `EPERM` 的三种成因仍无法自动区分；真实触发 `[仍需实测]`。

## 12. CLI 退出码契约（0/1/2）与 stub 后端

**背景**：库已具备 attach/maps/read/write/step 能力，但 `cmd/main` 仍是模板
`Hello`，无法作为诊断/演示入口；本仓库既有 CLI 已确立
`0=成功 / 1=运行失败 / 2=用法错误` 口径。

**决策**：`cmd/main` 落地 CLI 骨架：

- 子命令 `attach <pid>` / `maps <pid>` / `read <pid> <addr> <len>` /
  `write <pid> <addr> <hex>` / `step <pid>` / `--help`；
- 地址十六进制（可带 `0x`），长度十进制，写入字节为十六进制串（可空格分隔）；
- 退出码 `0` 成功 / `1` 库层 `PtraceError` / `2` 用法错误；错误信息走 stderr；
- 每个成功命令都显式 `detach`（唯一释放点），失败也尝试 detach；
- 桌面 stub 后端可跑（仅 pid 4242）；真实设备实测 `[仍需实测]`。

**理由**：退出码契约与本仓库其它 CLI 统一，便于脚本化；参数解析纯函数可白盒
测试；不新增库公开 API，不影响 API 快照。

**后果**：正面——库有了可运行的端到端入口与错误路径回归；负面——stub 只模拟
pid 4242，CLI 的真实价值仍需设备轮验证；帮助文本中的平台限制必须保留
`[仍需实测]` 标注。
