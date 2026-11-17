# ptrace_lite 进程控制契约开发文档

> 建立：2026-11-17 ｜ 状态：待开发 ｜ 适用仓库：本仓库（独立自包含）
> 配套文档：[2026-11-17-test-system-design.md](2026-11-17-test-system-design.md)（验收测试 ID `T-W*-*` 出自该文档）
> 本文所有「现状」结论均为 2026-11-17 对本仓库源码的实测核对，非转述历史文档。
> 五门禁 2026-11-17 实跑（开发前基线）：`moon check --deny-warn` 退出 0；`moon build` 退出 0（native 可执行文件产出）；`moon test` **49/49 通过、0 条 #skip**；`moon fmt --check` 退出 0；`moon info` 后 `git diff --exit-code -- pkg.generated.mbti cmd/main/pkg.generated.mbti` 退出 0（双快照零漂移）。工具链版本锁与 CI 断言一致，详见 CI 配置。
>
> 说明：本轮 P1 线索包含仓库外申报材料；其提交数、测试数与「后续」项一律按 P4 实测重核，本文只以「仓库外申报口径」泛称记录差异，不假定该材料在本仓库可访问、不回写。
>
> **裁决落地记录（2026-11-17，用户采纳推荐 A）**：W5-A 的 M5-1/M5-2 已落地为 `native/ptrace_real.c`（7 个 shim 同 ABI、真实 errno 通道 `-1000-errno`、`PTRACE_ATTACH/DETACH/SINGLESTEP`、`process_vm_readv/writev`、`/proc` 文本包）+ `tools/real-runner.sh` + `native/README-REAL.md`；默认 stub 构建与 49/49 测试不受影响。M5-3（Linux/Android 真机、SELinux/`ptrace_scope`/W^X、多线程停止）**未实测**，按 `[仍需实测]` 与显式 SKIPPED 登记；真实 C 文件在 2026-11-17 Windows/MSVC 主机未编译、未运行，不得表述为已跑通。

## 0. 现状基线（实测核对，开发前必读）

能力点清单（P1 基准，仓库自足文档 + 公开 API 面核对后确立）：

- F1 `parse_maps` 纯函数：`/proc/<pid>/maps` 文本 → `Array[MemoryRegion]`，含权限位/设备/inode/可选路径、排序与畸形行分类
- F2 `Target` 状态机与 `attach`/`detach` 生命周期（唯一释放点、重复 detach 明确拒绝）
- F3 `read_bytes`/`write_bytes` 与 `MemoryView` 契约（未 attach 拒绝、零长度无操作、分段读写）
- F4 跨页分段计划 `plan_access`（保守 4 KiB、上限 65,536 段、失败即整体失败）
- F5 `step` 单步与 `threads` 线程枚举（task 段解析 + `task_count` 交叉校验）
- F6 `PtraceError` 12 构造与双状态通道（stub 合成码 `-1..-999`、`-1000-errno` 真实通道预留）
- F7 7 个包私有 `extern "C"` shim 与桌面 stub（`#borrow` 所有权标注、状态码协议）
- F8 CLI 五个子命令与退出码 0/1/2 契约
- F9 非目标边界：真实 `ptrace`/`process_vm`/`waitpid` 链路未实现、未编译、未运行；无回调插桩、无符号解析

非目标清单：真实 libc 转发与设备实测（E5）、多线程 attach 逐线程停止、隐式 `mprotect` 写入、内核差异自动降级、回调式插桩、符号解析；本仓库只交付桌面 stub 可验证的 MoonBit 层契约与纯逻辑。

### B# 基线事实表

| # | 事实（已实现/缺口/漂移，含细节） | 证据位置（文件+函数/行段） |
|---|---|---|
| B1 | 已实现：公开面 = 1 个顶层 `pub fn`（`parse_maps`）、`PtraceError` 12 变体 + `to_repr`、4 个 `pub(all)` struct + 1 个 enum、1 个 `#external` 类型 `TraceeRaw`、2 个类型别名、`MemoryView` trait、`Target` 8 方法 | `pkg.generated.mbti` L9–87 |
| B2 | 漂移（API 索引）：README §3 索引漏 `MemoryView` trait、`TraceeRaw` 外部类型、`Address`/`Pid` 别名、`PtraceError::to_repr`；自称「自动抽取 pub 声明行」但口径不完整 | README.md L30–47 ↔ `pkg.generated.mbti` L75–87 |
| B3 | 已实测：错误变体逐个数清为 **12**（申报口径 12 一致）；测试显式簿记 **12/12**，每变体均有直接变体名断言，无死变体 | `ptrace_lite.mbt` L77–90；`pkg.generated.mbti` L13–26；`*_test.mbt` / `*_wbtest.mbt` 变体名 Grep |
| B4 | 已实测：测试 **49/49**，文件分布 `access_plan_wbtest` 11 + `errno_map_wbtest` 7 + `ptrace_lite_failclosed_test` 5 + `ptrace_lite_segment_test` 3 + `ptrace_lite_test` 11 + `ptrace_lite_wbtest` 7 + `cmd/main/cli_wbtest` 5；`#skip` 全仓 0 条 | `moon test` 实跑；`grep -c '^test "'` 逐文件重数 |
| B5 | 已实测：五门禁全绿，双快照 `moon info` 前后无 diff；CLI 冒烟（`--help`/缺命令/未知命令/缺参/attach 失败/非法读写）输出与退出码在测试内实跑 | 2026-11-17 五门禁实跑；`cmd/main/cli_wbtest.mbt` L104–123 |
| B6 | 漂移（计数）：`git rev-list --count HEAD` = **15**，仓库外申报口径写 14；差异仅登记不回写 | 2026-11-17 `git rev-list --count HEAD` |
| B7 | 已实现：零第三方依赖；仅 `stub/ptrace_stub.c` 以 libc + 运行时头实现 7 个 shim；无 `tests/fixtures` 目录（测试为内嵌文本 + 程序化构造）；无模型/第三方二进制入库 | `moon.mod`；目录实测；`stub/ptrace_stub.c` L1–40 |
| B8 | 已实现（F1）：`parse_maps` 纯函数按空白分隔字段、perms 恰 4 字符 `[r-][w-][x-][ps]`、地址严格递增、dev `hex:hex` 校验后原文保留、inode 十进制带溢出防护、路径可含空格；结果按 `(start,end)` 升序；畸形行 `MapsParseFailed(行号,原因)`，末行换行空段忽略 | `maps_parser.mbt` L15–264；`ptrace_lite_test.mbt` L160–321 |
| B9 | 已实现（F2）：`Target.state` 为私有可变字段 + 只读访问器；`ensure_open` 只允许 `Attached`/`Stepping`；`detach` 是唯一释放点，重复调用 `NotAttached`，释放失败进入 `Failed` | `ptrace_lite.mbt` L65–72；`target.mbt` L73–78、L305–317 |
| B10 | 已实现（F3）：`read_bytes`/`write_bytes` 与 `pub impl MemoryView for Target` 共用 `target_*_bytes`；未 attach `NotAttached`；零长度合法无操作；读长度以参数为准、写长度以 `Bytes` 为准 | `target.mbt` L249–266、L326–412 |
| B11 | 已实现（F4）：`plan_access` 按 4 KiB 不跨页切段，段上限 65,536（256 MiB）；负长度/非法页大小/UInt64 地址溢出/超限均 `ReadFailed`/`WriteFailed`；任一段失败整体失败、部分读写报错，不截断 | `access_plan.mbt` L17–133；`target.mbt` L326–400；`access_plan_wbtest.mbt` 11 例 |
| B12 | 已实现（F5）：`step` 成功后进入 `Stepping`；`threads` 解析 `__tasks__` 段并逐行 `tid\tname\tstate`，与 `mb_ptrace_task_count` 交叉校验，不一致 `ThreadEnumerateFailed` | `target.mbt` L270–298、L150–197 |
| B13 | 已实现（F6）：状态码双通道：stub 合成码 `-1..-999` 与真实通道 `-1000-errno`；errno 分类覆盖 ESRCH/ENOENT/EPERM/EACCES/EFAULT/EIO/ENOSYS/EINTR/EBUSY/ECHILD/EINVAL；`EPERM/EACCES` 统一 `AttachDenied` 并列出候选原因，`EINTR` 显式报错不静默重试 | `errno_map.mbt` L1–385；`errno_map_wbtest.mbt` 7 例 |
| B14 | 已实现（F7）：7 个 `mb_ptrace_*` 均为包私有 `extern "C"`；`read_mem`/`write_mem`/`read_maps` 带 `#borrow` 所有权标注；`read_maps` 为 snprintf 语义（capacity=0 探测、返回所需长度），文本包为 `<maps>\n__tasks__\n<tasks>` | `ptrace_lite.mbt` L103–155；`target.mbt` L81–146；`stub/ptrace_stub.c` L9–39 |
| B15 | 已实现（F8）：CLI 五子命令 `attach/maps/read/write/step` + `--help`；退出码 0 成功 / 1 `PtraceError` / 2 用法错误；地址支持 `0x`/裸十六进制、字节串可含空白；13 条退出码断言含失败后再用无句柄泄漏 | `cmd/main/main.mbt` L19–37、L295–430；`cmd/main/cli_wbtest.mbt` L34–131 |
| B16 | 已实现（F9 的事实面）：真实 libc 转发在当前仓库**未实现、未编译、未运行**；桌面 stub 以模拟 pid（4242/4243/7001/7002/7003）触发各路径，4200 系列仅模拟；仓库内不存在真实转发 C 文件 | `stub/ptrace_stub.c` L25–37；目录实测；README.md L19–22 |
| B17 | 缺口（F9「后续」逐项核对）：真实 `ptrace`/`process_vm_*`/`waitpid` 转发与设备实测、多线程 attach、隐式 `mprotect`、内核差异降级、CLI 真实设备 E2E 均未实现；仓库外申报口径与 README 一致 | README.md L59–63；`pkg.generated.mbti` 无相关新增声明；目录实测 |
| B18 | 漂移（自包含）：源码注释引用了两个兄弟模块名作为「非目标」说明（分别涉及符号解析与插桩）；本仓库无对应 import，假定外部代码可访问，违反模块自包含约束（仅注释层） | `ptrace_lite.mbt` L9 |
| B19 | 漂移（引用实存性）：源码/测试/C stub 共 8 处引用本仓库内不存在的文档：设计约束文档 3 处、API 文档 4 处、API 冻结决策文档 1 处（README 已用「原」字承认规格搬迁，但代码/C 注释仍指向旧路径） | `access_plan.mbt` L9；`target.mbt` L366；`ptrace_lite.mbt` L160；`ptrace_lite_test.mbt` L5/L58；`stub/ptrace_stub.c` L7/L12；README.md L28 |
| B20 | 口径待调整：README L4 称「唯一说明文档」；本轮 docs 交付后须改为「唯一入口文档」并加索引 | README.md L4；本轮交付物 |
| B21 | 健壮性缺口（生命周期）：`Target::attach` 先取 C 句柄再做句柄有效性探测；探测失败路径直接抛错，未对该句柄调用 `mb_ptrace_detach`（stub 下仅返回有效句柄故未触发，真实转发下可能泄漏） | `target.mbt` L219–234；`errno_map.mbt` L340–354 |
| B22 | 健壮性缺口（无界解析）：`parse_maps` 对输入行数/总长度无上界，超大转储文本会线性分配 `MemoryRegion` 数组；当前仅十进制 inode 与十六进制字段有单项溢出防护 | `maps_parser.mbt` L227–264；对照 L41–61 |
| B23 | 观察（非缺陷）：`read_proc_text` 容量从 4096 起按 shim 返回所需长度扩容，最多重试 4 次后 `MapsParseFailed(0,"length unstable")`；失败进入声明错误类型而非静默截断 | `target.mbt` L87–110 |
| B24 | 观察（非缺陷）：stub 句柄槽 8 个且复用，反复 attach/detach 12 轮全绿；`step` 后仍允许读写（`ensure_open` 接受 `Stepping`），与 README 语义一致 | `stub/ptrace_stub.c` L136–161；`cmd/main/cli_wbtest.mbt` L127–131；`ptrace_lite_test.mbt` L58–60 |
| B25 | 许可与对标线索：仓库外申报口径称无第三方代码、仅参考内核接口规范；本仓库零外部依赖、零二进制资产，口径仅作线索 | 仓库外申报口径（仅作线索）；`moon.mod`；目录实测 |

F# → B# 覆盖：F1→B8/B22；F2→B9/B21；F3→B10；F4→B11；F5→B12；F6→B13/B3；F7→B14/B16；F8→B15；F9→B16/B17。

**对历史口径的修正**（以 2026-11-17 实测为准）：

1. 提交数：仓库外申报口径 14 → 实测 **15**（B6；不回写仓库外材料）。
2. 测试 **49/49**、错误变体 **12**、零 `#skip`、双快照无漂移均实测成立（B3/B4/B5）。
3. README API 索引不完整：漏 trait、外部类型、两个别名与 `to_repr`（B2）。
4. 源码注释与 C stub 仍引用不存在的旧文档路径（B19）；README「唯一说明文档」在 docs 交付后失效（B20）。
5. 「真实链路未实现/未编译/未运行」经目录与 stub 实测确认（B16/B17），不得表述为已跑通。
6. 新发现两处此前未登记缺口：attach 句柄探测失败未释放（B21）、`parse_maps` 输入无界（B22）。

## 1. 硬约束（每个工作包都必须满足）

1. API 冻结：`pkg.generated.mbti`（含 `cmd/main` 快照）为冻结基线，只允许纯加法；禁止给 4 个 `pub(all)` struct 与 `TargetState` 加字段/变体；禁止新增错误变体（`PtraceError` 12 变体冻结，破坏性需求走 ADR+用户裁决+CHANGELOG+主版本四件例外）；校验失败复用 `ReadFailed`/`WriteFailed`/`MapsParseFailed` 等既有变体；语义变更走新函数新类型防火墙（W6 及裁决后的 W5）。
2. 加法三件套：快照随源码同提交且 diff 纯加法 + `docs/CHANGELOG.md` 登记 + CI 快照门禁绿。
3. 依赖不动：零第三方依赖；工具链按 CI 版本断言锁定；7 个 shim 的符号名/签名/`#borrow` 约定与 `-1000-errno` 状态通道为冻结 ABI，真实转发层只能在同 ABI 内实现，不得改 MoonBit 侧公开签名。
4. 许可红线：真实 `.so`、第三方调试器/devkit、许可不明样本永不入库；真实设备验证只允许「仓库外本地路径 + SHA-256 登记 + 显式 SKIPPED」。
5. 五门禁全绿才可合入；`#skip`/SKIPPED/退出码 78 不得写成通过。fail-closed 修复（W3：探测失败即释放句柄）属行为增强而非契约破坏（变体集合与签名不变），须 CHANGELOG 显式登记 + 回归确认仅受影响样本变化。
6. 边界不变量：不实现符号解析、不实现 inline hook/回调插桩、不自动 `mprotect`、不把真实引擎句柄暴露到公开类型；桌面 stub 事实不得冒充内核事实。
7. 文档自包含：本文、配套文档、代码注释、CLI 帮助文本、C 注释与脚本不得引用工作区路径或兄弟模块符号（B18/B19 为现存违例，W1 清理）；仓库外申报口径只用泛称，不写路径、不回写。

## 2. 业界对标摘要（P2 结论，证据三级标注）

**渠道与限定**：2026-11-17 经公开 web 渠道（mooncakes 包页、官方/社区文档、搜索引擎）调研；mooncakes 站内搜索此前实测 422/SPA 无法穷举，本轮不冒充已穷举。「未见同类」限定为：**MoonBit 语言 + 「纯 MoonBit 值契约 + 私有 C shim + 桌面 stub 可验证 + 12 类错误语义」组合语义 + 2026-11-17 时点 + 上述公开渠道**。

| 能力（F#） | 本模块（B# 实测） | Milky2018/sysinfo（MoonBit） | libmem（C/C++ 跨进程内存库） | Python ctypes/raw ptrace | GDB / LLDB（CLI 工具） | procfs 类库（Rust，只读 /proc） |
|---|---|---|---|---|---|---|
| F1 maps 纯解析 | ✓ 独立纯函数 + 畸形行分类（B8） | ✗ 进程指标，不解析 maps 文本 | ◐ 内部解析 /proc，非公开纯 API | ✗ 无 | ◐ `info proc mappings`，非库 API | ✓ 结构化 /proc 读取，通常不保留原始文本语义 |
| F2 attach/状态机 | ✓ 四态 + 唯一释放点（B9） | ◐ `kill/wait` 等控制，无 attach 调试状态机 | ✓ attach/detach | ✓ 手工 ptrace 调用 | ✓ 内建 | ✗ 只读 |
| F3 内存读写契约 | ✓ `MemoryView` trait + 未 attach 拒绝（B10） | ✗ 无 | ✓ 读/写/分配/保护 | ✓ 手写 syscall | ✓ 命令式 | ✗ |
| F4 分段计划 | ✓ 4 KiB 保守切段 + 上限 fail-closed（B11） | n/a | ◐ 直接 process_vm 向量 I/O，不按页定位 | ✗ 通常单字读写 | ◐ 内部处理 | n/a |
| F5 step/线程枚举 | ✓ 单步 + task 交叉校验（B12） | ◐ 线程信息只读 | ✓ 线程枚举 | ✓ 手工 | ✓ | ◐ 只读 task |
| F6 错误分类 | ✓ 12 变体 + 双状态通道（B13/B3） | ◐ Err/None 降级，非 errno 分类 | ◐ C 返回值/错误码 | ✗ 手工 errno | ◐ 人读错误 | ◐ io::Error |
| F7 可桌面验证的 stub | ✓ 7 shim + 模拟 pid（B14/B16） | ✓ native 无主机依赖的降级策略 | ✗ 需真实系统 | ◐ 需 Linux | ✗ 需真实进程 | ✓ 只读可测 |
| F8 CLI 契约 | ✓ 5 子命令 + 0/1/2（B15） | ✗ 库 | ◐ 工具形态各异 | ✗ | ✓ 命令丰富 | ✗ |
| F9 真实内核链路 | ✗ 明确未实现（B16/B17） | ✓ 进程控制 API 可用 | ✓ 真实 ptrace/process_vm | ✓ 真实 | ✓ 真实 | ✓ 只读真实 |

- 证据等级：MoonBit 生态候选的 API 面与 `native` 限定 [仅据本轮 mooncakes 包页核验]（版本/star/维护状态 [需联网核实]）；`ptrace(2)`/`process_vm_readv(2)` 的语义与权限约束、`ptrace_scope` 与 CAP_SYS_PTRACE 讨论 [已知常识]（内核版本差异 [需联网核实]）；libmem 的 Linux 实现结构来自本轮公开文档镜像 [需联网核实]；GDB/LLDB 能力 [已知常识]；Python 无标准 ptrace 库、多为 ctypes 封装 [需联网核实]。本模块全部列来自 2026-11-17 源码实测 [仅据本项目文档]。
- 最接近 1–3 名与重叠度：**同生态系统信息库**（进程枚举/信号/等待，重叠在「进程可观测面」，但无 attach/内存读写/errno 分类）；**libmem**（重叠最高：attach + 内存读写 + 线程枚举 + 页保护，但它是真实系统库且依赖 C/C++ 工具链）；**raw ptrace/ctypes**（控制权等价但无值契约、无 stub 可测层）。
- 差异化判断：本模块是「**契约先行、事实分层**」路线：先用桌面 stub 把状态机、分段计划、错误分类和 CLI 契约全部锁进纯 MoonBit 测试面，再把真实内核实现留作同 ABI 的替换点。组合语义（MoonBit + native + 私有 shim + stub 可验证 + 12 类错误）在调研渠道内未见同类。
- 缺失能力清单：已声明非目标 = 真实转发/设备实测/多线程停止/回调插桩/符号解析/隐式 mprotect；真缺口 = attach 探测失败释放（B21）、`parse_maps` 无界（B22）、文档与注释漂移（B2/B18/B19/B20）。

## 3. 边界裁决（P3 结论）

**本质职责（一句话）**：把目标进程的有限可观测面（`/proc` 文本、受控内存字节、单步与线程摘要）整理成**可分类错误、可单一释放的中性值**——只回答「目标是什么、操作失败属于哪一类」，永不回答「如何注入、如何绕权限、如何 hook」。

**边界判据**：是否停留在「纯解析/分段计划/状态机/错误分类 + 字节契约」层面，且副作用只经私有 shim、只由 `detach` 单点释放。满足者界内；需要真实内核权限、回调执行、符号/指令语义者界外。

| 灰区 | 判据结论 | 裁决 | 落点（W#） |
|---|---|---|---|
| G1 桌面 stub vs 真实转发 | 界内当前面：stub 是可测事实源；真实链路是同 ABI 替换点（B16） | 冻结 7 shim ABI 与公开 API；归属声明「stub 事实 ≠ 内核事实」；真实转发列为须裁决大工程 | W5（A 已落地 M5-1/2）、W2（golden 锁） |
| G2 `parse_maps` 与通用文本解析库 | 界内：maps 语义是本库职责 | 冻结现有签名与错误行号口径；无界输入走新函数防火墙，不改旧函数 | W6 |
| G3 跨页分段与真实页大小校准 | 界内纯逻辑（4 KiB 保守切分）；`sysconf(_SC_PAGESIZE)` 校准界外（shim/设备轮） | 冻结计划口径与 65,536 段上限；校准结论只进新实现，不反改旧计划 | W2、W5 |
| G4 `MemoryView` 与多后端切换 | 界内契约、界外实现（组合根持有后端） | 冻结 trait；后端注入一致性用本地替身验证，真实第二后端缺失显式 SKIPPED | W2 |
| G5 errno/SELinux/ptrace_scope 语义 | 分类标签界内；真实探测界外 | 冻结 12 变体与双通道；`EPERM/EACCES` 候选原因文案不改；设备轮事实不得回写为当前能力 | W2、W5 |
| G6 CLI 与真实设备 E2E | 薄壳契约界内；真实设备场景界外 | 冻结 0/1/2 与输出格式；设备 E2E 仅脚本层可选 + SKIPPED | W4、W5 |
| G7 注释/C 注释引用外部模块与失效文档 | 界内（自包含违约，非能力） | 纯文档修复；仓库外申报口径只保留泛称 | W1 |

## 4. 工作包总览

| 包 | 名称 | 优先级 | 规模(S/M/L/XL) | API 影响 | 对应缺口(B#) |
|---|---|---|---|---|---|
| W1 | 漂移清理与自包含 | P0 | S | 无（文档/注释/C 注释/帮助文本） | B2、B6、B18–B20、B25 |
| W2 | 纯逻辑与错误分类 golden 固化 | P1 | M | 无（测试层 + 脚本层） | B8、B11、B13、B15、B23、B24 |
| W3 | 生命周期与资源释放加固 | P1 | S | 无（复用既有变体） | B21 |
| W4 | CLI 场景脚本化与契约冻结 | P1 | S | 无（脚本层） | B15、B16 |
| W5 | 真实 libc 转发与设备轮（A 已落地 M5-1/2，M5-3 未实测） | P2 | XL | 零 pub 变化；仅 ABI 内新增 C 文件 | B16、B17、G1/G3/G5/G6 |
| W6 | `parse_maps` 资源上界防火墙 | P2 | S | 加法：`parse_maps_limited`（新函数，复用既有错误变体） | B22 |

## 5. 工作包详细设计

### W1 漂移清理与自包含（P0/S）

**目标**：消除 B2/B18/B19/B20 四类漂移，使文档、注释、C stub 注释与代码现状一致且自包含；B6 提交数差异仅登记。
**非目标**：不改任何 `.mbt`/`.c` 逻辑；不重建已搬迁且不存在的旧设计文档；不改 7 shim ABI。
**新增 API**：无。
**实现要点**：
- `ptrace_lite.mbt` L9 注释去掉兄弟模块名，改为自足表述（「不提供符号解析/回调插桩能力，由上层组合根自行选择」）；L160、`access_plan.mbt` L9、`target.mbt` L366、`ptrace_lite_test.mbt` L5/L58、`stub/ptrace_stub.c` L7/L12 的失效文档路径改为「README.md §1/§2/§3」或本仓库 docs 索引；改后扫 `.mbt/.md/.yml/.c/.sh/.ps1` 全部引用。
- README §3 索引补 `MemoryView` trait、`TraceeRaw`、`Address`/`Pid`、`to_repr`；L4 改「唯一入口文档」并加 docs 索引；抽取口径改为「全部 pub 声明」。
- 新建 `docs/CHANGELOG.md`，登记 W1（新增 pub=无 / 快照 diff 空 / 测试增量 0），并注明仓库外申报口径不回写。
**验收**：T-W1-1 引用实存性扫描零失效；T-W1-2 README 索引 ↔ mbti 逐条一致；T-W1-3 五门禁绿 + 双快照 diff 空；T-W1-4 CHANGELOG 建立并登记。

### W2 纯逻辑与错误分类 golden 固化（P1/M）

**目标**：把 49 条点状断言升级为契约资产：maps 文本黄金、分段计划枚举、errno×操作矩阵、`#borrow` 与状态包协议 golden、CLI 输出黄金（B8/B11/B13/B15）。
**非目标**：不改 pub API；不引入真实系统调用；不把 stub pid 事实写成内核事实。
**新增 API**：无。
**实现要点**：
- `tests/golden/`（确定性自产文本）覆盖：regular/含空格路径/Android 设备映射/CRLF/排序/畸形行六类 maps 输入；`plan_access` 覆盖跨页/对齐/零长度/负长度/溢出/超限六类；errno 通道覆盖 `-1000-errno` 与 `-1..-999` 两套，逐操作（attach/detach/step/proc/thread/read/write）断言变体与消息包含的关键标签。
- 性质：解析同一文本双次结果逐字段相等；分段首尾相接且每段不跨 4 KiB 页；分段长度和 = 请求长度；`MemoryView` 与 `Target` 同名方法结果逐字节相等；`step` → `detach` → 再读写必 `NotAttached`。
- CLI 输出黄金：五子命令 stdout 与 0/1/2 退出码逐字节锁定；错误路径 stderr 文案冻结。
- 错误簿记门禁化：§6.2 的 12 变体与测试代码双向核对；脚本层 `tools/verify.sh` 串五门禁 + golden + 引用扫描；无 oracle 时显式 SKIPPED。
**验收**：T-W2-1 golden 入库且被测试真实读取；T-W2-2 分段/解析性质全绿；T-W2-3 errno×操作矩阵 12/12 显式；T-W2-4 CLI 输出与退出码逐字节回归；T-W2-5 旧 49 用例零改动全绿（防火墙）。

### W3 生命周期与资源释放加固（P1/S）

**目标**：关闭 B21——`attach` 取到句柄但有效性探测失败时未释放。
**非目标**：不改公开签名；不新增错误变体；不改成功路径返回值与状态；不引入自动重试。
**新增 API**：无（mbti diff 为空）。
**实现要点**：`Target::attach` 把句柄探测失败分支改为先调用 `mb_ptrace_detach(handle)`（忽略其返回码，原失败错误原样抛出，保持错误分类不变）；若 C 侧释放也失败，仍以原探测错误为准，不叠加新变体。按 fail-closed 例外在 CHANGELOG 登记「以前探测失败路径可能遗留句柄，现在立即释放」；回归确认只有注入探测失败样本行为变化，原 49 用例零改动全绿。
**验收**：T-W3-1 注入句柄探测失败 → 错误原样且 `detach` 被调用一次；T-W3-2 成功路径状态仍为 `Attached`、后续 `detach` 正常；T-W3-3 旧 49 用例零改动全绿；T-W3-4 重复 attach/detach 12 轮仍无槽位耗尽。

### W4 CLI 场景脚本化与契约冻结（P1/S）

**目标**：把 CLI 的 0/1/2 契约从白盒测试扩展为仓库自包含冒烟脚本（B15/B16）。
**非目标**：不新增子命令；不改变输出格式；不把 stub pid 写死为生产接口。
**新增 API**：无。
**实现要点**：`tools/smoke-cli.sh` 以 `moon run cmd/main --target native -- …` 逐场景断言退出码与关键输出行（help/五子命令成功/不存在 pid/越界地址/只读页写入/用法错误）；输出做成可 diff 的文本快照；平台无 native 工具链时显式 SKIPPED，不计通过。
**验收**：T-W4-1 冒烟脚本全场景退出码符合契约；T-W4-2 输出快照逐字节 diff=0；T-W4-3 SKIPPED 不进通过计数。

### W5 真实 libc 转发与设备轮（裁决 A 已落地 M5-1/2，P2/XL）

**目标**：在 E5 解禁后于同 ABI 内实现 7 个 shim 的真实 `ptrace`/`process_vm_*`/`waitpid` 转发（B16/B17），并完成 Linux/Android 设备实测。
**非目标**：不改 MoonBit 公开面与 12 变体；不引入第三方调试器/devkit；不把设备样本入库；不自动 `mprotect`。
**须裁决选项**：
- **A（推荐，2026-11-17 采纳；M5-1/2 已落地，M5-3 需用户确认设备与权限条件）**：分里程碑实施——M5-1 仅在 Linux 主机实现 attach/detach/step + errno 通道并用黄金 errno 矩阵验证；M5-2 接 `process_vm_readv/writev` 与 4 KiB 分段；M5-3 设备轮（SELinux/`ptrace_scope`/W^X 降级决策逐项实测）；每里程碑独立五门禁 + 止损条件，任一里程碑失败即停在 stub 路线。需要用户提供可合法使用的 Linux/Android 设备与授权范围。
- **B（零成本降级）**：保持当前 stub + 规格声明，真实转发继续列为未实现/待排期；测试文档 L3/R 全标「未实现」，不产生任何"已跑通"表述。
- **C（不推荐）**：引入第三方库/devkit 或仓库外二进制以求快速落地——触碰零依赖与许可红线，除非用户另行裁决四件例外，否则不执行。
**实现要点（A）**：新增 C 文件仅实现既有 7 符号，按构建条件选择 stub/real；`-1000-errno` 通道是唯一真实错误编码；多线程 attach 停止语义、ARM64 指令边界与 `mprotect` 策略须在对应里程碑单独登记 `[仍需实测]`，未实测项不得以结论形式写入 README。
**验收**：T-W5-1（裁决 A）每里程碑五门禁绿 + stub 侧旧用例零改动；T-W5-2（裁决 A）errno 矩阵在真实 Linux 与 stub 输出同变体分类；T-W5-3（裁决 A）设备报告含哈希/日期/内核版本与 SKIPPED 项；T-W5-4（裁决 B）README 与测试文档维持未实现声明。

### W6 `parse_maps` 资源上界防火墙（P2/S）

**目标**：为无界 maps 转储提供有界替代入口（B22），旧 `parse_maps` 语义冻结。
**非目标**：不给 `MemoryRegion` 加字段；不静默截断超限输入；不新增错误变体。
**新增 API（mbti 草案，纯加法）**：

```text
pub fn parse_maps_limited(String, Int32) -> Array[MemoryRegion] raise PtraceError
```

**实现要点**：第二参数为允许的最大行数（≤0 → `MapsParseFailed(0,"invalid line limit")`）；逐行计数超限即 `MapsParseFailed(limit+1,"line limit exceeded")`，不返回部分结果；内部复用 `parse_maps_line`/排序逻辑；旧 `parse_maps` 一行不改，行为与既有黄金逐字节一致；快照 diff 仅 +1 行并登记 CHANGELOG。
**验收**：T-W6-1 有界入口在边界行数±1 的行为断言；T-W6-2 旧 `parse_maps` 在既有语料上逐字节不变；T-W6-3 快照 diff 纯加法、错误变体仍 12 个；T-W6-4 无界大文本不 panic/不部分返回。

## 6. 里程碑与合入顺序

```text
M0（第1日）   W1 漂移清理与自包含（零风险文档/注释）
M1            W3 生命周期与资源释放加固（安全缺口，行为增强例外）
M2            W2 纯逻辑 golden + W4 CLI 冒烟脚本（高价值低成本）
M3            W6 parse_maps 有界防火墙（新函数，纯加法）
M4（已裁决）  W5 真实 libc 转发：M5-1/2 源码已落地；M5-3 设备轮待配置（SKIPPED）
```

排序判据：先零风险文档、再安全缺口、再高价值低成本、最后大工程与须裁决项；每包独立提交、独立过五门禁；W5 已于 2026-11-17 裁决采纳 A，M5-1/2 源码落地，M5-3 仍为未实测的待配置设备轮。

## 7. 簿记与变更管理

- `docs/CHANGELOG.md`：每包登记「日期/工作包/新增 pub 声明/快照 diff 结论/测试增量」。
- README §3 API 索引随 `moon info` 快照同步（含 trait/外部类型/别名/方法），禁手编 mbti。
- 提交数与测试数只以本仓库实测为准；仓库外申报口径与本仓库不一致时不反向回写。
- 7 个 shim 符号与状态通道变更视为 ABI 破坏，须走四件例外流程；本轮所有 W# 零新增错误变体。
- W3 按 fail-closed 例外登记；W5 各里程碑的 `[仍需实测]` 项单独登记，未实测不得升级为结论。

## 8. 完成定义（DoD，逐包勾选）

- [ ] 新增 API 与 mbti 草案一致（偏差回写本文）；零新增错误变体
- [ ] 快照 diff 纯加法（或空），CHANGELOG 已登记
- [ ] `T-W*-*` 验收全绿；`#skip` 显式标注原因、不计通过
- [ ] 五门禁全绿；CLI 输出/退出码契约零意外漂移
- [ ] 防火墙回归：新函数/新包合入后旧 API 在既有语料上输出逐字节不变、旧用例零改动全绿（W1/W4 纯文档脚本包以旧用例零改动全绿为准）
- [ ] 畸形输入（无界文本、负长度、地址溢出、非法状态）无 panic、无句柄泄漏
- [ ] 零新第三方依赖；零许可不明二进制入库
- [ ] README 能力/非目标/索引同步；本文状态行更新「已交付+日期」
- [ ] 自包含扫描：docs + 代码注释 + C 注释 + 帮助文本 + CI/脚本无工作区路径与兄弟模块符号引用

## 9. 风险登记

| 风险 | 等级 | 缓解 |
|---|---|---|
| stub 语义被误当作真实内核能力 | 高 | W1/W2 冻结归属声明与 golden；W5 未裁决前 README 保持「未实现/未编译/未运行」 |
| 真实转发改动 shim ABI 牵连公开面 | 高 | 7 符号签名与 `-1000-errno` 通道冻结；W5 仅在 ABI 内实现，快照门禁拦截任何漂移 |
| attach 探测失败资源泄漏在真实路径被放大 | 中 | W3 先修 MoonBit 层释放分支，W5 各里程碑复验 |
| `parse_maps` 无界输入导致内存放大 | 中 | W6 新函数上界防火墙 + 截断/变异扫描；旧函数冻结 |
| 设备轮权限/SELinux/W^X 结论不确定 | 高 | W5 分里程碑 + `[仍需实测]` 登记 + 显式 SKIPPED，不猜测结论 |
| 仓库外申报口径继续被当作事实 | 中 | §0 集中登记修正；产出文档只用泛称，不写路径、不回写 |
