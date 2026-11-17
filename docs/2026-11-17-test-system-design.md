# ptrace_lite 测试系统设计（第一性原理）

> 建立：2026-11-17 ｜ 状态：设计生效，随开发文档逐包落地 ｜ 适用仓库：本仓库（独立自包含）
> 配套文档：[2026-11-17-proc-trace-contract-dev-plan.md](2026-11-17-proc-trace-contract-dev-plan.md)（`T-W*-*` 验收 ID 一一对应；B# 证据行见该文档 §0）

## 1. 第一性原理：本库的正确性是什么

本库的数学形态：

```text
(/proc 文本, 受控字节, shim 状态码) → (MemoryRegion / ThreadInfo / Bytes / 状态) | PtraceError(12 类)
```

正确性不可约简为以下断言，每条必须有测试层承载：

| # | 断言 | 含义 | 反例（测试必须抓住） |
|---|---|---|---|
| A1 | 解析与寻址忠实 | maps 字段/权限/排序/行号与格式规范一致；分段首尾相接且不跨 4 KiB 页；读字节偏移与请求一致 | 含空格路径被截断；分段重叠或漏字节；CRLF 行尾被误当字段 |
| A2 | 完整性 fail-closed | 畸形输入/部分读写/超预算分段/非法状态必报声明错误；未校验≠通过；无静默截断 | 句柄探测失败后继续操作；部分读被当作成功 |
| A3 | 边界纯净 | 只输出中性值与错误分类；stub 模拟事实不得表述为内核事实；不产出 hook/符号/权限绕过语义 | 把模拟 pid 4242 写成真实进程能力 |
| A4 | 输入安全 | 任意文本/地址/长度/状态码不 panic、不越界、内存有界；句柄不泄漏 | 无界 maps 文本撑爆内存；负长度导致负数组 |
| A5 | 契约稳定 | mbti 冻结、12 变体、CLI 0/1/2、shim ABI 与 `-1000-errno` 通道一致；变更只加法 | README 索引漏 trait；CLI 失败返回 0 |
| A6 | 平台等价（按本模块裁剪） | `preferred_target=native`，无 wasm 双目标要求；等价口径为「纯逻辑层在桌面 stub 与未来真实实现上同类错误分类一致」 | 真实 errno 通道被错误映射为 stub 合成码语义 |
| A7 | FFI 生命周期与所有权 | 7 shim 的 `#borrow` 约定成立；`detach` 是唯一释放点；失败路径也释放；重复 detach `NotAttached` | 探测失败遗留句柄；C 侧修改被借用的 `Bytes` |
| A8 | 权限语义忠实 | errno → 12 变体分类稳定；`EPERM/EACCES` 列候选原因而非臆断 SELinux；`EINTR` 显式报错不静默重试 | 把 `ENOENT` 误映射成 stub 的「无此进程」语义标签而不分类 |

设计推论：A1/A2 → 性质测试 + 结构化 golden + 截断/变异扫描；A7/A8 → 状态序列断言 + errno×操作矩阵；A4 → 边界值 + 无界输入扫描；A5 → 五门禁、CLI 冒烟与快照 diff。

## 2. 测试分层

```text
L0 单元与程序化 fixture（现有 40 库内 + 5 CLI 白盒 = 45 条直接单元断言）
L1 性质与变异（变形律 / maps 截断与位翻转 / 分段枚举 / errno 通道边界）
L2 受控黄金差分（tests/golden/ 自产文本与结构化记录；W2 建立）
L3 外部 oracle 差分（真实内核 ptrace/process_vm，仅 W5 裁决后本地可选，显式 SKIPPED）
L4 CLI 场景 E2E（五子命令 + 0/1/2 退出码矩阵；W4 脚本化）
L5 元契约门禁（快照 / 错误簿记 12/12 / 引用实存性 / shim ABI 冻结 / 变异自检）
R  真实样本本地 runner（仓库外 pid/设备 + 哈希登记 + 显式 SKIPPED）
```

断言×层承载表：

| 断言 | 主承载层 | 辅助层 |
|---|---|---|
| A1 解析/寻址忠实 | L0 + L2 | L1（分段恒等式） |
| A2 完整性 fail-closed | L0 + L5 | L1（截断/变异）、L4 |
| A3 边界纯净 | L0 | L5（文案/文档扫描） |
| A4 输入安全 | L1 | L0（极端构造）、L2 |
| A5 契约稳定 | L5 | L4（CLI 逐字节） |
| A6 平台等价（裁剪） | L3（裁决后） | L0（纯逻辑分类） |
| A7 生命周期/所有权 | L0 + L1 | L3（真实路径复验） |
| A8 权限语义忠实 | L0 + L2 | L3（真实 errno 对照） |

## 3. fixture 体系

| 类 | 形态 | 入库 | 许可 | 现状 |
|---|---|---|---|---|
| F-A 程序化构造 | 测试内嵌 maps 文本、状态码、模拟 pid（4242/4243/7001/7002/7003/999999） | 是 | 随仓库 | 已实现；全部经 C stub 真实消费 |
| F-B 受控文件 fixture | `tests/fixtures/*` | 是 | 哈希登记 | 当前无目录、无死资产（B7）；W2 建 golden 须附登记 |
| F-C 生成器资产 | 确定性脚本产出（maps 文本 builder、errno 矩阵生成器） | 是 | 自产 | W2 待建 |
| F-D 真实进程/设备样本 | 仓库外 pid / Linux/Android 设备 | 否（红线） | 权限与许可需确认 | W5-A M5-1/2 源码已落地；M5-3 设备轮未配置时 runner 显式 SKIPPED |

红线：F-D 永不入库；golden 字节变更须同步登记与黄金记录；仓库外申报材料不进入本仓库测试路径或文档引用。
builder 能力清单：maps 行（地址区间/perms 四字符/offset/dev/inode/path/CRLF/空白/畸形字段）；errno 值（1/2/3/4/5/10/13/14/16/22/38 与未知值）；状态码（`-1..-8` stub 码、`-1001..-5095` 真实通道、边界 `-1000`/`-5096`）；访问请求（零长度/负长度/跨页/对齐/地址溢出/超 65,536 段）；目标状态（Detached/Attached/Stepping/Failed）。

## 4. L1 性质与变异

- 变形律 P1 幂等：`parse_maps(text)` 双次结果逐字段相等；同状态同请求读写结果相等（stub 数据确定）。
- 变形律 P2 分段恒等式：`plan_access` 各段首尾相接、每段不跨 4 KiB、段长和 = 请求长度、`offset+length` 覆盖请求；地址溢出/超限时整体失败且无部分计划返回。
- 变形律 P3 双入口一致：`Target::read_bytes`/`write_bytes` 与 `MemoryView` 同名方法在相同状态下逐字节相等。
- 变形律 P4 状态律：`step ⇒ Stepping`；`detach ⇒ Detached`；`Detached/Failed` 下任意读写/单步 `NotAttached`；重复 `detach` 恒 `NotAttached`。
- 变形律 P5 分类律：`status = -1000 - errno`（1≤errno≤4095）在任一操作上映射的变体与 `-errno` 直传绝不混淆；未知 errno 落入各操作的兜底分支而非 panic。
- 变形律 P6 **防火墙律**：任一 W# 合入后旧 API 在既有 49 语料上输出逐字节不变、旧用例零改动全绿；7 shim 符号与 `#borrow` 标注不变。
- 位翻转：maps 关键字段（权限字符、地址 hex、inode 数字）单字符变异 → `MapsParseFailed` 或解析值改变；**格式依赖口径**：maps 有语法但无 checksum，变异后可能仍是合法行，断言为「要么报声明错误，要么输出与变异前不同」，不得断言全部必错。
- 边界值矩阵：零长度读/写、负长度、地址恰 `UINT64_MAX`、长度恰 256 MiB 上限±1、段上限 65,536±1、maps 空文本/仅换行/末行无换行/超大行号、errno 通道边界 `-1000`/`-1001`/`-5095`/`-5096`。
- 截断扫描：每个 maps golden 的全部前缀 + 每字段边界；只允许 `MapsParseFailed`，无 panic/挂起。
- 变异语料：固定种子随机替换/插入/删除字符，每轮 ≥1000 变异体；errno 通道全量 4095 值分桶抽样。

## 5. L3 oracle 矩阵 + R runner

| oracle | 差分对象 | 规范化口径 |
|---|---|---|
| 真实 Linux `ptrace`/`process_vm_*`（W5 裁决后） | 同一操作序列下 stub 与真实后端的**变体分类与状态迁移**，不比地址/字节内容 | 变体名一致、状态序列一致；真实 errno 值单独登记 |
| `/proc/<pid>/maps` 真实文本（仓库外文件） | `parse_maps` 输出字段与系统工具呈现的区间语义，不比下游解释 | 逐字段（`start/end/perms/offset/device/inode/path`）比对 |

纪律：oracle 缺失 → 显式 SKIPPED + 原因（退出码 78 口径），不得写成通过；内核版本/工具版本随结果登记。R runner：样本路径 + 登记哈希 → 哈希不符拒绝执行 → 规范化差分 → 报告「本地已差分 + 哈希 + 日期」；入库 `#skip` 占位用例保留不删，真实结论永不进入通过计数。

## 6. 覆盖矩阵与错误簿记

### 6.1 能力×场景×安全 覆盖矩阵

现状列来自 2026-11-17 P4 实测（B# 见开发文档 §0）；✓=已有用例，◐=点状/间接覆盖，✗=待建。

| ID | 能力/场景 | L0 | L1 | L2 | L3 | L4 | 现状(P4) | 缺口→W# |
|---|---|---|---|---|---|---|---|---|
| F1 | maps 纯解析 | ✓ | ◐ | ✗ | ✗ | ✓ | 4 类 golden + 9 类畸形（B8） | 文本 golden→W2；有界→W6 |
| F2 | Target 状态机/attach/detach | ✓ | ◐ | ✗ | ✗ | ✓ | 四态 + 唯一释放 + 重复拒绝（B9） | 探测失败释放→W3 |
| F3 | 读写/MemoryView | ✓ | ◐ | ✗ | ✗ | ✓ | 未 attach 拒绝 + 双入口（B10） | 双入口 golden→W2 |
| F4 | 跨页分段计划 | ✓ | ◐ | ✗ | ✗ | ◐ | 11 条白盒 + 3 条端到端（B11） | 分段枚举 golden→W2 |
| F5 | step/threads | ✓ | ✗ | ✗ | ✗ | ✓ | 状态迁移 + task 交叉校验（B12） | 序列 golden→W2 |
| F6 | 错误模型/errno 分类 | ✓ | ◐ | ✗ | ✗ | ✓ | 12/12 显式 + 7 errno 白盒（B3/B13） | errno×操作矩阵→W2 |
| F7 | 7 shim + 桌面 stub | ✓ | ✗ | ✗ | ✗ | ✓ | 包私有 + `#borrow` + 模拟 pid（B14/B16） | ABI 冻结门禁→W2；真实实现→W5 |
| F8 | CLI 0/1/2 | ✓ | ✗ | ✗ | ✗ | ✓ | 13 条退出码断言（B15） | 冒烟脚本→W4 |
| F9 | 真实链路 | ✗ | ✗ | ✗ | ◐ | ✗ | 明确未实现（B16/B17） | 裁决→W5 |
| S1 | 预期场景端到端（attach→maps→read→detach） | ✓ | | ◐ | | ✓ | 模拟 pid 4242/4243 全链路 | 脚本固化→W2/W4 |
| S2 | 安全拒绝（未 attach/越界/只读页/不存在 pid） | ✓ | ◐ | | | ✓ | 显式变体断言 + CLI 失败码 1 | 截断变异→W2；资源释放→W3 |
| C1 | 输入安全（畸形不 panic/内存有界/句柄不泄漏） | ◐ | ✗ | | | | 单项溢出防护在，无系统扫描（B21/B22） | 有界→W6；释放→W3 |
| C2 | 防火墙（新包不改旧语义） | ◐ | ✗ | ✗ | | ◐ | 尚无固化 golden（B25 相关） | T-W2-5/T-W3-3/T-W6-2 |
| C3 | 许可红线（F-D 零入库） | ✓ | | | | | 零二进制资产（B7） | R runner 哈希门禁→W5 |
| C4 | 契约稳定（快照/索引/引用实存性） | ◐ | | | | | 双快照无漂移；索引与注释漂移（B2/B18/B19） | 清理→W1；门禁→W2 |

C 行含防火墙（C2）与许可红线（C3）两行。

### 6.2 错误变体触发簿记（12/12 强制）

| 变体 | 触发 fixture（现状，2026-11-17） | 新增触发（待建） |
|---|---|---|
| `AttachDenied` | ✓ stub pid 7003、`EPERM/EACCES` 分类、`/proc` 读取拒绝 | 真实 Linux 权限对照（W5） |
| `DetachFailed` | ✓ errno 分类白盒（未知 errno 兜底） | 真实释放失败注入（W5） |
| `NotAttached` | ✓ 未 attach 读写/单步、重复 detach、失效句柄 | 探测失败后状态断言（W3） |
| `AlreadyAttached` | ✓ 对已 attach pid 再 attach、`EBUSY` 分类 | 无 |
| `ProcessNotFound` | ✓ pid 999999、`ESRCH/ENOENT/ECHILD` 分类 | 无 |
| `MapsParseFailed` | ✓ 9 类畸形 maps 行、文本包缺 task 段、长度不稳定 | 截断扫描（W2）、行数上限（W6） |
| `ReadFailed` | ✓ 越界地址、负长度、地址溢出、部分读、errno 分类 | 真实 EFAULT 对照（W5） |
| `WriteFailed` | ✓ 只读页写入、部分写、errno 分类 | 真实 EPERM 对照（W5） |
| `StepFailed` | ✓ errno 分类白盒兜底 | 真实 singlestep 失败（W5） |
| `ThreadEnumerateFailed` | ✓ task 行畸形、task_count 不一致 | 无 |
| `UnsupportedKernel` | ✓ stub pid 7002、`ENOSYS`/`/proc` 不可用分类 | 真实内核降级决策（W5） |
| `SelinuxDenied` | ✓ stub pid 7001 | 真实 SELinux 探测（W5，未实测前不升级口径） |

显式簿记 **12/12**（2026-11-17 实测，每变体至少一条直接变体名断言）；W3/W6 只增加触发语料，不新增变体。

### 6.3 恒等式断言（语义契约，全路径成立）

- `Target.state` 恒与 C 侧句柄状态一致；只有 `Attached|Stepping` 可读写/单步。
- `detach` 是唯一释放点；成功后恒 `Detached`，释放失败恒 `Failed`；任何状态下重复 `detach` 恒 `NotAttached`。
- 零长度读恒为空 `Bytes`、零长度写恒无副作用，且不改变状态。
- `plan_access` 段长和恒等于请求长度、每段不跨 4 KiB、超限恒整体失败无部分返回。
- `parse_maps` 结果按 `(start,end)` 升序；空文本恒空数组；行号从 1 起且末行换行不产生额外错误。
- errno 通道恒满足 `status = -1000 - errno` 与 `-1..-999` 两域不交叠；`EINTR` 恒显式报错而非静默继续。
- **防火墙恒等式：任一 W# 合入后，旧 API 在既有 49 语料上输出逐字节不变、旧用例零改动全绿**（W1/W4 文档脚本包以旧用例零改动全绿为准）。

### 6.4 #skip 清单（显式单列，永不计入通过）

| 用例 | 位置 | 原因 |
|---|---|---|
| （无） | — | 当前基线零 `#skip`（2026-11-17 实测：源码 Grep `#skip`/SKIPPED = 0，`moon test` 49/49） |

计数口径：49 条声明（库内 44 + CLI 5）− 0 条 `#skip` = 49 执行（2026-11-17，native 默认目标）；`--include-skipped` 结果单独报告。W5 若裁决 A，设备/真实内核用例以 `#skip` 入库并在此表单列；SKIPPED 永不进入通过计数。

### 6.5 验收 ID 双向追溯表

| `T-W*-*` | W#（开发文档） | 矩阵缺口行 | 断言/层 |
|---|---|---|---|
| T-W1-1 引用实存性扫描零失效 | W1 | C4 | A5/L5 |
| T-W1-2 README 索引 ↔ mbti 逐条一致 | W1 | C4 | A5/L5 |
| T-W1-3 五门禁绿 + 双快照 diff 空 | W1 | C4 | A5/L5 |
| T-W1-4 CHANGELOG 建立并登记 | W1 | C4 | A5/L5 |
| T-W2-1 golden 入库且被测试真实读取 | W2 | F1、F4、F6、S1 | A1/L2 |
| T-W2-2 分段/解析性质全绿 | W2 | F1、F4 | A1/L1 |
| T-W2-3 errno×操作矩阵 12/12 显式 | W2 | F6、A8 | A8/L2+L5 |
| T-W2-4 CLI 输出与退出码逐字节回归 | W2 | F8 | A5/L4 |
| T-W2-5 旧 49 用例零改动全绿（防火墙） | W2 | C2 | A5/L5 |
| T-W3-1 探测失败 → 原错误且 detach 调用一次 | W3 | F2、S2、C1 | A7/L0 |
| T-W3-2 成功路径状态仍 Attached、后续 detach 正常 | W3 | F2 | A7/L0 |
| T-W3-3 旧 49 用例零改动全绿 | W3 | C2 | A5/L5 |
| T-W3-4 重复 attach/detach 12 轮无槽位耗尽 | W3 | F2、C1 | A7/L1 |
| T-W4-1 冒烟脚本全场景退出码符合契约 | W4 | F8 | A5/L4 |
| T-W4-2 输出快照逐字节 diff=0 | W4 | F8 | A5/L4 |
| T-W4-3 SKIPPED 不进通过计数 | W4 | C3 | A5/L5 |
| T-W5-1（裁决 A）每里程碑五门禁绿 + stub 旧用例零改动 | W5（M5-1/2 源码已落地；本机 POSIX 未编译，未写通过） | F9、C2 | A5/L5 |
| T-W5-2（裁决 A）errno 矩阵真实与 stub 同变体分类 | W5（源码已落地；待 Linux 主机验证） | F6、A6 | A8/L3 |
| T-W5-3（裁决 A）设备报告含哈希/日期/内核版本与 SKIPPED | W5（M5-3 未配置，runner 显式 SKIPPED） | F9、C3 | A4/R |
| T-W5-4（裁决 B）README 与测试文档维持未实现声明 | W5（B 未采纳，存档） | F9 | A3/L5 |
| T-W6-1 有界入口边界行数±1 行为断言 | W6 | F1、C1 | A4/L0 |
| T-W6-2 旧 `parse_maps` 逐字节不变 | W6 | C2 | A5/L5 |
| T-W6-3 快照 diff 纯加法、变体仍 12 个 | W6 | C4、F6 | A5/L5 |
| T-W6-4 无界大文本不 panic、不部分返回 | W6 | C1 | A4/L1 |

W5-A 已裁决：M5-1/2 仅登记为「源码已落地、未实测」，M5-3 保持「未实现/SKIPPED」；不预写通过。

## 7. L4 CLI 场景 E2E

| 场景 | 命令序列 | 断言要点（退出码 + 输出 + 落盘） |
|---|---|---|
| 帮助/用法错误 | `--help`、`help`、`-h`；无命令、未知命令、缺参、多参、非法 pid/地址/长度/字节 | 0 / 2；帮助文本与错误行冻结 |
| attach 成功 | `attach 4242` | 0；输出含 `state=Attached` 与 `detach` 行 |
| maps 成功 | `maps 4242` | 0；4 行区间记录，字段顺序与格式冻结 |
| read 成功 | `read 4242 0x10000 4` | 0；`hex=41 42 43 44` |
| write 成功 | `write 4242 0x10010 4142` | 0；`bytes=2` |
| step 成功 | `step 4242` | 0；`state=Stepping` |
| 运行失败 | `attach 999999`、`maps 999999`、`read 4242 0x500000 4`、`write 4242 0x20000 41` | 1；错误行含变体分类；无写盘（本 CLI 不落盘） |
| 失败后恢复 | 失败命令后再 `attach 4242` | 0；句柄表无泄漏 |

记录行/JSON 契约冻结口径：`attach pid=<n> state=<S>` / `detach pid=<n>` / `maps` 逐行 `<start>-<end> <perms> offset=<hex> dev=<dev> inode=<n> path=<p>` / `read … hex=…` / `write … bytes=<n> hex=…` / `step pid=<n> state=<S>`；变更即破坏。退出码矩阵 0=成功 / 1=`PtraceError` / 2=用法错误，逐例断言；脚本层 78 为 SKIPPED 独立口径。

## 8. L5 元契约门禁

1. 快照门禁：`moon info` + `git diff --exit-code -- pkg.generated.mbti cmd/main/pkg.generated.mbti`（纯加法）。
2. shim ABI 门禁：7 个 `mb_ptrace_*` 符号/签名/`#borrow` 标注与 `-1000-errno` 通道逐条核对，变更即红。
3. 错误簿记门禁：§6.2 的 12 变体 ↔ 测试代码双向核对；缺一即红。
4. 变异自检：注入 3 类缺陷（分段漏一段 / errno 通道偏移改 `+1000` / detach 后未改状态），套件必须变红后还原复绿。
5. 计数纪律：`#skip` 不计通过；过滤串以 `*` 结尾防空转假绿。
6. 引用实存性扫描：`.mbt/.md/.yml/.c/.sh/.ps1` 注释与文案引用的仓库内路径全部实存；README API 索引与快照逐条一致；无工作区路径与兄弟模块符号。

## 9. CI 集成与执行入口

五门禁不变（CI 已固化）；L0/L1/L2 挂 `moon test`；L3/L4/R/真实内核对照为脚本层可选 job，缺失显式 SKIPPED。
复验命令（本仓库根目录自包含）：

```bash
moon check --deny-warn
moon build
moon test
moon fmt --check
moon info; git diff --exit-code -- pkg.generated.mbti cmd/main/pkg.generated.mbti
bash tools/smoke-cli.sh
```

Windows 下 moon 把进度写 stderr，以退出码与 `Total tests: N, passed: N` 判定；语句分隔用 `;` 而非 `&&`。

## 10. 维护规则与验收清单

1. 新增 pub API ⇒ 同提交附 L0 样例 + L1 性质 + 矩阵/簿记更新；无测试不合入。
2. 新增解析路径/状态码分支 ⇒ 进截断扫描与 errno 矩阵 fixture 集。
3. golden/登记哈希变更 ⇒ 黄金记录同提交更新，并附「仅受影响样本变化」对照。
4. 每包合入 ⇒ 开发文档 DoD 勾选 + 矩阵现状刷新 + CHANGELOG 测试增量。
5. 「通过」须可复验：命令 + 日期 + 计数；SKIPPED 永远单列；stub 事实不得升级为内核事实。

落地验收：L0 ✓（49 条实跑）、L1 ◐（点状，W2/W6 补齐）、L2 ✗（W2 待建）、L3 ◐（W5-A M5-1/2 源码已落地，Linux 主机未编译/未实测；M5-3 设备轮 SKIPPED）、L4 ✓（CLI 白盒 5 条，脚本化待 W4）、L5 ◐（快照与计数已验，ABI/簿记门禁与变异自检待 W2）、R ✗（零入库样本）；W5 已裁决 A，不再列为待裁决项。
