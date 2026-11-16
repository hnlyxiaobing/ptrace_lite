# ptrace_lite · 轻量进程控制

> 独立发布单元 ｜ L2 动态验证 ｜ `preferred_target = native` ｜ Apache-2.0
> 状态：`moon test` **49/49** 通过（2026-11-11 本机实测）；本文件是本仓库**唯一**说明文档。
> 公开 API 以 `pkg.generated.mbti` 为准（由 `moon info` 生成，禁手工编辑）；加法性变更须登记簿记 + 快照审阅 + 快照门禁。

## 1. 定位与边界

用比 Frida 更小的依赖面提供进程 attach、内存读写与 `/proc` 解析能力。

**能力**

- `parse_maps` 纯函数（`/proc/<pid>/maps`）与 `Target` 八个方法
- 7 个包私有 `mb_ptrace_*` shim；`PtraceError` 12 构造；状态通道 `-1000 - errno`
- `access_plan` 跨页分段（保守 4 KiB、上限 65,536）与 `errno_map` 分类
- `pub impl MemoryView for Target`；`Target.state` 私有 + `state()`；`detach` 幂等（`NotAttached`）
- CLI 五个子命令，退出码 0/1/2

**非目标**

- **真实 `ptrace` / `process_vm` / `waitpid` 链路未实现、未编译、未运行**，不得表述为已跑通
- 不提供回调式插桩，不依赖 Frida

## 2. 关键设计决策（本仓库自足记录）

- 选轻量路线作为 frida 的更小互斥备选；无回调设计，避免被钩线程执行 MoonBit 闭包。
- 只缓存必要状态；`preferred_target = native`；`Target.state` 私有化以收紧公开面。
- 真实转发层规格（原 `docs/FORWARDING.md`）要点：7 个 shim 符号与签名不变、公开 API/快照不变；跨页读写按 4 KiB 分段；`mprotect` 写入策略与 `waitpid` 细节、SELinux/`ptrace_scope`/W^X 降级决策全部 `[仍需实测]`，设备轮验证清单未执行。

## 3. 公开 API 索引（自动抽取 `pkg.generated.mbti` 的 `pub` 声明行；完整字段见快照）

```text
pub fn parse_maps(String) -> Array[MemoryRegion] raise PtraceError
pub(all) struct MemoryProtection {
pub(all) struct MemoryRegion {
pub(all) struct Target {
pub fn Target::attach(Int32) -> Self raise PtraceError
pub fn Target::detach(Self) -> Unit raise PtraceError
pub fn Target::maps(Self) -> Array[MemoryRegion] raise PtraceError
pub fn Target::read_bytes(Self, UInt64, Int32) -> Bytes raise PtraceError
pub fn Target::state(Self) -> TargetState
pub fn Target::step(Self) -> Unit raise PtraceError
pub fn Target::threads(Self) -> Array[ThreadInfo] raise PtraceError
pub fn Target::write_bytes(Self, UInt64, Bytes) -> Unit raise PtraceError
pub(all) enum TargetState {
pub(all) struct ThreadInfo {
```

## 4. 依赖、平台与许可

零第三方依赖（仅 `stub/ptrace_stub.c`）；`preferred_target = native`；Apache-2.0。

## 5. 命令行与验证

- `moon run cmd/main --target native -- <子命令>`；退出码 0=成功 / 1=运行失败 / 2=用法错误。
- 复验：`moon clean` → `moon check --deny-warn` → `moon build` → `moon test` → `moon fmt --check` → `moon info` 后检查 `pkg.generated.mbti` 无意外 diff。
- 本仓库为独立 Git 仓库，文档与 CI 均自包含，不依赖工作区其他目录。

## 6. 风险与未决

- E5：非 Windows 平台 + W^X / SELinux `untrusted_app` / `ptrace_scope` 的实际限制未实测。
- 真实 libc 转发层是规格而非实现；若长期不排期，该规格只有待办价值。

