# hnlyxiaobing/ptrace_lite

> **实现轮（2026-11-07 完成）+ API 冻结前整改**：1 个 `#external` 句柄、7 个 `extern "C"` shim（**包私有，私有实现 ABI**）、值类型、`MemoryView` trait 与全部包装 API 已实现（桌面 `stub/ptrace_stub.c` 双路径）；`moon check --deny-warn` / `moon build` / `moon test`（18 测试全过）/ `moon fmt --check` 全绿。
> **API 冻结前收紧**：`Target.state` 私有字段 + 只读访问器 `Target::state()` · 7 个 shim 移出公开 API · 追认 `pub impl MemoryView for Target`（冻结后新增 impl 即破坏性变更）· `detach` 措辞统一「不会二次释放，重复调用返回明确错误」（详见 `DECISIONS.md`）。
> **真实 libc ptrace / `process_vm_*` 转发留待 Linux / 设备阶段**（风险与待验证见 `DECISIONS.md`），本轮不链接任何外部库。

Linux / Android 轻量进程控制：attach / maps / peek-poke / 单步 / 线程枚举。frida-gum 的更小备选，两库零互相 import（选型与备选关系见 `DECISIONS.md`）。`preferred_target = "native"`（理由见 `DECISIONS.md`）。

完整文档见同目录 `README.md`、`DESIGN.md`、`API.md`；设计决策与风险记录见同目录 `DECISIONS.md`。

**当前状态：API 冻结前整改完成，等待真实 libc 对接与 API 冻结。**
