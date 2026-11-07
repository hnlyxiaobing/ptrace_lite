# hnlyxiaobing/ptrace_lite

> **R1.5 实现轮 + 冻结前 P0 整改（R2 准备轮）**：1 个 `#external` 句柄、7 个 `extern "C"` shim（**包私有，私有实现 ABI**）、值类型、`MemoryView` trait 与全部包装 API 已实现（桌面 `stub/ptrace_stub.c` 双路径）；`moon check --deny-warn` / `moon build` / `moon test`（18 测试全过）/ `moon fmt --check` 全绿。
> **冻结前 P0**：`Target.state` 私有字段 + 只读访问器 `Target::state()`（决策 5）· 7 个 shim 移出公开 API（决策 6）· 追认 `pub impl MemoryView for Target`（决策 7，冻结后新增 impl 即破坏性变更）· `detach` 措辞统一「不会二次释放，重复调用返回明确错误」（决策 8）。
> **真实 libc ptrace / `process_vm_*` 转发留待 Linux/设备轮次**（E5），本轮不链接任何外部库。

Linux / Android 轻量进程控制：attach / maps / peek-poke / 单步 / 线程枚举。frida-gum 的更小备选，两库零互相 import（ADR-0006）。`preferred_target = "native"`（ADR-0007）。

完整文档见同目录 `README.md`、`DESIGN.md`、`API.md`；总体架构与决策见 `../docs/architecture.md`、`../docs/adr/`。

**当前状态：冻结前 P0 整改完成，等待 R2 真实对接与 API 冻结。**
