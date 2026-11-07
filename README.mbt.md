# hnlyxiaobing/ptrace_lite

> Round-1 · 架构与声明可评审（2026-11-06）。本包只有 1 个 `#external` 句柄、7 个 `extern "C"` shim 声明、值类型、`MemoryView` trait 与 `declare` 包装 API，**无系统调用执行、无 `/proc` 解析、无 shim 实现**。`moon check`：0 error，8 × `[0068]`（预期）。

Linux / Android 轻量进程控制：attach / maps / peek-poke / 单步 / 线程枚举。frida-gum 的更小备选，两库零互相 import（ADR-0006）。`preferred_target = "native"`（ADR-0007）。

> `moon build` / `moon test` 本轮**预期链接期失败**：`mb_ptrace_*` shim 尚未实现。

完整文档见同目录 `README.md`、`DESIGN.md`、`API.md`；总体架构与决策见 `../docs/architecture.md`、`../docs/adr/`。

**当前状态：等待评审，不进入实现。**
