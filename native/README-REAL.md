# 真实 libc 转发层（W5-A，M5-1/M5-2）

- 实现文件：`native/ptrace_real.c`，7 个 `mb_ptrace_*` 符号与 MoonBit 侧 ABI 完全一致。
- 默认构建仍用 `stub/ptrace_stub.c`；二者符号集合重合，**不可同时编译**。
- 启用方式（Linux 主机/设备轮）：把 `moon.pkg` 的 `options("native-stub": [...])` 中
  `stub/ptrace_stub.c` 替换为 `native/ptrace_real.c`，再按仓库 README 的复验命令跑五门禁。
  禁止同时引入第三方调试器/devkit 或把真实库/样本入库。
- 状态码：真实 errno 一律编码为 `-(1000 + errno)`（1≤errno≤4095），越界折叠为 EIO；
  `-8` 仅保留给空/失效句柄。MoonBit 侧 `errno_map.mbt` 的分类逻辑零改动。
- M5-1：attach（`PTRACE_ATTACH` + `waitpid(__WALL)`）、detach、SINGLESTEP 已实现。
- M5-2：`process_vm_readv/writev` 分段读写（4 KiB 分段由 MoonBit 侧 `plan_access` 负责）、
  `/proc/<pid>/maps` + `/proc/<pid>/task` 文本包已实现，snprintf 语义与 64 MiB 上界保留。
- M5-3（Linux/Android 真机、SELinux/`ptrace_scope`/W^X、多线程停止语义）**未实测**：
  按 `[仍需实测]` 登记；本文件在 2026-11-17 的 Windows/MSVC 主机未编译、未运行。
- 非目标不变：符号解析、inline hook、回调插桩、隐式 `mprotect`。
