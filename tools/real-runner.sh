#!/usr/bin/env bash
# ptrace_lite 真实后端本地 runner（W5-A：M5-1/M5-2 冒烟 + M5-3 设备轮显式 SKIPPED）
#
# 纪律：真实 tracee 只在仓库外本地运行；不入库样本；缺失能力一律 SKIPPED(78)，
# 不计入 moon test 通过数。仅 Linux 主机可进入 M5-1/M5-2 冒烟。

set -uo pipefail

skip() {
  echo "SKIPPED: $1 (exit 78; not counted as passed)" >&2
  exit 78
}

fail() {
  echo "FAIL: $1" >&2
  exit 1
}

[ "$(uname -s)" = "Linux" ] || skip "real backend requires Linux POSIX host"

case "$(uname -m)" in
  x86_64|aarch64) ;;
  *) skip "unsupported architecture for this milestone" ;;
esac

command -v moon >/dev/null 2>&1 || skip "moon toolchain not available"

# M5-1/M5-2：由调用方在 moon.pkg 中换成 native/ptrace_real.c 后执行五门禁。
echo "real-backend: Linux host detected; M5-1/M5-2 source is available at native/ptrace_real.c"
echo "real-backend: switch moon.pkg native-stub source to native/ptrace_real.c before running the gates"

# M5-3：设备轮（SELinux / ptrace_scope / W^X / 多线程停止）未配置时显式 SKIPPED。
if [ -z "${PTRACE_DEVICE_CONFIG:-}" ]; then
  skip "M5-3 device round not configured (SELinux/ptrace_scope/W^X not measured)"
fi
[ -f "$PTRACE_DEVICE_CONFIG" ] || fail "device config not found: $PTRACE_DEVICE_CONFIG"

echo "real-backend: device config registered ($PTRACE_DEVICE_CONFIG)"
echo "SKIPPED: M5-3 on-device assertions require explicit device report (exit 78)" >&2
exit 78
