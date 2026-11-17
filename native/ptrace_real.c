/*
 * ptrace_lite — 真实 libc 转发实现（W5-A，2026-11-17，里程碑 M5-1/M5-2）
 *
 * 启用方式（POSIX/Linux 主机或设备轮）：用本文件替换 moon.pkg 的 native-stub
 * 源列表中的 stub/ptrace_stub.c（二者不可同时编译，符号集合完全重合）。
 * 默认构建仍使用 stub/ptrace_stub.c；Windows/MSVC 主机不编译本文件。
 *
 * 与 MoonBit 层共享的 ABI（冻结，7 个 mb_ptrace_* 符号签名不变）：
 *   - 返回 >= 0：成功（字节数 / 文本所需长度 / 线程数 / 句柄指针）；
 *   - 返回 <= -1001：真实 errno 通道，编码为 -(1000 + errno)，errno ∈ [1,4095]；
 *   - -8：空/失效句柄（legacy 通道，MoonBit 映射 NotAttached）。
 * MoonBit 侧 errno_map.mbt 已实现该通道的分类；本文件不得更改状态码语义。
 *
 * 边界：只做 attach/detach/single-step、process_vm_readv/writev 与 /proc 只读文本包；
 * 不做符号解析、不做 inline hook、不做回调、不自动 mprotect。
 *
 * 实测状态：本文件在 2026-11-17 的 Windows/MSVC 主机**未编译、未运行**（无 POSIX
 * 工具链）；Linux/Android 设备轮 M5-3 仍未实测，按 [仍需实测] 登记，不得表述为已跑通。
 */

#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#include "moonbit.h"

#if !defined(__linux__)
#error "ptrace_real.c requires Linux POSIX interfaces (ptrace/process_vm_*/procfs)"
#endif

#define MB_ERR_HANDLE (-8)
#define ERRNO_BASE 1000
#define ERRNO_MAX 4095
#define REAL_MAX_BYTES (64 * 1024 * 1024)

typedef struct {
  pid_t pid;
  int attached;
} real_tracee;

/* 真实 errno → 冻结通道；越界时折叠为 EIO，绝不返回 0 或正成功值。 */
static int32_t errno_status(void) {
  int e = errno;
  if (e < 1 || e > ERRNO_MAX) e = EIO;
  return -(ERRNO_BASE + e);
}

/* 等待被 ptrace 停住的目标；__WALL 覆盖多线程 attach 场景。 */
static int wait_stopped(pid_t pid) {
  int status = 0;
  for (;;) {
    pid_t got = waitpid(pid, &status, __WALL);
    if (got == pid) return WIFSTOPPED(status) ? 0 : -1;
    if (got == -1 && errno == EINTR) continue;
    return -1;
  }
}

void *mb_ptrace_attach(int32_t pid) {
  if (pid <= 0) return NULL;
  if (ptrace(PTRACE_ATTACH, (pid_t)pid, 0, 0) == -1) return NULL;
  if (wait_stopped((pid_t)pid) != 0) {
    (void)ptrace(PTRACE_DETACH, (pid_t)pid, 0, 0);
    return NULL;
  }
  real_tracee *t = (real_tracee *)malloc(sizeof(real_tracee));
  if (t == NULL) {
    (void)ptrace(PTRACE_DETACH, (pid_t)pid, 0, 0);
    return NULL;
  }
  t->pid = (pid_t)pid;
  t->attached = 1;
  return (void *)t;
}

int32_t mb_ptrace_detach(void *handle) {
  real_tracee *t = (real_tracee *)handle;
  if (t == NULL || !t->attached) return MB_ERR_HANDLE;
  int rc = 0;
  if (ptrace(PTRACE_DETACH, t->pid, 0, 0) == -1) rc = errno_status();
  t->attached = 0;
  free(t);
  return rc;
}

int32_t mb_ptrace_read_mem(void *handle, uint64_t address, uint8_t *dst,
                           int32_t length) {
  real_tracee *t = (real_tracee *)handle;
  if (t == NULL || !t->attached) return MB_ERR_HANDLE;
  if (length < 0 || dst == NULL) return -(ERRNO_BASE + EINVAL);
  if (length == 0) return 0;
  if ((uint64_t)length > (uint64_t)Moonbit_array_length(dst))
    return -(ERRNO_BASE + EINVAL);
  if (address > UINTPTR_MAX - (uint64_t)length)
    return -(ERRNO_BASE + EINVAL);

  struct iovec local;
  struct iovec remote;
  local.iov_base = dst;
  local.iov_len = (size_t)length;
  remote.iov_base = (void *)(uintptr_t)address;
  remote.iov_len = (size_t)length;
  ssize_t got = process_vm_readv(t->pid, &local, 1, &remote, 1, 0);
  if (got == -1) return errno_status();
  return (int32_t)got; /* 部分读取返回正数，由 MoonBit 层判为 ReadFailed */
}

int32_t mb_ptrace_write_mem(void *handle, uint64_t address, uint8_t *src,
                            int32_t length) {
  real_tracee *t = (real_tracee *)handle;
  if (t == NULL || !t->attached) return MB_ERR_HANDLE;
  if (length < 0 || src == NULL) return -(ERRNO_BASE + EINVAL);
  if (length == 0) return 0;
  if ((uint64_t)length > (uint64_t)Moonbit_array_length(src))
    return -(ERRNO_BASE + EINVAL);
  if (address > UINTPTR_MAX - (uint64_t)length)
    return -(ERRNO_BASE + EINVAL);

  struct iovec local;
  struct iovec remote;
  local.iov_base = src;
  local.iov_len = (size_t)length;
  remote.iov_base = (void *)(uintptr_t)address;
  remote.iov_len = (size_t)length;
  ssize_t put = process_vm_writev(t->pid, &local, 1, &remote, 1, 0);
  if (put == -1) return errno_status();
  return (int32_t)put; /* 部分写入由 MoonBit 层判为 WriteFailed */
}

int32_t mb_ptrace_step(void *handle) {
  real_tracee *t = (real_tracee *)handle;
  if (t == NULL || !t->attached) return MB_ERR_HANDLE;
  if (ptrace(PTRACE_SINGLESTEP, t->pid, 0, 0) == -1) return errno_status();
  if (wait_stopped(t->pid) != 0) return -(ERRNO_BASE + EIO);
  return 0;
}

/* 读取整个文件到内存；上限 REAL_MAX_BYTES，超限 fail-closed。 */
static int read_file_bounded(const char *path, char **out, size_t *out_len) {
  int fd = open(path, O_RDONLY);
  if (fd < 0) return -1;
  size_t cap = 8192;
  size_t len = 0;
  char *buf = (char *)malloc(cap + 1);
  if (buf == NULL) { close(fd); return -1; }
  for (;;) {
    if (len == cap) {
      if (cap >= REAL_MAX_BYTES) { free(buf); close(fd); return -1; }
      size_t next = cap * 2;
      if (next > REAL_MAX_BYTES) next = REAL_MAX_BYTES;
      char *grown = (char *)realloc(buf, next + 1);
      if (grown == NULL) { free(buf); close(fd); return -1; }
      buf = grown;
      cap = next;
    }
    ssize_t n = read(fd, buf + len, cap - len);
    if (n > 0) { len += (size_t)n; continue; }
    if (n == 0) break;
    if (errno == EINTR) continue;
    free(buf); close(fd); return -1;
  }
  close(fd);
  buf[len] = '\0';
  *out = buf;
  *out_len = len;
  return 0;
}

static int append_bytes(char **buf, size_t *len, size_t *cap, const char *src,
                        size_t n) {
  if (*len + n + 1 > REAL_MAX_BYTES) return -1;
  if (*len + n + 1 > *cap) {
    size_t next = *cap ? *cap : 8192;
    while (next < *len + n + 1) next = next * 2;
    if (next > REAL_MAX_BYTES) next = REAL_MAX_BYTES;
    if (next < *len + n + 1) return -1;
    char *grown = (char *)realloc(*buf, next);
    if (grown == NULL) return -1;
    *buf = grown;
    *cap = next;
  }
  memcpy(*buf + *len, src, n);
  *len += n;
  (*buf)[*len] = '\0';
  return 0;
}

/* 构造 "/proc/<pid>/maps\n__tasks__\n<tid>\t<name>\t<state>\n" 文本包。 */
static int build_proc_bundle(pid_t pid, char **out, size_t *out_len) {
  char path[PATH_MAX];
  int n = snprintf(path, sizeof(path), "/proc/%d/maps", (int)pid);
  if (n <= 0 || (size_t)n >= sizeof(path)) return -1;
  char *maps = NULL;
  size_t maps_len = 0;
  if (read_file_bounded(path, &maps, &maps_len) != 0) return -1;

  size_t cap = maps_len + 4096;
  if (cap > REAL_MAX_BYTES) cap = REAL_MAX_BYTES;
  char *buf = (char *)malloc(cap);
  if (buf == NULL) { free(maps); return -1; }
  size_t len = 0;
  buf[0] = '\0';
  int failed = append_bytes(&buf, &len, &cap, maps, maps_len);
  free(maps);
  if (failed != 0) { free(buf); return -1; }
  failed = append_bytes(&buf, &len, &cap, "__tasks__\n", 10);
  if (failed != 0) { free(buf); return -1; }

  n = snprintf(path, sizeof(path), "/proc/%d/task", (int)pid);
  if (n <= 0 || (size_t)n >= sizeof(path)) { free(buf); return -1; }
  DIR *dir = opendir(path);
  if (dir == NULL) { free(buf); return -1; }
  struct dirent *ent;
  while ((ent = readdir(dir)) != NULL) {
    if (ent->d_name[0] == '.') continue;
    char tid_path[PATH_MAX];
    int m = snprintf(tid_path, sizeof(tid_path), "/proc/%d/task/%s/comm",
                     (int)pid, ent->d_name);
    if (m <= 0 || (size_t)m >= sizeof(tid_path)) continue;
    char *name = NULL;
    size_t name_len = 0;
    if (read_file_bounded(tid_path, &name, &name_len) != 0) continue;
    while (name_len > 0 && (name[name_len - 1] == '\n' || name[name_len - 1] == '\r'))
      name[--name_len] = '\0';
    m = snprintf(tid_path, sizeof(tid_path), "/proc/%d/task/%s/stat",
                 (int)pid, ent->d_name);
    char state = '?';
    if (m > 0 && (size_t)m < sizeof(tid_path)) {
      char *stat = NULL;
      size_t stat_len = 0;
      if (read_file_bounded(tid_path, &stat, &stat_len) == 0) {
        const char *close_paren = strrchr(stat, ')');
        if (close_paren != NULL && close_paren + 2 < stat + stat_len)
          state = close_paren[2];
        free(stat);
      }
    }
    char line[PATH_MAX];
    m = snprintf(line, sizeof(line), "%s\t%s\t%c\n", ent->d_name, name, state);
    free(name);
    if (m <= 0 || (size_t)m >= sizeof(line)) continue;
    if (append_bytes(&buf, &len, &cap, line, (size_t)m) != 0) break;
  }
  closedir(dir);
  *out = buf;
  *out_len = len;
  return 0;
}

int32_t mb_ptrace_read_maps(int32_t pid, uint8_t *dst, int32_t capacity) {
  if (pid <= 0 || capacity < 0) return -(ERRNO_BASE + EINVAL);
  char *bundle = NULL;
  size_t bundle_len = 0;
  if (build_proc_bundle((pid_t)pid, &bundle, &bundle_len) != 0) {
    int saved = errno;
    free(bundle);
    if (saved < 1 || saved > ERRNO_MAX) saved = EIO;
    return -(ERRNO_BASE + saved);
  }
  if (bundle_len > (size_t)INT32_MAX) { free(bundle); return -(ERRNO_BASE + EFBIG); }
  int32_t required = (int32_t)bundle_len;
  if (capacity == 0) { free(bundle); return required; } /* 就绪性探测 */
  if ((uint64_t)capacity > (uint64_t)Moonbit_array_length(dst)) {
    free(bundle);
    return -(ERRNO_BASE + EINVAL);
  }
  int32_t to_write = capacity < required ? capacity : required;
  memcpy(dst, bundle, (size_t)to_write);
  free(bundle);
  return required; /* snprintf 语义：返回所需长度 */
}

int32_t mb_ptrace_task_count(int32_t pid) {
  if (pid <= 0) return -(ERRNO_BASE + EINVAL);
  char path[PATH_MAX];
  int n = snprintf(path, sizeof(path), "/proc/%d/task", (int)pid);
  if (n <= 0 || (size_t)n >= sizeof(path)) return -(ERRNO_BASE + EINVAL);
  DIR *dir = opendir(path);
  if (dir == NULL) return errno_status();
  int32_t count = 0;
  struct dirent *ent;
  while ((ent = readdir(dir)) != NULL) {
    if (ent->d_name[0] != '.') count++;
  }
  closedir(dir);
  return count;
}
