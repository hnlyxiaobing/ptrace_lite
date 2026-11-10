/*
 * ptrace_lite — native C shim implementation (desktop stub).
 *
 * ！！重要标注：本文件是「桌面 stub」实现，真实 libc 转发留待 Linux / 设备阶段。
 * 它用可移植 C 代码模拟 tracee 句柄、内存页与 /proc 文本，使
 * moon build / moon test 在 Windows + MSVC 主机上真实编译、链接、运行。
 * 语义与 docs/API.md 一致；attach 的可失败路径通过模拟 pid 参数触发。
 *
 * 内部 shim 协议（与 MoonBit 侧 glue 共享，非公开 API）：
 *   - 返回值 0 或正数 = 成功（读写字节数 / 文本所需长度 / 线程数）。
 *   - 返回值负数 = 失败类别（语义标签，非 -errno 数值；真实路径须用
 *     -1000 - errno 通道，见 errno_map.mbt / FORWARDING.md §1.2）：
 *       -1 通用失败        -2 无此进程(语义 ESRCH)   -3 权限拒绝(语义 EPERM/EACCES)
 *       -4 SELinux 拒绝     -5 内核不支持(语义 ENOSYS) -6 已被本 tracer attach(语义 EBUSY)
 *       -7 参数/地址非法(语义 EINVAL) -8 句柄为空或已失效
 *   - mb_ptrace_read_maps 是 snprintf 语义：写入 min(所需长度, capacity) 字节，
 *     返回完整内容所需长度；capacity == 0 时为「就绪性探测」（不写入），用于
 *     attach 前区分 ProcessNotFound / AttachDenied / SelinuxDenied /
 *     UnsupportedKernel / AlreadyAttached。
 *   - read_maps 的内容是「/proc 文本包」：<maps 全文> + "__tasks__\n" +
 *     每线程一行 "<tid>\t<name>\t<state>\n"。MoonBit 侧 Target::maps 取前段
 *     交给 parse_maps，Target::threads 解析后段，线程数与 mb_ptrace_task_count
 *     交叉校验。
 *
 * 模拟 pid 约定（stub 特有，测试用参数触发各失败路径）：
 *   4242  正常可 attach 的 tracee（2 线程、4 个模拟内存区）
 *   4243  正常可 attach 的多页 tracee（1 线程、1 个三页区 0x40000-0x43000，
 *         用于端到端验证跨页分段拼接；与 4242 的 fixture 互不影响）
 *   7001  存在但 SELinux 拒绝
 *   7002  存在但内核不支持
 *   7003  存在但 ptrace/proc 权限拒绝
 *   其他  不存在
 *
 * 未来 Linux 真实路径（留待设备实测）：mb_ptrace_attach 转发 PTRACE_ATTACH +
 * waitpid，read/write 转发 process_vm_readv / process_vm_writev，read_maps 读
 * /proc/<pid>/maps 并按上述协议附加 /proc/<pid>/task 摘要，task_count 数
 * /proc/<pid>/task 条目。
 *
 * 不引入任何外部依赖；只用 libc 与 moonbit 运行时头（取数组长度做容量校验）。
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "moonbit.h"

/* ---- 状态码（内部协议） ---- */
#define MB_OK 0
#define MB_ERR_GENERIC (-1)
#define MB_ERR_NOTFOUND (-2)
#define MB_ERR_PERM (-3)
#define MB_ERR_SELINUX (-4)
#define MB_ERR_KERNEL (-5)
#define MB_ERR_BUSY (-6)
#define MB_ERR_INVAL (-7)
#define MB_ERR_HANDLE (-8)

/* ---- 模拟 pid ---- */
#define SIM_PID 4242
#define SIM_MULTIPAGE_PID 4243
#define SIM_SELINUX_PID 7001
#define SIM_KERNEL_PID 7002
#define SIM_DENIED_PID 7003

/* ---- 模拟内存区 ---- */
typedef struct {
  uint64_t start;
  uint64_t end; /* exclusive */
  uint32_t perms; /* bit0: read, bit1: write, bit2: exec, bit3: private */
  uint8_t *data;
} sim_region;

#define PERM_R 1u
#define PERM_W 2u
#define PERM_X 4u
#define PERM_P 8u

static uint8_t sim_heap[0x1000];
static uint8_t sim_code[0x100];
static uint8_t sim_res[0x1000];
static uint8_t sim_stack[0x1000];
/* 多页 fixture：3 页（0x40000-0x43000），用于端到端验证跨页分段拼接。
 * 与 SIM_PID 的 4 个单页区互不影响（4242 的 maps/测试保持原样）。 */
static uint8_t sim_big[0x3000];

static sim_region sim_regions[4];
static sim_region sim_big_regions[1];
static int sim_ready = 0;

static void sim_init(void) {
  if (sim_ready) return;
  for (size_t i = 0; i < sizeof(sim_heap); i++)
    sim_heap[i] = (uint8_t)('A' + (i % 26));
  for (size_t i = 0; i < sizeof(sim_code); i++)
    sim_code[i] = (uint8_t)i;
  memset(sim_res, 0, sizeof(sim_res));
  for (size_t i = 0; i < sizeof(sim_stack); i++)
    sim_stack[i] = (uint8_t)(255 - (i & 0xff));
  for (size_t i = 0; i < sizeof(sim_big); i++)
    sim_big[i] = (uint8_t)(0xA0 + (i % 16));
  sim_regions[0].start = 0x10000;
  sim_regions[0].end = 0x11000;
  sim_regions[0].perms = PERM_R | PERM_W | PERM_P;
  sim_regions[0].data = sim_heap;
  sim_regions[1].start = 0x20000;
  sim_regions[1].end = 0x20100;
  sim_regions[1].perms = PERM_R | PERM_X | PERM_P;
  sim_regions[1].data = sim_code;
  sim_regions[2].start = 0x30000;
  sim_regions[2].end = 0x31000;
  sim_regions[2].perms = PERM_R; /* shared, not private */
  sim_regions[2].data = sim_res;
  sim_regions[3].start = 0x7ffd4a5b0000ULL;
  sim_regions[3].end = 0x7ffd4a5b1000ULL;
  sim_regions[3].perms = PERM_R | PERM_W | PERM_P;
  sim_regions[3].data = sim_stack;
  sim_big_regions[0].start = 0x40000;
  sim_big_regions[0].end = 0x43000;
  sim_big_regions[0].perms = PERM_R | PERM_W | PERM_P;
  sim_big_regions[0].data = sim_big;
  sim_ready = 1;
}

/* 按 pid 选择模拟内存区集合（4242 = 4 个单页区；4243 = 1 个三页区）。 */
static int sim_regions_for(int32_t pid, sim_region **out) {
  sim_init();
  if (pid == SIM_MULTIPAGE_PID) {
    *out = sim_big_regions;
    return 1;
  }
  *out = sim_regions;
  return 4;
}

/* ---- 句柄表 ---- */
typedef struct {
  int32_t pid;
  int alive; /* 1 = 已 attach，0 = 已 detach（逻辑释放） */
} sim_tracee;

#define MAX_HANDLES 8
static sim_tracee *g_handles[MAX_HANDLES];

static sim_tracee *handle_lookup(void *handle) {
  if (handle == NULL) return NULL;
  for (int i = 0; i < MAX_HANDLES; i++) {
    if (g_handles[i] != NULL && (void *)g_handles[i] == handle &&
        g_handles[i]->alive)
      return g_handles[i];
  }
  return NULL;
}

static int sim_is_attached(int32_t pid) {
  for (int i = 0; i < MAX_HANDLES; i++) {
    if (g_handles[i] != NULL && g_handles[i]->alive && g_handles[i]->pid == pid)
      return 1;
  }
  return 0;
}

/* ---- /proc 文本包 ---- */
static const char sim_maps_text[] =
    "00010000-00011000 rw-p 00000000 00:00 0 [heap]\n"
    "00020000-00020100 r-xp 00001000 08:01 8888 /sim/lib/libtracee.so\n"
    "00030000-00031000 r--s 00000000 08:01 8888 /sim/lib/libtracee.so\n"
    "7ffd4a5b0000-7ffd4a5b1000 rw-p 00000000 00:00 0 [stack]\n";

static const char sim_task_text[] =
    "__tasks__\n"
    "4242\tsim-tracee\tS\n"
    "4250\tsim-worker\tS\n";

/* 多页 fixture 的 maps / task 文本（pid 4243）。 */
static const char sim_maps_text_big[] =
    "00040000-00043000 rw-p 00000000 00:00 0 [sim-big]\n";

static const char sim_task_text_big[] =
    "__tasks__\n"
    "4243\tsim-big\tS\n";

/* pid 存在性/可访问性；不可访问时返回负状态码 */
static int32_t sim_pid_status(int32_t pid) {
  sim_init();
  switch (pid) {
  case SIM_PID:
    return MB_OK;
  case SIM_MULTIPAGE_PID:
    return MB_OK;
  case SIM_SELINUX_PID:
    return MB_ERR_SELINUX;
  case SIM_KERNEL_PID:
    return MB_ERR_KERNEL;
  case SIM_DENIED_PID:
    return MB_ERR_PERM;
  default:
    return MB_ERR_NOTFOUND;
  }
}

/* ---- shim 实现 ---- */

void *mb_ptrace_attach(int32_t pid) {
  sim_init();
  if (sim_pid_status(pid) != MB_OK) return NULL;
  if (sim_is_attached(pid)) return NULL; /* 已被本 tracer attach */
  /* 优先复用已 detach 的死槽：句柄表是有限资源，反复 attach/detach 不得
   * 耗尽槽位（否则同一进程内第 9 次 attach 会假性失败为 AttachDenied）。
   * 死槽保留原指针，使 stale handle 仍能被 handle_lookup 判为失效。 */
  for (int i = 0; i < MAX_HANDLES; i++) {
    if (g_handles[i] != NULL && !g_handles[i]->alive) {
      g_handles[i]->pid = pid;
      g_handles[i]->alive = 1;
      return (void *)g_handles[i];
    }
  }
  for (int i = 0; i < MAX_HANDLES; i++) {
    if (g_handles[i] == NULL) {
      sim_tracee *t = (sim_tracee *)malloc(sizeof(sim_tracee));
      if (t == NULL) return NULL;
      t->pid = pid;
      t->alive = 1;
      g_handles[i] = t;
      return (void *)t;
    }
  }
  return NULL;
}

int32_t mb_ptrace_detach(void *handle) {
  sim_tracee *t = handle_lookup(handle);
  if (t == NULL) return MB_ERR_HANDLE;
  t->alive = 0; /* 逻辑释放：唯一释放点；标记失效以防悬挂句柄被再次使用 */
  return MB_OK;
}

int32_t mb_ptrace_read_mem(void *handle, uint64_t address, uint8_t *dst,
                           int32_t length) {
  sim_tracee *t = handle_lookup(handle);
  if (t == NULL) return MB_ERR_HANDLE;
  if (length < 0) return MB_ERR_INVAL;
  if (length == 0) return MB_OK;
  if ((uint64_t)length > (uint64_t)Moonbit_array_length(dst))
    return MB_ERR_INVAL; /* 容量不足 */
  uint64_t end_addr = address + (uint64_t)length;
  if (end_addr < address) return MB_ERR_INVAL; /* 地址溢出 */
  sim_region *regions = NULL;
  int region_count = sim_regions_for(t->pid, &regions);
  for (int i = 0; i < region_count; i++) {
    sim_region *r = &regions[i];
    if (r->start <= address && end_addr <= r->end) {
      memcpy(dst, r->data + (size_t)(address - r->start), (size_t)length);
      return length;
    }
  }
  return MB_ERR_INVAL; /* 非法/越界地址 */
}

int32_t mb_ptrace_write_mem(void *handle, uint64_t address, uint8_t *src,
                            int32_t length) {
  sim_tracee *t = handle_lookup(handle);
  if (t == NULL) return MB_ERR_HANDLE;
  if (length < 0) return MB_ERR_INVAL;
  if (length == 0) return MB_OK;
  if ((uint64_t)length > (uint64_t)Moonbit_array_length(src))
    return MB_ERR_INVAL; /* 容量不足 */
  uint64_t end_addr = address + (uint64_t)length;
  if (end_addr < address) return MB_ERR_INVAL; /* 地址溢出 */
  sim_region *regions = NULL;
  int region_count = sim_regions_for(t->pid, &regions);
  for (int i = 0; i < region_count; i++) {
    sim_region *r = &regions[i];
    if (r->start <= address && end_addr <= r->end) {
      if ((r->perms & PERM_W) == 0) return MB_ERR_INVAL; /* 页不可写（W^X） */
      memcpy(r->data + (size_t)(address - r->start), src, (size_t)length);
      return length;
    }
  }
  return MB_ERR_INVAL; /* 非法/越界地址 */
}

int32_t mb_ptrace_step(void *handle) {
  sim_tracee *t = handle_lookup(handle);
  if (t == NULL) return MB_ERR_HANDLE;
  return MB_OK; /* 模拟单步成功 */
}

int32_t mb_ptrace_read_maps(int32_t pid, uint8_t *dst, int32_t capacity) {
  sim_init();
  int32_t status = sim_pid_status(pid);
  if (status != MB_OK) return status;
  if (capacity < 0) return MB_ERR_INVAL;

  size_t maps_len = strlen(sim_maps_text);
  size_t task_len = strlen(sim_task_text);
  const char *maps_text = sim_maps_text;
  const char *task_text = sim_task_text;
  if (pid == SIM_MULTIPAGE_PID) {
    maps_text = sim_maps_text_big;
    task_text = sim_task_text_big;
    maps_len = strlen(maps_text);
    task_len = strlen(task_text);
  }
  int32_t required = (int32_t)(maps_len + task_len);

  if (capacity == 0) {
    /* 就绪性探测：能否与该 pid 交互（attach 前） */
    if (sim_is_attached(pid)) return MB_ERR_BUSY; /* 已被本 tracer attach */
    return required;
  }
  if ((uint64_t)capacity > (uint64_t)Moonbit_array_length(dst))
    return MB_ERR_INVAL; /* capacity 超出缓冲容量 */

  int32_t to_write = capacity < required ? capacity : required;
  size_t written = 0;
  if (written < (size_t)to_write) {
    size_t n = maps_len < (size_t)to_write - written ? maps_len
                                                     : (size_t)to_write - written;
    memcpy(dst + written, maps_text, n);
    written += n;
  }
  if (written < (size_t)to_write) {
    size_t n = task_len < (size_t)to_write - written ? task_len
                                                     : (size_t)to_write - written;
    memcpy(dst + written, task_text, n);
    written += n;
  }
  return required; /* snprintf 语义：返回所需长度 */
}

int32_t mb_ptrace_task_count(int32_t pid) {
  sim_init();
  int32_t status = sim_pid_status(pid);
  if (status != MB_OK) return status;
  if (pid == SIM_MULTIPAGE_PID) return 1; /* sim-big 主线程 */
  return 2; /* sim-tracee 主线程 + sim-worker */
}
