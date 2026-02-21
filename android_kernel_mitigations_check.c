#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <sys/xattr.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <linux/keyctl.h>
#include <linux/userfaultfd.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <sched.h>

/* Test each heap spray syscall / android debugging feature / exploit primitive */

/* ---- helpers ---- */

static void read_sysctl(const char *label, const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) {
        printf("  %-28s %s\n", label, strerror(errno));
        return;
    }
    char val[128] = {0};
    fgets(val, sizeof(val), f);
    fclose(f);
    /* strip trailing newline */
    val[strcspn(val, "\n")] = 0;
    printf("  %-28s %s\n", label, val);
}

static int read_int(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    int v = -1;
    fscanf(f, "%d", &v);
    fclose(f);
    return v;
}

static void try_dev(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd >= 0) {
        printf("  %-28s ACCESSIBLE\n", path);
        close(fd);
    } else {
        printf("  %-28s %s\n", path, strerror(errno));
    }
}

/* ---- heap spray primitives ---- */

static void test_keyctl(void) {
    char payload[] = "AAAA";
    long key = syscall(__NR_add_key, "user", "test",
                       payload, 4, -2 /* KEY_SPEC_PROCESS_KEYRING */);
    if (key < 0)
        printf("  add_key:       BLOCKED (%s)\n", strerror(errno));
    else {
        printf("  add_key:       OK (key=%ld)\n", key);
        syscall(__NR_keyctl, KEYCTL_REVOKE, (int)key);
    }
}

static void test_msgq(void) {
    int qid = msgget(IPC_PRIVATE, IPC_CREAT | 0600);
    if (qid < 0) {
        printf("  msgget:        BLOCKED (%s)\n", strerror(errno));
        return;
    }
    struct { long mtype; char mtext[64]; } msg;
    msg.mtype = 1;
    memset(msg.mtext, 'A', 64);
    if (msgsnd(qid, &msg, 64, 0) < 0)
        printf("  msgsnd:        BLOCKED (%s)\n", strerror(errno));
    else
        printf("  msgsnd:        OK\n");
    msgctl(qid, IPC_RMID, NULL);
}

static void test_pipe(void) {
    int fds[2];
    if (pipe(fds) < 0) {
        printf("  pipe:          BLOCKED (%s)\n", strerror(errno));
        return;
    }
    printf("  pipe:          OK\n");
    close(fds[0]); close(fds[1]);
}

static void test_socket(void) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        printf("  socket(UNIX):  BLOCKED (%s)\n", strerror(errno));
    else {
        printf("  socket(UNIX):  OK\n");
        close(fd);
    }

    fd = socket(AF_NETLINK, SOCK_RAW, 0);
    if (fd < 0)
        printf("  socket(NL):    BLOCKED (%s)\n", strerror(errno));
    else {
        printf("  socket(NL):    OK\n");
        close(fd);
    }

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        printf("  socket(INET):  BLOCKED (%s)\n", strerror(errno));
    else {
        printf("  socket(INET):  OK\n");
        close(fd);
    }
}

static void test_xattr(void) {
    /* setxattr on /data/local/tmp file — allocates in kmalloc */
    int fd = open("/data/local/tmp/.xattr_test", O_CREAT|O_WRONLY, 0666);
    if (fd >= 0) close(fd);
    char val[128];
    memset(val, 'X', sizeof(val));
    if (setxattr("/data/local/tmp/.xattr_test", "user.test", val, sizeof(val), 0) < 0)
        printf("  setxattr:      BLOCKED (%s)\n", strerror(errno));
    else {
        printf("  setxattr:      OK\n");
        removexattr("/data/local/tmp/.xattr_test", "user.test");
    }
    unlink("/data/local/tmp/.xattr_test");
}

static void test_sendmsg_cmsg(void) {
    /* SCM_RIGHTS via unix socket — allocates skb in kmalloc */
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        printf("  socketpair:    BLOCKED (%s)\n", strerror(errno));
        return;
    }
    printf("  socketpair:    OK\n");

    /* Send a dummy fd via SCM_RIGHTS */
    int dummy = open("/dev/null", O_RDONLY);
    if (dummy >= 0) {
        char buf[1] = {'X'};
        struct iovec iov = { .iov_base = buf, .iov_len = 1 };
        char cmsg_buf[CMSG_SPACE(sizeof(int))];
        struct msghdr msg = {
            .msg_iov = &iov, .msg_iovlen = 1,
            .msg_control = cmsg_buf, .msg_controllen = sizeof(cmsg_buf),
        };
        struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(cmsg), &dummy, sizeof(int));
        if (sendmsg(sv[0], &msg, 0) < 0)
            printf("  sendmsg(SCM):  BLOCKED (%s)\n", strerror(errno));
        else
            printf("  sendmsg(SCM):  OK\n");
        close(dummy);
    }
    close(sv[0]); close(sv[1]);
}

/* ---- race/timing primitives ---- */

static void test_userfaultfd(void) {
    long fd = syscall(__NR_userfaultfd, 0);
    if (fd < 0) {
        printf("  userfaultfd(0):BLOCKED (%s)\n", strerror(errno));
        /* Try user-mode only */
        fd = syscall(__NR_userfaultfd, 1 /* UFFD_USER_MODE_ONLY */);
        if (fd < 0)
            printf("  userfaultfd(U):BLOCKED (%s)\n", strerror(errno));
        else {
            printf("  userfaultfd(U):OK\n");
            close(fd);
        }
    } else {
        printf("  userfaultfd(0):OK (full)\n");
        close(fd);
    }
}

static void test_epoll(void) {
    int fd = syscall(__NR_epoll_create1, 0);
    if (fd < 0)
        printf("  epoll_create:  BLOCKED (%s)\n", strerror(errno));
    else {
        printf("  epoll_create:  OK\n");
        close(fd);
    }
}

static void test_timerfd(void) {
    int fd = syscall(__NR_timerfd_create, 1 /* CLOCK_MONOTONIC */, 0);
    if (fd < 0)
        printf("  timerfd:       BLOCKED (%s)\n", strerror(errno));
    else {
        printf("  timerfd:       OK\n");
        close(fd);
    }
}

static void test_signalfd(void) {
    unsigned long long mask = 0;
    int fd = syscall(__NR_signalfd4, -1, &mask, 8, 0);
    if (fd < 0)
        printf("  signalfd:      BLOCKED (%s)\n", strerror(errno));
    else {
        printf("  signalfd:      OK\n");
        close(fd);
    }
}

static void test_clone_unshare(void) {
    if (syscall(__NR_unshare, 0x10000000 /* CLONE_NEWUSER */) < 0)
        printf("  unshare(USER): BLOCKED (%s)\n", strerror(errno));
    else
        printf("  unshare(USER): OK\n");
}

/* ---- privilege escalation helpers ---- */

static void test_bpf(void) {
    long ret = syscall(__NR_bpf, 0 /* BPF_MAP_CREATE */, NULL, 0);
    if (ret < 0 && errno == EPERM)
        printf("  bpf:           BLOCKED (EPERM)\n");
    else if (ret < 0 && errno == EACCES)
        printf("  bpf:           BLOCKED (EACCES/SELinux)\n");
    else if (ret < 0)
        printf("  bpf:           returned %ld (%s) — syscall exists\n", ret, strerror(errno));
    else
        printf("  bpf:           OK\n");
}

#ifndef __NR_io_uring_setup
#if defined(__aarch64__)
#define __NR_io_uring_setup 425
#elif defined(__x86_64__)
#define __NR_io_uring_setup 425
#elif defined(__i386__)
#define __NR_io_uring_setup 425
#endif
#endif

static void test_io_uring(void) {
#ifdef __NR_io_uring_setup
    /* entries=1, params=NULL will fail with EFAULT if syscall exists */
    long ret = syscall(__NR_io_uring_setup, 1, NULL);
    if (ret < 0 && (errno == EPERM || errno == EACCES))
        printf("  io_uring:      BLOCKED (%s)\n", strerror(errno));
    else if (ret < 0 && errno == ENOSYS)
        printf("  io_uring:      NOT IN KERNEL\n");
    else if (ret < 0)
        printf("  io_uring:      returned %ld (%s) — syscall exists\n", ret, strerror(errno));
    else {
        printf("  io_uring:      OK\n");
        close(ret);
    }
#else
    printf("  io_uring:      N/A (no syscall number)\n");
#endif
}

static void test_ptrace(void) {
    pid_t child = fork();
    if (child < 0) {
        printf("  ptrace:        fork failed (%s)\n", strerror(errno));
        return;
    }
    if (child == 0) {
        /* child: sleep briefly then exit */
        usleep(200000);
        _exit(0);
    }
    /* parent: try to attach */
    if (ptrace(PTRACE_ATTACH, child, NULL, NULL) < 0) {
        printf("  ptrace:        BLOCKED (%s)\n", strerror(errno));
    } else {
        printf("  ptrace:        OK\n");
        ptrace(PTRACE_DETACH, child, NULL, NULL);
    }
    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
}

static void test_cross_memory(void) {
    char buf[16] = {0};
    struct iovec local = { .iov_base = buf, .iov_len = sizeof(buf) };
    struct iovec remote = { .iov_base = buf, .iov_len = sizeof(buf) };
    /* read from our own process via syscall (avoids libc wrapper issues) */
    long n = syscall(__NR_process_vm_readv, (long)getpid(), &local, 1UL, &remote, 1UL, 0UL);
    if (n < 0)
        printf("  process_vm_readv: BLOCKED (%s)\n", strerror(errno));
    else
        printf("  process_vm_readv: OK\n");
}

/* ---- info leak sources ---- */

static void test_proc_info(void) {
    FILE *f;
    char line[256];

    f = fopen("/proc/timer_list", "r");
    if (f) { printf("  /proc/timer_list: READABLE\n"); fclose(f); }
    else printf("  /proc/timer_list: %s\n", strerror(errno));

    f = fopen("/proc/sched_debug", "r");
    if (f) { printf("  /proc/sched_debug: READABLE\n"); fclose(f); }
    else printf("  /proc/sched_debug: %s\n", strerror(errno));

    f = fopen("/proc/slabinfo", "r");
    if (f) { printf("  /proc/slabinfo: READABLE\n"); fclose(f); }
    else printf("  /proc/slabinfo: %s\n", strerror(errno));

    f = fopen("/proc/kallsyms", "r");
    if (f) {
        if (fgets(line, sizeof(line), f)) {
            unsigned long addr = 0;
            sscanf(line, "%lx", &addr);
            printf("  /proc/kallsyms: %s\n", addr ? "REAL ADDRS" : "zeroed (kptr_restrict)");
        }
        fclose(f);
    } else printf("  /proc/kallsyms: %s\n", strerror(errno));

    f = fopen("/proc/iomem", "r");
    if (f) {
        int has_data = 0;
        while (fgets(line, sizeof(line), f)) {
            unsigned long s;
            if (sscanf(line, " %lx-", &s) == 1 && s != 0) has_data = 1;
        }
        printf("  /proc/iomem: %s\n", has_data ? "REAL ADDRS" : "zeroed");
        fclose(f);
    } else printf("  /proc/iomem: %s\n", strerror(errno));

    f = fopen("/proc/version", "r");
    if (f) {
        if (fgets(line, sizeof(line), f))
            printf("  /proc/version: READABLE\n");
        fclose(f);
    } else printf("  /proc/version: %s\n", strerror(errno));

    f = fopen("/proc/pagetypeinfo", "r");
    if (f) { printf("  /proc/pagetypeinfo: READABLE\n"); fclose(f); }
    else printf("  /proc/pagetypeinfo: %s\n", strerror(errno));

    f = fopen("/proc/vmallocinfo", "r");
    if (f) { printf("  /proc/vmallocinfo: READABLE\n"); fclose(f); }
    else printf("  /proc/vmallocinfo: %s\n", strerror(errno));
}

/* ---- sysctl / hardening knobs ---- */

static void test_sysctls(void) {
    read_sysctl("kptr_restrict:",          "/proc/sys/kernel/kptr_restrict");
    read_sysctl("dmesg_restrict:",         "/proc/sys/kernel/dmesg_restrict");
    read_sysctl("perf_event_paranoid:",    "/proc/sys/kernel/perf_event_paranoid");
    read_sysctl("randomize_va_space:",     "/proc/sys/kernel/randomize_va_space");
    read_sysctl("mmap_min_addr:",          "/proc/sys/vm/mmap_min_addr");
    read_sysctl("unprivileged_bpf:",       "/proc/sys/kernel/unprivileged_bpf_disabled");
    read_sysctl("modules_disabled:",       "/proc/sys/kernel/modules_disabled");
    read_sysctl("kexec_load_disabled:",    "/proc/sys/kernel/kexec_load_disabled");
    read_sysctl("panic_on_oops:",          "/proc/sys/kernel/panic_on_oops");
    read_sysctl("sysrq:",                  "/proc/sys/kernel/sysrq");
}

/* ---- SELinux ---- */

static void test_selinux(void) {
    int enforce = read_int("/sys/fs/selinux/enforce");
    if (enforce < 0) {
        printf("  selinux:       not found (disabled or not mounted)\n");
        return;
    }
    printf("  selinux:       %s\n", enforce ? "ENFORCING" : "PERMISSIVE !!!");

    /* read our own context */
    FILE *f = fopen("/proc/self/attr/current", "r");
    if (f) {
        char ctx[256] = {0};
        fgets(ctx, sizeof(ctx), f);
        fclose(f);
        ctx[strcspn(ctx, "\n")] = 0;
        printf("  context:       %s\n", ctx);
    }
}

/* ---- device nodes ---- */

static void test_dev_access(void) {
    try_dev("/dev/mem");
    try_dev("/dev/kmem");
    try_dev("/dev/port");
    try_dev("/dev/binder");
    try_dev("/dev/hwbinder");
    try_dev("/dev/vndbinder");
    try_dev("/dev/dma_heap");
}

/* ---- Android properties ---- */

static void test_android_props(void) {
    /* Read properties from /system files since __system_property_get
       requires linking against libcutils. These files are always readable. */
    const char *props[] = {
        "ro.build.type",
        "ro.build.version.security_patch",
        "ro.debuggable",
        "ro.secure",
        "ro.adb.secure",
        "ro.boot.verifiedbootstate",
        "ro.boot.veritymode",
        "ro.boot.flash.locked",
        "ro.crypto.state",
        "ro.hardware.chipname",
        NULL,
    };

    for (int i = 0; props[i]; i++) {
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "getprop %s 2>/dev/null", props[i]);
        FILE *p = popen(cmd, "r");
        if (p) {
            char val[128] = {0};
            fgets(val, sizeof(val), p);
            pclose(p);
            val[strcspn(val, "\n")] = 0;
            if (val[0])
                printf("  %-36s %s\n", props[i], val);
            else
                printf("  %-36s (empty)\n", props[i]);
        }
    }
}

/* ---- /proc/config.gz ---- */

static void test_kernel_config(void) {
    /* Try /proc/config.gz first, then /boot/config-$(uname -r) */
    FILE *f = NULL;
    char cmd[256];

    if (access("/proc/config.gz", R_OK) == 0) {
        printf("  /proc/config.gz: READABLE — dumping security options:\n\n");
        f = popen("zcat /proc/config.gz", "r");
    } else {
        /* try uncompressed config */
        struct { char s[128]; } u;
        FILE *uf = popen("uname -r", "r");
        if (uf) {
            fgets(u.s, sizeof(u.s), uf);
            pclose(uf);
            u.s[strcspn(u.s, "\n")] = 0;
            snprintf(cmd, sizeof(cmd), "/boot/config-%s", u.s);
            if (access(cmd, R_OK) == 0) {
                printf("  %s: READABLE — dumping security options:\n\n", cmd);
                f = fopen(cmd, "r");
            }
        }
    }

    if (!f) {
        printf("  kernel config: NOT AVAILABLE\n");
        return;
    }

    /* Config options we care about and their security meaning */
    const char *configs[] = {
        /* heap hardening */
        "CONFIG_SLAB_FREELIST_RANDOM",
        "CONFIG_SLAB_FREELIST_HARDENED",
        "CONFIG_SHUFFLE_PAGE_ALLOCATOR",
        "CONFIG_INIT_ON_ALLOC_DEFAULT_ON",
        "CONFIG_INIT_ON_FREE_DEFAULT_ON",
        "CONFIG_INIT_STACK_ALL",
        "CONFIG_INIT_STACK_ALL_ZERO",
        /* control flow */
        "CONFIG_CFI_CLANG",
        "CONFIG_CFI_PERMISSIVE",
        "CONFIG_SHADOW_CALL_STACK",
        "CONFIG_ARM64_BTI",
        "CONFIG_ARM64_PTR_AUTH",
        "CONFIG_ARM64_MTE",
        "CONFIG_STACKPROTECTOR",
        "CONFIG_STACKPROTECTOR_STRONG",
        /* KASLR / ASLR */
        "CONFIG_RANDOMIZE_BASE",
        "CONFIG_RANDOMIZE_MODULE_REGION_FULL",
        /* attack surface reduction */
        "CONFIG_IO_URING",
        "CONFIG_USER_NS",
        "CONFIG_BPF_SYSCALL",
        "CONFIG_BPF_JIT",
        "CONFIG_BPF_JIT_ALWAYS_ON",
        "CONFIG_BPF_UNPRIV_DEFAULT_OFF",
        "CONFIG_USERFAULTFD",
        /* kernel module loading */
        "CONFIG_MODULES",
        "CONFIG_MODULE_SIG",
        "CONFIG_MODULE_SIG_FORCE",
        "CONFIG_SECURITY_LOADPIN",
        "CONFIG_STATIC_USERMODEHELPER",
        /* memory protection */
        "CONFIG_HARDENED_USERCOPY",
        "CONFIG_FORTIFY_SOURCE",
        "CONFIG_STRICT_KERNEL_RWX",
        "CONFIG_STRICT_MODULE_RWX",
        "CONFIG_RODATA_FULL_DEFAULT_ENABLED",
        "CONFIG_ARM64_SW_TTBR0_PAN",
        "CONFIG_ARM64_PAN",
        "CONFIG_ARM64_UAO",
        "CONFIG_VMAP_STACK",
        /* debugging / info leaks */
        "CONFIG_DEBUG_KERNEL",
        "CONFIG_DEBUG_INFO",
        "CONFIG_KASAN",
        "CONFIG_KASAN_GENERIC",
        "CONFIG_KASAN_SW_TAGS",
        "CONFIG_KASAN_HW_TAGS",
        "CONFIG_UBSAN",
        "CONFIG_KCOV",
        "CONFIG_DEBUG_LIST",
        "CONFIG_BUG_ON_DATA_CORRUPTION",
        "CONFIG_IKCONFIG",
        "CONFIG_IKCONFIG_PROC",
        "CONFIG_KALLSYMS",
        "CONFIG_KALLSYMS_ALL",
        /* LSM / SELinux */
        "CONFIG_SECURITY",
        "CONFIG_SECURITY_SELINUX",
        "CONFIG_DEFAULT_SECURITY",
        /* namespace / sandbox */
        "CONFIG_SECCOMP",
        "CONFIG_SECCOMP_FILTER",
        /* misc exploit targets */
        "CONFIG_DEVMEM",
        "CONFIG_DEVKMEM",
        "CONFIG_DEVPORT",
        "CONFIG_ACPI_CUSTOM_METHOD",
        "CONFIG_PROC_KCORE",
        NULL,
    };

    /* Read entire config into memory for fast lookup */
    char *config_buf = NULL;
    size_t config_sz = 0;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        size_t len = strlen(line);
        config_buf = realloc(config_buf, config_sz + len + 1);
        memcpy(config_buf + config_sz, line, len + 1);
        config_sz += len;
    }
    /* popen or fopen */
    if (access("/proc/config.gz", R_OK) == 0)
        pclose(f);
    else
        fclose(f);

    if (!config_buf) {
        printf("  (empty config)\n");
        return;
    }

    for (int i = 0; configs[i]; i++) {
        char pattern_y[128], pattern_m[128], pattern_n[128];
        snprintf(pattern_y, sizeof(pattern_y), "%s=y", configs[i]);
        snprintf(pattern_m, sizeof(pattern_m), "%s=m", configs[i]);
        snprintf(pattern_n, sizeof(pattern_n), "# %s is not set", configs[i]);

        /* also check for string values like CONFIG_DEFAULT_SECURITY="selinux" */
        char pattern_eq[128];
        snprintf(pattern_eq, sizeof(pattern_eq), "%s=", configs[i]);

        if (strstr(config_buf, pattern_y)) {
            printf("  %-44s y\n", configs[i]);
        } else if (strstr(config_buf, pattern_m)) {
            printf("  %-44s m\n", configs[i]);
        } else if (strstr(config_buf, pattern_n)) {
            printf("  %-44s n\n", configs[i]);
        } else {
            /* check for =<value> (strings, numbers) */
            char *p = strstr(config_buf, pattern_eq);
            if (p) {
                char val[128] = {0};
                p += strlen(pattern_eq);
                int j = 0;
                while (p[j] && p[j] != '\n' && j < 127) { val[j] = p[j]; j++; }
                printf("  %-44s %s\n", configs[i], val);
            }
            /* if not found at all, skip — not all configs exist on all kernels */
        }
    }

    free(config_buf);
}

/* ---- main ---- */

int main(void) {
    printf("=== Exploit Primitive Availability Test ===\n");
    printf("uid=%d gid=%d\n\n", getuid(), getgid());

    printf("[Heap spray primitives]\n");
    test_keyctl();
    test_msgq();
    test_pipe();
    test_socket();
    test_xattr();
    test_sendmsg_cmsg();

    printf("\n[Race/timing primitives]\n");
    test_userfaultfd();
    test_epoll();
    test_timerfd();
    test_signalfd();
    test_clone_unshare();

    printf("\n[Privilege escalation helpers]\n");
    test_bpf();
    test_io_uring();
    test_ptrace();
    test_cross_memory();

    printf("\n[Info leak sources]\n");
    test_proc_info();

    printf("\n[Sysctl hardening]\n");
    test_sysctls();

    printf("\n[SELinux]\n");
    test_selinux();

    printf("\n[Device nodes]\n");
    test_dev_access();

    printf("\n[Kernel cmdline (key params)]\n");
    FILE *f = fopen("/proc/cmdline", "r");
    if (f) {
        char cmdline[4096] = {0};
        fread(cmdline, 1, sizeof(cmdline)-1, f);
        fclose(f);
        const char *params[] = {"init_on_alloc=", "init_on_free=", "kasan=",
                                "norandmaps", "arm64.nomte", "cgroup_disable=",
                                "cgroup.memory=", "lockdown=", "lsm=",
                                "slub_debug=", "page_poison=", NULL};
        for (int i = 0; params[i]; i++) {
            char *p = strstr(cmdline, params[i]);
            if (p) {
                char val[64] = {0};
                int j = 0;
                while (p[j] && p[j] != ' ' && j < 63) { val[j] = p[j]; j++; }
                printf("  %s\n", val);
            }
        }
    }

    printf("\n[Android properties]\n");
    test_android_props();

    printf("\n[Kernel config]\n");
    test_kernel_config();

    return 0;
}
