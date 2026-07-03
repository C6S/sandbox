#define _GNU_SOURCE
#include <seccomp.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h> /* arch-correct TIOCSTI / TIOCLINUX */
#include <sched.h>     /* arch-correct CLONE_NEWUSER */

/* Fallbacks only if the headers above don't define them; the header
   value is authoritative and per-arch correct where it exists. */
#ifndef TIOCSTI
#define TIOCSTI 0x5412
#endif
#ifndef TIOCLINUX
#define TIOCLINUX 0x541C
#endif
#ifndef CLONE_NEWUSER
#define CLONE_NEWUSER 0x10000000
#endif

int main(int argc, char **argv) {
  /* "allow-userns" omits the user-namespace/mount rules; any other
     profile name (i.e. "default") gets the full rule set — fail closed. */
  int allow_userns = (argc > 1 && strcmp(argv[1], "allow-userns") == 0);
  scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
  if (!ctx) return 1;

  /* Cover the build arch's co-resident 32-bit ABI(s) too. Without this a
     program could reach a denied syscall via a compat entry point (int
     0x80 on x86_64, the 32-bit ARM ABI on aarch64) and bypass the native
     rules, since a non-matching arch falls through to the default ALLOW.
     These tokens are arch-specific, so add only what the build arch
     exposes; other arches (riscv64, ppc64, s390x, ...) build native-only.
     seccomp_rule_add (below) applies each rule to every configured arch,
     skipping any arch where a given syscall does not exist. */

#if defined(__x86_64__)
  seccomp_arch_add(ctx, SCMP_ARCH_X86);
  seccomp_arch_add(ctx, SCMP_ARCH_X32);
#elif defined(__aarch64__)
  seccomp_arch_add(ctx, SCMP_ARCH_ARM);
#endif

  const char *deny[] = {
    "add_key", "keyctl", "request_key",
    "bpf", "userfaultfd", "perf_event_open",
    "open_by_handle_at", "name_to_handle_at", "kcmp", "ptrace",
    "process_vm_readv", "process_vm_writev",
    "init_module", "finit_module", "delete_module",
    "kexec_load", "kexec_file_load", "reboot",
    "iopl", "ioperm", "swapon", "swapoff", "acct",
    "settimeofday", "adjtimex", "clock_adjtime",
    "uselib", "personality", "_sysctl", "sysfs", "ustat", "nfsservctl",
    NULL
  };

  for (int i = 0; deny[i]; i++) {
    int nr = seccomp_syscall_resolve_name(deny[i]);
    if (nr != __NR_SCMP_ERROR)
      seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), nr, 0);
  }

  seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(ioctl), 1,
                   SCMP_A1(SCMP_CMP_EQ, TIOCSTI));
  seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(ioctl), 1,
                   SCMP_A1(SCMP_CMP_EQ, TIOCLINUX));

  if (!allow_userns) {
    /* Block new user namespaces without touching ordinary fork/threads:
       only match calls whose flags request CLONE_NEWUSER. This filters
       arg 0 (flags), which holds for x86_64/i386/x32/arm/aarch64; a few
       arches (e.g. s390) put flags elsewhere, so strict userns blocking
       is only validated on the arches above. */
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(clone), 1,
                     SCMP_A0(SCMP_CMP_MASKED_EQ, CLONE_NEWUSER, CLONE_NEWUSER));
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(unshare), 1,
                     SCMP_A0(SCMP_CMP_MASKED_EQ, CLONE_NEWUSER, CLONE_NEWUSER));

    /* clone3 hides its flags in a struct we cannot inspect from seccomp;
       return ENOSYS so libc falls back to clone(), which is filtered. */
    int nr_clone3 = seccomp_syscall_resolve_name("clone3");
    if (nr_clone3 != __NR_SCMP_ERROR)
      seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), nr_clone3, 0);

    const char *mnt[] = {
      "mount", "umount2", "pivot_root", "move_mount", "open_tree",
      "fsopen", "fsconfig", "fsmount", "mount_setattr", NULL
    };

    for (int i = 0; mnt[i]; i++) {
      int nr = seccomp_syscall_resolve_name(mnt[i]);
      if (nr != __NR_SCMP_ERROR)
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), nr, 0);
    }
  }

  seccomp_export_bpf(ctx, STDOUT_FILENO);
  seccomp_release(ctx);

  return 0;
}
