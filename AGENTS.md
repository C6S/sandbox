# Agent / maintainer notes

Working notes for this repo — conventions, checks, and the design rationale
that doesn't belong in the user-facing README. Pending work lives in
`TODO.md`.

## Ground rules

- Do not run git commits; the human commits.
- `seccomp-gen.c` stays a standalone C file compiled in the `buildPhase`.
  Do not inline it into the nix as a string or heredoc: nix/nixfmt re-indent
  multi-line `''` strings, which can shift a heredoc terminator off column 0
  and silently break the build. A real file has no indentation-sensitive
  terminator.

## Layout

| File | Contents |
|---|---|
| `src/sandbox.sh` | The wrapper: config discovery, toggles, fd-10 seccomp filter selection (`$seccomp.bpf`), bwrap invocation. |
| `src/seccomp-gen.c` | libseccomp-based generator emitting `default.bpf` / `allow-userns.bpf`. |
| `src/package.nix` | `stdenv.mkDerivation` recipe: compiles the generator, runs it, installs `sandbox.sh` with `@sandboxSeccompDir@` substituted, wraps PATH (bwrap/coreutils/zsh), shellchecks in `checkPhase`. |
| `default.nix` | `callPackage ./src/package.nix { }` for classic `nix-build` (repo root). |
| `flake.nix` | Exposes `packages.<system>.default` (repo root). |
| `test/inside.sh` | In-sandbox enforcement checks; not installed by the package. |
| `test/outside.sh` | Cfg matrix driver: generates dummy dirs/cfgs, launches sandboxes, runs `inside.sh` in each; must run unsandboxed. |

`src/package.nix` takes `sandboxSrc ? ./.` instead of plain `src` because
callPackage would fill `src` from the nixpkgs top-level alias. The `./.`
default resolves relative to `package.nix`, i.e. to `src/`, so tarball
consumers don't need to pass it.

## Checks

```sh
nix build   # or nix-build; compiles the generator, emits both blobs,
            # shellchecks sandbox.sh in checkPhase

# Lint the script standalone (substitute the placeholder first):
sed 's#@sandboxSeccompDir@#/nix/store/x-sandbox-seccomp#' \
  src/sandbox.sh | shellcheck /dev/stdin

nixfmt --check src/package.nix default.nix flake.nix
statix check && deadnix .

# Runtime enforcement, from inside a sandbox (invoke via `bash`:
# /usr/bin/env does not exist inside, so the shebang can't resolve):
sandbox -- bash test/inside.sh

# Cfg matrix, from an unsandboxed shell (nested bwrap is blocked inside):
bash test/outside.sh
```

## seccomp design

The kernel checks a classic-BPF program on every syscall the sandboxed
process makes. The program is compiled at nix build time by `package.nix`
(from `seccomp-gen.c`, using libseccomp) and shipped as a precompiled blob;
the script opens the blob on fd 10 and passes `--seccomp 10` to bwrap, which
installs it for the child. Compiling at build time means a mistake fails the
consumer's build loudly instead of shipping a broken or no-op filter, and
the runtime needs no extra tools.

Rules return `EPERM` (not `SIGKILL`) so a blocked call is debuggable rather
than a silent process death.

### Base denylist (both profiles)

Kernel-attack-surface / rarely-needed syscalls, EPERM:

`add_key keyctl request_key` · `bpf userfaultfd perf_event_open` ·
`open_by_handle_at name_to_handle_at kcmp ptrace` ·
`process_vm_readv process_vm_writev` ·
`init_module finit_module delete_module` · `kexec_load kexec_file_load reboot` ·
`iopl ioperm swapon swapoff acct` · `settimeofday adjtimex clock_adjtime` ·
`uselib personality _sysctl sysfs ustat nfsservctl`.

Plus argument-filtered ioctls: `ioctl(TIOCSTI)` and `ioctl(TIOCLINUX)` — the
terminal command-injection vector (pushing characters into the controlling
TTY that the parent shell runs after the sandbox exits).

### `default`-only additions

- `clone` / `unshare` filtered on the `CLONE_NEWUSER` flag (masked-EQ on
  arg 0), so creating a user namespace is blocked while ordinary
  fork/threads (which don't set that flag) are untouched. Blanket-blocking
  `clone` would break everything — this deliberately does not.
- `clone3` → `ENOSYS` (its flags live in a struct seccomp can't read),
  forcing libc to fall back to the filtered `clone`.
- Mount machinery: `mount umount2 pivot_root move_mount open_tree fsopen
  fsconfig fsmount mount_setattr`, EPERM.

The recommended policy is `seccomp=default` everywhere: a coding agent has
no reason to run podman, and podman-in-a-sandbox is exactly what the default
profile is meant to stop (rootless podman needs a user namespace to map
subuids). `nix build` inside the sandbox is unaffected because the build's
namespace setup happens in the nix daemon, outside bwrap, reached over the
bound `/nix` socket.

### Multi-ABI coverage (the 32-bit hole)

A filter configured only for the native arch is bypassable: a process can
issue a denied syscall via a compat entry point (`int 0x80` for the i386
ABI, or the x32 ABI on x86_64) under a different arch token, which falls
through to the default ALLOW. The generator therefore adds the build arch's
co-resident 32-bit ABI(s) before adding rules — `SCMP_ARCH_X86` +
`SCMP_ARCH_X32` on x86_64, `SCMP_ARCH_ARM` on aarch64; other arches build
native-only. `seccomp_rule_add` (the lenient variant, vs `_add_exact`) then
emits every rule for all configured ABIs, resolving per-arch syscall numbers
and skipping arches where a syscall doesn't exist.

### Architecture / portability

The blob encodes syscall numbers (and, for TIOCSTI, an ioctl request
value), so it's architecture-specific, not host-specific. Rather than
maintain a per-arch list, the filter is built natively: the derivation
compiles on whatever system builds it, so the constants come from that
arch's headers (`<sys/ioctl.h>`, `<sched.h>`; the `#define` fallbacks are
inert where the headers define them). Hosts sharing an arch share one build
via nix; an aarch64 host builds a correct aarch64 filter for free.

Two caveats baked into the source: the TIOCSTI value diverges on
mips/ppc/sparc/alpha (fine on x86/arm/aarch64/riscv), and the
`CLONE_NEWUSER` arg-0 clone filter assumes flags-in-arg0 (true for
x86_64/i386/x32/arm/aarch64, not s390) — so the default profile's userns
blocking is validated only on those arches.

### Host sysctl

`dev.tty.legacy_tiocsti = 0` (NixOS:
`boot.kernel.sysctl."dev.tty.legacy_tiocsti" = 0;`) disables the legacy
TIOCSTI ioctl host-wide on kernel ≥ 6.2. Belt-and-suspenders with the
seccomp rule: the sysctl protects the whole host, the seccomp rule protects
the sandbox even on a host that lacks the sysctl. `test/inside.sh`
distinguishes the two layers by errno (seccomp EPERM vs sysctl EIO).

## Not done / future hardening

- `--new-session` is intentionally not used: it drops the controlling TTY
  (killing the same TIOCSTI class) but breaks job control, `sudo`/`ssh`/`gpg`
  password prompts, and window-resize — bad for a wrapper around an
  interactive TUI. The seccomp ioctl filter plus the sysctl cover TIOCSTI
  without that cost.
- The default-ALLOW model means foreign-ABI calls to non-denied syscalls are
  still allowed — identical to the native-ABI posture, so no new risk, but
  it is not a `SystemCallArchitectures=native`-style whitelist.
- A single universal multi-arch blob is intentionally avoided: it would
  carry dead branches for unreachable arches and hit per-arch correctness
  traps (TIOCSTI value, clone arg order). Native-per-arch builds are simpler
  and correct by construction; a non-nix distribution should ship per-arch
  prebuilt blobs selected by `uname -m`.
- Non-nix distros are out of scope for now. The seccomp machinery is
  portable C (a Makefile against `libseccomp-dev` would cover the build),
  but the default read-only binds are NixOS paths, and the hide-by-omission
  model means other distros need a different base set (`/usr`, `/bin`,
  `/lib`, select `/etc`) — likely via `--ro-bind-try` plus per-distro
  skeleton cfgs.
