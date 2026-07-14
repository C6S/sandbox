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

## Resource caps

`slice` / `limit` wrap the final exec in `systemd-run --user --scope`.
Scope, not service, is load-bearing: systemd-run allocates the unit and then
`execvp`s in place, so the PID, the controlling TTY, the exit status and the
inherited seccomp fd 10 all pass through to bwrap untouched. A `--service`
would hand the process to the user manager, detaching it from the terminal —
useless for a wrapper around an interactive shell.

Costs and caveats, all of them quiet failures:

- `exec -a "$1"` (argv[0] rewriting, so the sandbox shows up under the
  command's name rather than as `bwrap`) does not survive the scope path:
  systemd-run builds its child's argv itself. Uncapped launches keep it.
- The `--` terminating systemd-run's options is required, not cosmetic:
  bwrap's first argument is `--proc`, which a permuting getopt would claim.
- An undelegated controller accepts its property and ignores it — `CPUQuota=`
  is the usual victim. See the README for the delegation check.
- A named-but-undefined slice is created implicitly with no limits, so
  `slice=` alone caps nothing.
- `--collect` matters: a sandbox OOM-killed by `MemoryMax` leaves a failed
  scope unit behind without it.

Not enforced by `test/outside.sh` — the cfg matrix would need a live systemd
user session, and the in-sandbox checks can't see the cgroup they're in
(`/sys/fs/cgroup` isn't bound). Verify by hand with `--show-command`, and with
`systemd-cgls --user-unit` from a second terminal while a sandbox runs.

## Portability

Target is glibc + FHS + systemd, plus NixOS. `default.cfg` probes the host
instead of assuming a layout; the branch is chosen by `/run/current-system/sw`
(NixOS) vs `/usr/bin` (FHS), with the `/nix/store` binds independent of both so
nix-on-Debian gets a store *and* an FHS tree.

Things that bit, and must keep being respected:

- **The whole model inverts on FHS.** Hide-by-omission means an unbound `/usr`
  is not a degraded sandbox, it is one with no libc and no shell — nothing
  runs. NixOS gets away with binding only the store because the store *is* the
  toolchain.
- **Merged-`/usr`.** On Debian/Arch, `/bin` and `/lib` are symlinks into
  `/usr`. Binding them resolves the symlink and materializes a real directory,
  which is not the layout the dynamic linker's hardcoded interpreter path
  (`/lib64/ld-linux-x86-64.so.2`) expects. They go in `link`, not `ro`. Which
  case applies is probed per entry (`-L` before `-d`), not assumed per distro.
- **glibc needs `/etc/ld.so.cache`** to find libraries outside its builtin
  search path, and `/etc/nsswitch.conf` to resolve users and hosts. NixOS needs
  neither, so neither was in the base list.
- **No `[[ … ]] && arr+=( … )` guards in a cfg.** A trailing `&&` whose test
  fails makes `source` return non-zero, and the wrapper's `set -e` then aborts
  the launch with no message. This was a live bug: `default.cfg` ended in the
  env-shim guard, so the wrapper died silently on every non-NixOS host. Use
  `if`/`fi` — an `if` with a false condition returns 0.
- **The stock `/etc` entries are existence-guarded.** A missing `ro` source is
  a hard failure by design, but `/etc/ssl`, `/etc/localtime` and
  `/etc/resolv.conf` are each absent on some stock install, and the default
  policy must not fail a launch over one. Paths a *cfg* names explicitly still
  hard-fail.

Untested: musl (different linker paths), non-systemd (works, but `slice`/`limit`
degrade to a warning). No non-nix build exists — `package.nix` is the only way
to get a seccomp blob, so FHS support is currently "the policy is right if you
can build it". A `Makefile` against `libseccomp-dev` is the missing piece.

The FHS branches cannot be exercised on a NixOS host: `test/outside.sh` sees
only the layout it runs on, and nested bwrap is blocked by the default seccomp
profile, so a synthetic root can't be entered either. The logic was validated
by re-rooting the cfg's absolute paths at a fake tree and sourcing it; real
coverage needs a run on each target distro.

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
- The non-nix *build* is still missing; only the runtime policy is portable.
  The seccomp machinery is portable C, so a Makefile against `libseccomp-dev`
  covers it — compile the generator, emit both blobs, install `sandbox.sh`
  with the two `@…@` placeholders substituted. See Portability above.
