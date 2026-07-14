# Sandbox – a simple bubblewrap wrapper

`sandbox` runs a command (default: `$SHELL`) inside a
[bubblewrap](https://github.com/containers/bubblewrap) sandbox configured by
the nearest `.sandbox.cfg`. It exists to confine AI coding agents: the
agent's launcher goes through `sandbox`, while your own shell stays
unsandboxed.

The sandbox hides by omission. `$HOME` and `/tmp` are fresh tmpfs, `/nix`
and a few `/etc` files are read-only, and everything else simply doesn't
exist inside — no permission errors, just absence. A project's cfg binds the
project itself read-write plus whatever else it needs. On top of that, a
seccomp filter blocks rarely-needed kernel attack surface and the
TIOCSTI/TIOCLINUX terminal-injection ioctls.

The stock policy adapts to the host it runs on, since "everything else doesn't
exist inside" only works if the toolchain is bound in explicitly. On NixOS
that means `/nix/store` plus `/etc/static` and the system profile's
`/usr/bin/env` shim. On an FHS distro it means `/usr` and whichever of
`/bin`, `/sbin`, `/lib*` are real directories — on a merged-`/usr` system
those are symlinks into `/usr`, and are recreated as symlinks rather than
bound — plus the glibc bits (`/etc/ld.so.cache`, `/etc/nsswitch.conf`) that
NixOS has no use for. A nix store on a non-NixOS host gets both. Targets
glibc + FHS + systemd; see [Portability](#portability).

## Usage

```
sandbox                      open $SHELL sandboxed in the current directory
sandbox subdir/              open $SHELL sandboxed in subdir
sandbox -- cmd args          run cmd sandboxed in the current directory
sandbox subdir/ -- cmd args  run cmd sandboxed in subdir
```

`LOGLEVEL` (syslog-style: 3=err, 6=info, 7=debug; default 3) controls wrapper
logging. `LOGLEVEL=6` shows the resolved decisions, `LOGLEVEL=7` every bind
and the final bwrap command.

Three flags inspect instead of launching (nothing runs, not even `pre`
hooks): `--show-config` prints the resolved policy — all layers applied —
as sourceable cfg syntax; `--show-config-#` prints the same `#`-prefixed,
handy for documenting the inherited baseline in a project cfg
(`sandbox --show-config-# >> .sandbox.cfg`); `--show-command` prints the
bwrap invocation that would run.

## Configuration

The wrapper walks up from the working directory to the nearest
`.sandbox.cfg` and refuses to run without one. The cfg is plain bash sourced
over the defaults, so it can append (`+=`) or replace them. `$DIR` (the
cfg's directory), `$CFG` (its path), and `$HOME` are in scope.

```sh
# .sandbox.cfg
rw+=(
  "$DIR"                # the project itself
  "$HOME/.claude"       # agent state
)
ro+=( "$HOME/.config/git" )
env+=( HISTFILE "$DIR/.zsh_history" )
```

Configs are sourced in layers, each appending to or overriding the last:

1. the default policy — `/etc/sandbox.cfg` when present, otherwise the stock
   `default.cfg` shipped with the package (`SANDBOX_CFG_DEFAULT` overrides
   the path outright);
2. the optional per-user `$XDG_CONFIG_HOME/sandbox/default.cfg`
   (`~/.config/…` when unset);
3. the project `.sandbox.cfg`.

The table shows the stock defaults.

| Var | Default | Meaning |
|---|---|---|
| `tmpfs` | `/tmp`, `$HOME` | Fresh tmpfs mounts. |
| `ro` | select `/etc` files; with a nix store also `/nix/store`, `/nix/var/nix`, `/etc/static` | Read-only binds. |
| `rw` | empty | Read-write binds. |
| `dev` | empty | Device nodes passed through read-write (`/dev/kvm`, `/dev/dri/*`). Ordinary binds cannot carry a usable device. |
| `overlay` | empty | `path:store` pairs: `path` acts read-write inside, but writes land in host `store` instead of `path`. |
| `mask` | empty | Paths hidden even where a bind exposes them: dirs become an empty tmpfs, files a `/dev/null` bind (writes are swallowed). Masked even if absent on the host. |
| `link` | empty | `target:linkpath` pairs: symlinks created inside. |
| `env` | `( inherit )` | Flat pairs of `NAME value`. |
| `net` | `1` | `--share-net`. `0` isolates the network. |
| `seccomp` | `default` | Filter to load: `default`, `allow-userns`, or `none`. |
| `slice` | empty | systemd slice the sandbox is placed under. Limits on the slice cap all sandboxes in it together. |
| `limit` | empty | Flat pairs of `Property value` (`MemoryMax 4G`, `CPUQuota 200%`, …) capping this sandbox alone. |
| `pre` / `post` | empty | Commands eval'd outside the sandbox, before launch / after exit. |

An `ro`/`rw`/`dev` entry is normally a single path, mounted at the same path
inside. Writing it as `src:dest` (split on the first colon) mounts host
`src` at `dest` inside instead — e.g.
`ro+=( "$HOME/.config/foo:/etc/foo" )`. `overlay` and `link` entries use
the same `a:b` syntax, always as pairs. A literal colon in a path is
escaped as `\:`; the entry must be quoted, since bash strips the
backslash from unquoted words before the cfg value is seen.

`dev` exists because bubblewrap mounts an unprivileged bind `nodev`: a device
node listed in `ro`/`rw` shows up inside, but opening it returns `EACCES`.
Entries here are bound with the `nodev` flag dropped, which is why device
passthrough is its own array rather than something `rw` infers from the inode
— it is a policy decision the cfg should state outright. Devices are handed
through read-write (KVM is driven by `ioctl` on a writable fd). A `dev` entry
also needs the host-side permissions to match: `/dev/kvm` is typically
`root:kvm 0660`, so the user must be in the `kvm` group.

`mask` mounts over paths that would otherwise be visible through an enclosing
bind — the same mechanism systemd uses for masking. Whether a path gets the
tmpfs or the `/dev/null` treatment is decided by what it is on the host,
resolved through any `src:dest` pairs so masks under a relocated dest work. A path
absent on the host is masked anyway (as `/dev/null`), so a file appearing
later is already shadowed; bubblewrap creates the missing mountpoint itself,
which leaves an empty placeholder file on the host when the path sits under
a `rw` bind, and fails the launch when it sits under a `ro` one.

`overlay` mounts `path` as an overlayfs with the host path as the read-only
lower layer and `store` as the upper: the sandbox sees a writable `path`, but
the host copy is never touched — modified files are copied up into `store`
whole, deletions become whiteout character devices there, and the overlaid
state persists across launches. `store` is created on demand, along with the
`<store>.work` scratch directory overlayfs requires on the same filesystem.
Unprivileged overlayfs needs kernel ≥ 5.11.

A missing `ro`, `rw`, `dev`, or `overlay` source path fails the launch.

Appending to `env` keeps the host environment and sets the named variables.
Replacing the array (dropping the `inherit` sentinel) clears the environment
instead; `HOME`/`TERM`/`PATH`/`SHELL` are kept, and your pairs can override
them.

`pre`/`post` are meant for things like btrfs snapshots around a session. A
failing `pre` aborts the launch; `post` runs on normal exit, not when the
wrapper is killed by a signal.

## Resource caps

Bubblewrap does namespaces and seccomp, not cgroups, so a runaway process
inside the sandbox can still eat the host's RAM and CPU. Setting `slice` or
`limit` launches bwrap inside a transient systemd scope
(`systemd-run --user --scope`), which puts the sandbox and everything it
spawns in a cgroup the kernel enforces limits on.

```sh
# .sandbox.cfg
slice=sandbox.slice  # aggregate ceiling, shared with every other sandbox
limit+=(             # per-sandbox ceiling, this project only
  MemoryHigh 3G      # throttle + reclaim above this
  MemoryMax  4G      # hard limit; the cgroup is OOM-killed at it
  CPUQuota   200%    # two cores' worth
  TasksMax   512
)
```

The two answer different questions. `limit` entries are properties of the
sandbox's own scope, so each sandbox gets its own private ceiling — but N
sandboxes then get N times the limit. `slice` places that scope under a shared
slice, and limits on the *slice* apply to everything in it collectively: one
budget, however many sandboxes are open. Use `limit` to stop one sandbox
running away, `slice` to stop all of them together outgrowing the machine.
Any [resource-control property][rc] systemd accepts on a scope works.

[rc]: https://www.freedesktop.org/software/systemd/man/systemd.resource-control.html

Two things to know, because both fail quietly:

**A slice carries no limits until a slice unit gives it some.** Naming a slice
that doesn't exist doesn't fail — systemd creates it implicitly, with no
limits, and caps nothing. The numbers live in a unit:

```nix
# NixOS, alongside the package's own config
systemd.user.slices.sandbox = {
  description = "Aggregate resource ceiling for all sandboxes";
  sliceConfig = {
    MemoryHigh = "6G";
    MemoryMax = "8G";
    CPUQuota = "400%";
  };
};
```

**A limit only bites for a controller systemd has delegated to your user
manager.** `memory` and `pids` are delegated by default; `cpu` frequently is
not, and an undelegated `CPUQuota=` is accepted and then silently ignored.
Check what you have:

```sh
cat /sys/fs/cgroup/user.slice/user-$UID.slice/cgroup.controllers
```

If `cpu` is missing, delegate it:

```nix
systemd.services."user@".serviceConfig.Delegate = "cpu cpuset io memory pids";
```

Grouping is useful on its own even without limits: `systemctl --user status
sandbox.slice` lists every running sandbox, `systemctl --user stop
sandbox.slice` kills them all, and `systemd-cgtop` shows live usage per
sandbox.

On a host with no systemd user session (a non-systemd distro, a bare `ssh`
without lingering), the caps cannot be applied. The sandbox still launches —
seccomp and the namespaces are unaffected — and logs a warning; run with
`LOGLEVEL=4` to see it.

Inside the sandbox, `$SANDBOX` points at the cfg — a cheap "am I sandboxed?"
check.

## Portability

Supported: **glibc + FHS + systemd** Linux, and NixOS. The stock `default.cfg`
detects which system tree it is on rather than assuming one:

| Host | What the default policy binds |
|---|---|
| NixOS | `/nix/store`, `/nix/var/nix`, `/etc/static`, the `/usr/bin/env` shim. `/usr` is *not* bound — it holds nothing else. |
| FHS (Debian, Arch, Fedora, …) | `/usr`, plus each of `/bin`, `/sbin`, `/lib`, `/lib32`, `/lib64`, `/libx32` that is a real directory. Merged-`/usr` symlinks are recreated as symlinks. Plus the glibc lookup files: `/etc/ld.so.cache`, `/etc/ld.so.conf{,.d}`, `/etc/nsswitch.conf`, `/etc/alternatives`. |
| nix on an FHS distro | Both: the store *and* the FHS tree. |

Every host also gets the `/etc` identity, network, trust, and time files —
`passwd`, `group`, `hosts`, `resolv.conf`, `localtime`, and the CA bundle
wherever the distro keeps it (`ssl`, `pki`, `ca-certificates`) — each bound
only where it exists. A missing `ro` source normally fails the launch, which is
the right behaviour for a path a cfg named explicitly, but none of these is
universal (`/etc/ssl` is absent on some Fedora installs, `/etc/localtime` on a
fresh Arch), and the default policy must not fail a launch over one.

Known gaps: **musl** (Alpine) is untested — the linker paths differ.
**Non-systemd** hosts (OpenRC, runit) work, but `slice`/`limit` cannot be
enforced there and degrade to a warning. Building outside nix has no supported
path yet: `package.nix` is the only build, so a non-nix host has no way to
produce the seccomp blobs. A `Makefile` against `libseccomp-dev` is the
missing piece.

## seccomp

Two precompiled filters ship with the package. `default` denies a list of
kernel-attack-surface syscalls, the terminal-injection ioctls, mounts, and
the creation of user namespaces; `allow-userns` drops the userns/mount rules
for projects that need rootless podman or nested bubblewrap inside the
sandbox. `none` disables filtering. Denied calls fail with `EPERM` rather
than killing the process, so breakage is debuggable.

The filters are compiled at package build time with libseccomp, so a broken
filter fails your build instead of silently launching unfiltered. Design
details — profile contents, 32-bit ABI coverage, portability caveats — live
in [AGENTS.md](AGENTS.md).


## Using from a Nix config

The flake works directly: `nix build github:C6S/sandbox`. For a non-flake
config, pin a release tarball and build it with your own `pkgs` using the
recipe inside the tarball — `builtins.fetchTarball` fetches at eval time, so
there's no flake input and no import-from-derivation:

```nix
let
  src = builtins.fetchTarball {
    url = "https://github.com/C6S/sandbox/archive/refs/tags/v0.1.2.tar.gz";
    sha256 = "..."; # set to lib.fakeSha256, build once, copy the real hash
  };
in
pkgs.callPackage "${src}/src/package.nix" { }
```

Versions are published as GitHub releases, so update checkers can read
`releases/latest`.

## Verifying

`test/inside.sh` checks a live sandbox from the inside: binds, tmpfs,
hide-by-omission, network, and the seccomp profile (including TIOCSTI and
`keyctl` probes). Run it from this repo:

```sh
sandbox -- bash test/inside.sh
```

Exit 0 means the loaded cfg is enforced as declared.

`test/outside.sh` covers the cfg matrix from the outside: it generates dummy
project directories with various `.sandbox.cfg` files (net isolation, seccomp
variants, env inherit/replace, links, extra binds, `src:dest` pairs, overlays,
masks, `pre`/`post` hooks, and
the refusal paths), launches a sandbox on each, and runs `inside.sh` inside.
It must run from an unsandboxed shell — the default seccomp profile blocks
the nested user namespaces bwrap needs:

```sh
bash test/outside.sh
```
