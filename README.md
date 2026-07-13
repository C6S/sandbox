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

Nix-specific defaults (the `/nix` mounts, and where they exist `/etc/static`
and a `/usr/bin/env` shim from the system profile) apply only when a nix
store is detected (`/nix/store` exists).

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
   `default.cfg` shipped with the package (`SANDBOX_DEFAULT_CFG` overrides
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
| `bind` | empty | Flat pairs of `src dest`: host `src` bind-mounted read-write at `dest` inside. |
| `overlay` | empty | Flat pairs of `path store`: `path` acts read-write inside, but writes land in host `store` instead of `path`. |
| `mask` | empty | Paths hidden even where a bind exposes them: dirs become an empty tmpfs, files a read-only `/dev/null`. Masked even if absent on the host. |
| `link` | empty | Flat pairs of `target linkpath`: symlinks created inside. |
| `env` | `( inherit )` | Flat pairs of `NAME value`. |
| `net` | `1` | `--share-net`. `0` isolates the network. |
| `seccomp` | `default` | Filter to load: `default`, `allow-userns`, or `none`. |
| `pre` / `post` | empty | Commands eval'd outside the sandbox, before launch / after exit. |

`mask` mounts over paths that would otherwise be visible through an enclosing
bind — the same mechanism systemd uses for masking. Whether a path gets the
tmpfs or the `/dev/null` treatment is decided by what it is on the host,
resolved through the `bind` pairs so masks under a bind dest work. A path
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

A missing `ro`, `rw`, `bind`, or `overlay` source path fails the launch.

Appending to `env` keeps the host environment and sets the named variables.
Replacing the array (dropping the `inherit` sentinel) clears the environment
instead; `HOME`/`TERM`/`PATH`/`SHELL` are kept, and your pairs can override
them.

`pre`/`post` are meant for things like btrfs snapshots around a session. A
failing `pre` aborts the launch; `post` runs on normal exit, not when the
wrapper is killed by a signal.

Inside the sandbox, `$SANDBOX` points at the cfg — a cheap "am I sandboxed?"
check.

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
variants, env inherit/replace, links, extra binds, `bind` pairs, overlays,
masks, `pre`/`post` hooks, and
the refusal paths), launches a sandbox on each, and runs `inside.sh` inside.
It must run from an unsandboxed shell — the default seccomp profile blocks
the nested user namespaces bwrap needs:

```sh
bash test/outside.sh
```
