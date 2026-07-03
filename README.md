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

The defaults assume NixOS.

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

| Var | Default | Meaning |
|---|---|---|
| `tmpfs` | `/tmp`, `$HOME` | Fresh tmpfs mounts. |
| `ro` | `/nix`, `/run/current-system`, select `/etc` files | Read-only binds. |
| `rw` | empty | Read-write binds. |
| `link` | empty | Flat pairs of `target linkpath`: symlinks created inside. |
| `env` | `( inherit )` | Flat pairs of `NAME value`. |
| `net` | `1` | `--share-net`. `0` isolates the network. |
| `seccomp` | `default` | Filter to load: `default`, `allow-userns`, or `none`. |
| `pre` / `post` | empty | Commands eval'd outside the sandbox, before launch / after exit. |

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
    url = "https://github.com/C6S/sandbox/archive/refs/tags/v0.1.0.tar.gz";
    sha256 = "..."; # set to lib.fakeSha256, build once, copy the real hash
  };
in
pkgs.callPackage "${src}/src/package.nix" { }
```

Versions are published as GitHub releases, so update checkers can read
`releases/latest`.

## Verifying

`test/enforce.sh` checks a live sandbox from the inside: binds, tmpfs,
hide-by-omission, network, and the seccomp profile (including TIOCSTI and
`keyctl` probes). Run it from this repo:

```sh
sandbox -- bash test/enforce.sh
```

Exit 0 means the loaded cfg is enforced as declared.
