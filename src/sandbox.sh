#!/usr/bin/env bash
set -euo pipefail

# Directory of precompiled seccomp BPF filters. The @sandboxSeccompDir@ placeholder
# is substituted with a nix store path at build time by package.nix.
# The `seccomp` config var names the filter to load ("$seccomp.bpf"); both
# filters deny rarely-needed kernel-attack-surface syscalls and the
# TIOCSTI/TIOCLINUX terminal-injection ioctls:
#   default      - also blocks new user namespaces + the mount syscalls
#   allow-userns - allows them, for projects running rootless podman or
#                  nested nix/bubblewrap builds
# seccomp=none (overridable in a .sandbox.cfg) disables filtering entirely.
SECCOMP_DIR="@sandboxSeccompDir@"

usage() {
  cat <<EOF
Usage: $(basename "$0") [option] [dir] [-- command [args...]]
       $(basename "$0") --help

  dir   Directory to sandbox into (default: current directory)
  --    Separator before the command to run inside the sandbox
        Without --, opens \$SHELL inside the sandbox

Options:
  --show-config    print the resolved config (all layers applied) and exit
  --show-config-#  same, but #-prefixed, e.g. to document the inherited
                   policy: $(basename "$0") --show-config-# >> .sandbox.cfg
  --show-command   print the bwrap command that would run, without running it

Examples:
  $(basename "$0")                     open shell in current directory
  $(basename "$0") subdir/             open shell in subdir
  $(basename "$0") -- cmd args         run cmd in current directory
  $(basename "$0") subdir/ -- cmd args run cmd in subdir
EOF
}

# Syslog-style severities: 3=err 4=warn 6=info 7=debug. Messages at or below
# LOGLEVEL (default 3, errors only) are printed; call sites pass the level
# (default 6). LOGLEVEL=6 shows decisions, LOGLEVEL=7 every bind/env and the
# final bwrap command.
log() {
	if [[ ${LOGLEVEL:-3} -ge ${2:-6} ]]; then
	  echo "$1" >&2
	fi
}

# Parse leading args: an optional mode flag and an optional dir, in any
# order, up to the -- separator.
DIR="$PWD"
MODE=run
while [[ $# -ge 1 && "$1" != "--" ]]; do
  case "$1" in
    --help)
      usage
      exit 0
      ;;
    --show-config)    MODE=show-config ;;
    --show-config-\#) MODE=show-config-commented ;;
    --show-command)   MODE=show-command ;;
    -*)
      log "Unknown option: $1" 3
      exit 1
      ;;
    *)
      if [[ -d "$1" ]]; then
        DIR="$(readlink -f "$1")"
        cd "$DIR" || { echo "Cannot enter directory: $DIR" >&2; exit 1; }
      else
        log "Not a directory: $1" 3
        exit 1
      fi
      ;;
  esac
  shift
done

# find config: walk up from PWD to the closest .sandbox.cfg
while :; do
  if [[ -f "$DIR/.sandbox.cfg" ]]; then
    CFG="$DIR/.sandbox.cfg"
    break
  fi
  if [[ "$DIR" == "/" || -z "$DIR" ]]; then
    log "Unable to find sandbox config" 3
    exit 1
  fi
  DIR="${DIR%/*}"
done

log "DIR=$DIR"

# Config variables, sourced in layers, each appending to or overriding the
# previous: the default policy (/etc/sandbox.cfg when present, otherwise the
# stock default.cfg shipped with the package; SANDBOX_CFG_DEFAULT overrides
# the path outright), then the optional per-user default.cfg under XDG,
# then the project cfg. Declared empty here only so set -u (and shellcheck)
# survive a default cfg that drops entries — the policy itself lives in the
# cfgs.
args=()
tmpfs=()
ro=()
rw=()
dev=()
overlay=()
mask=()
link=()
env=( inherit )
pre=()
post=()
net=1
seccomp=default
slice=
limit=()

CFG_DEFAULT="${SANDBOX_CFG_DEFAULT:-/etc/sandbox.cfg}"
if [[ ! -f "$CFG_DEFAULT" ]]; then
  CFG_DEFAULT="@sandboxDefaultCfg@"
fi
log "SOURCE: $CFG_DEFAULT" 6
# shellcheck disable=SC1090
source "$CFG_DEFAULT"

CFG_USER="${XDG_CONFIG_HOME:-$HOME/.config}/sandbox/default.cfg"
if [[ -f "$CFG_USER" ]]; then
  log "SOURCE: $CFG_USER" 6
  # shellcheck disable=SC1090
  source "$CFG_USER"
fi

log "SOURCE: $CFG" 6
# shellcheck disable=SC1090
source "$CFG"

# Cfg paths may contain "." or ".." segments (e.g. "$DIR/../shared"), which
# both bwrap's mountpoint creation and the mask prefix matching below
# take literally. Normalize them lexically (-s: no symlink resolution, so
# NixOS symlinks like /etc/resolv.conf keep binding the symlink path itself;
# -m: allow paths that don't exist yet).
normalize() {
  local -n paths="$1"
  local i
  for (( i=0; i<${#paths[@]}; i++ )); do
    paths[i]="$(realpath -sm -- "${paths[i]}")"
  done
}
normalize tmpfs
normalize mask

# ro/rw/dev entries are either a single path (mounted at the same path inside)
# or a SRC:DEST pair splitting on the first colon (host SRC appears at DEST
# inside); overlay and link entries are always pairs (PATH:STORE and
# TARGET:LINKPATH). A literal colon in a path is written \: — effective
# only inside quotes, since bash eats the backslash in unquoted words
# before the cfg value reaches us. Entries stay in escaped form in the
# arrays (so later splits and --show-config keep working); split_mount
# decodes one entry into src/dest via a sentinel byte no path can contain.
# For a plain entry both halves come out identical.
split_mount() {
  local entry="${1//\\:/$'\x01'}"
  src="${entry%%:*}"
  dest="${entry#*:}"
  src="${src//$'\x01'/:}"
  dest="${dest//$'\x01'/:}"
}
normalize_mounts() {
  local -n mounts="$1"
  local i src dest
  for (( i=0; i<${#mounts[@]}; i++ )); do
    split_mount "${mounts[i]}"
    src="$(realpath -sm -- "$src")"
    dest="$(realpath -sm -- "$dest")"
    if [[ "$src" == "$dest" ]]; then
      mounts[i]="${src//:/\\:}"
    else
      mounts[i]="${src//:/\\:}:${dest//:/\\:}"
    fi
  done
}
normalize_mounts ro
normalize_mounts rw
normalize_mounts dev
normalize_mounts overlay

# link targets stay literal (they may be deliberately dangling or relative);
# only the linkpath side is normalized.
for (( i=0; i<${#link[@]}; i++ )); do
  split_mount "${link[i]}"
  dest="$(realpath -sm -- "$dest")"
  link[i]="${src//:/\\:}:${dest//:/\\:}"
done

# --show-config[-#]: print the resolved (layered, normalized) policy as
# sourceable cfg syntax and exit. Pair arrays print two elements per line.
if [[ "$MODE" == show-config* ]]; then
  comment=""
  [[ "$MODE" == show-config-commented ]] && comment="# "
  show_array() {
    local -n elements="$1"
    local per_line="$2" i
    if (( ${#elements[@]} == 0 )); then
      printf '%s%s=()\n' "$comment" "$1"
      return
    fi
    printf '%s%s=(\n' "$comment" "$1"
    for (( i=0; i<${#elements[@]}; i+=per_line )); do
      printf '%s ' "$comment"
      printf ' %q' "${elements[@]:i:per_line}"
      printf '\n'
    done
    printf '%s)\n' "$comment"
  }
  show_array args 2
  show_array tmpfs 1
  show_array ro 1
  show_array rw 1
  show_array dev 1
  show_array overlay 1
  show_array mask 1
  show_array link 1
  # env may lead with the lone "inherit" sentinel; keep it on its own line
  # so the NAME-value pairs after it stay aligned
  if [[ "${env[0]:-}" == "inherit" ]]; then
    printf '%senv=(\n%s  inherit\n' "$comment" "$comment"
    for (( i=1; i<${#env[@]}; i+=2 )); do
      printf '%s ' "$comment"
      printf ' %q' "${env[@]:i:2}"
      printf '\n'
    done
    printf '%s)\n' "$comment"
  else
    show_array env 2
  fi
  show_array pre 1
  show_array post 1
  show_array limit 2
  printf '%snet=%q\n' "$comment" "$net"
  printf '%sseccomp=%q\n' "$comment" "$seccomp"
  printf '%sslice=%q\n' "$comment" "$slice"
  exit 0
fi

if [[ "$net" == "1" ]]; then
	log "NET: ENABLED" 6
  args+=( --share-net )
else
	log "NET: DISABLED" 6
fi

SECCOMP_FILTER=""
if [[ "$seccomp" == "none" ]]; then
	log "SECCOMP: DISABLED" 6
else
  SECCOMP_FILTER="$SECCOMP_DIR/$seccomp.bpf"
  if [[ ! -e "$SECCOMP_FILTER" ]]; then
    log "SECCOMP: filter not found ($SECCOMP_FILTER)" 3
    exit 1
  fi
	log "SECCOMP: ENABLED ($SECCOMP_FILTER)" 6
  # Open the filter on fd 10; the exec'd bwrap inherits it and reads its
  # BPF program from there.
  exec 10<"$SECCOMP_FILTER"
  args+=( --seccomp 10 )
fi

if [[ "${env[0]:-}" == "inherit" ]]; then
	# env was only appended to
  env=( "${env[@]:1}" )
else
	# env's "inherit" was replaced: clear the environment and prepend the
	# base vars to env[], so the loop below handles everything uniformly and
	# cfg-declared pairs can override the base ones (later --setenv wins).
	log "CLEARING ENVIRONMENT VARIABLES" 6
  args+=( --clearenv )
  env=(
    HOME "$HOME"
    TERM "${TERM:-xterm}"
    PATH "$PATH"
    SHELL "${SHELL:-zsh}"
    "${env[@]}"
  )
fi

for (( i=0; i<${#env[@]}; i+=2 )); do
  log "ENV: ${env[i]}=${env[i+1]}" 7
  args+=( --setenv "${env[i]}" "${env[i+1]}" )
done

for mount in "${tmpfs[@]}"; do
  log "TMPFS: $mount" 7
  args+=( --tmpfs "$mount" )
done

# bwrap creates a bind's mountpoint but not a missing parent directory for
# it: a bind under a nonexistent dir (e.g. a file bound into /bin on a host
# where only /usr/bin exists) is silently dropped. The namespace root is
# writable, so have bwrap mkdir -p the parent first; --dir is a no-op when
# the directory already exists.
ensure_parent() {
  local parent
  parent="$(dirname -- "$1")"
  if [[ "$parent" != "/" ]]; then
    args+=( --dir "$parent" )
  fi
}

for mount in "${ro[@]}"; do
  split_mount "$mount"
	log "RO: $src -> $dest" 7
  ensure_parent "$dest"
  args+=( --ro-bind "$src" "$dest" )
done

for mount in "${rw[@]}"; do
  split_mount "$mount"
	log "RW: $src -> $dest" 7
  ensure_parent "$dest"
  args+=( --bind "$src" "$dest" )
done

# Device passthrough (/dev/kvm, /dev/dri/*, ...). The ro/rw binds above are
# mounted nodev by unprivileged bwrap, so a device node bound through them
# exists but every open() of it returns EACCES — same trap the /dev/null
# masks below sidestep. --dev-bind is bwrap's only opt-out, and since it
# drops nodev for that mount, exposing a device is a policy decision the cfg
# has to state outright rather than something an rw entry infers from the
# inode type. Writable: KVM is driven by ioctls on a rw fd, and bwrap has no
# --ro-dev-bind. Entries land after rw so a device can be handed through a
# path an rw bind covers, and before the masks so a mask still shadows it.
for mount in "${dev[@]}"; do
  split_mount "$mount"
	log "DEV: $src -> $dest" 7
  ensure_parent "$dest"
  args+=( --dev-bind "$src" "$dest" )
done

# Overlays act like rw binds that divert writes: the host path becomes the
# read-only lower layer of an overlayfs, and writes go to the store dir
# instead (modified files as copied-up whole files, deletions as whiteout
# character devices). The store and the empty work dir overlayfs requires
# on the same filesystem (kept beside the store as "<store>.work") are
# created here on first use.
for mount in "${overlay[@]}"; do
  split_mount "$mount"
  path="$src"
  store="$dest"
	log "OVERLAY: $path -> $store" 7
  if [[ "$MODE" == "run" ]]; then
    mkdir -p "$store" "$store.work"
  fi
  args+=( --overlay-src "$path" --overlay "$store" "$store.work" "$path" )
done

# Masks shadow whatever the binds above exposed (later mounts win in bwrap):
# directories get an empty tmpfs, files a /dev/null bind — the same
# mechanism systemd uses for masking. The device needs --dev-bind: plain
# binds are mounted nodev in unprivileged bwrap, turning any open of the
# masked file into EACCES; dev-bound, reads see EOF and writes are
# swallowed like a real /dev/null. A mask is emitted even for paths absent
# on the host, so a file appearing later is already shadowed; bwrap creates
# the missing mountpoint itself, which leaves an empty placeholder on the
# host under a rw bind and fails the launch under a ro one. Dir-vs-file is
# decided on the host, after translating the path through any relocating
# ro/rw pairs so masks under a pair's dest resolve against the real source.
for mount in "${mask[@]}"; do
  hostpath="$mount"
  for entry in "${rw[@]}" "${ro[@]}"; do
    split_mount "$entry"
    if [[ "$mount" == "$dest" || "$mount" == "$dest"/* ]]; then
      hostpath="$src${mount#"$dest"}"
      break
    fi
  done
  if [[ -d "$hostpath" ]]; then
	  log "MASK (tmpfs): $mount" 7
    ensure_parent "$mount"
    args+=( --tmpfs "$mount" )
  else
	  log "MASK (null): $mount" 7
    ensure_parent "$mount"
    args+=( --dev-bind /dev/null "$mount" )
  fi
done

for mount in "${link[@]}"; do
  split_mount "$mount"
	log "LINK: $src -> $dest" 7
  args+=( --symlink "$src" "$dest" )
done

# Mount CFG read-only and set SANDBOX as the last step. SANDBOX is for easy
# "am I sandboxed?" detection. Only the project cfg is exposed inside — the
# default/user layers it was sourced over are not.
log "RO $CFG" 7
args+=( --ro-bind "$CFG" "$CFG" )
log "ENV: SANDBOX=$CFG" 7
args+=( --setenv SANDBOX "$CFG" )

[[ $# -ge 1 && "$1" == "--" ]] && shift
[[ $# -ge 1 ]] || set -- "${SHELL:-zsh}"

# Resource caps. bwrap does namespaces and seccomp, not cgroups, so a cap can
# only come from the cgroup the sandbox lands in: bwrap is launched inside a
# transient systemd scope, where `limit` pairs become that scope's own
# limits (one ceiling per sandbox) and `slice` places the scope under a shared
# slice whose limits cap every sandbox in it *in aggregate* (one ceiling for
# all of them, however many are open).
#
# A slice carries no limits of its own unless a slice unit defines them, and
# systemd creates a named-but-undefined slice implicitly rather than failing —
# so `slice` alone buys grouping (systemctl --user status/stop "$slice",
# systemd-cgtop) but caps nothing until the unit exists. The limits also only
# bite for controllers systemd has delegated to the user manager: memory and
# pids are delegated by default, cpu often is not, and an undelegated
# CPUQuota= is accepted and silently ignored. Check with
#   cat /sys/fs/cgroup/user.slice/user-$UID.slice/cgroup.controllers
launcher=()
if [[ -n "$slice" || ${#limit[@]} -gt 0 ]]; then
  if (( ${#limit[@]} % 2 )); then
    log "LIMIT: odd element count; expected NAME value pairs" 3
    exit 1
  fi
  if ! command -v systemd-run >/dev/null 2>&1 ||
     [[ ! -d "${XDG_RUNTIME_DIR:-}/systemd" ]]; then
    # No systemd user session (non-systemd host, plain ssh, ...). seccomp and
    # the namespaces still hold, so warn rather than refuse to launch — at
    # level 3, since the default LOGLEVEL shows nothing above it.
    log "LIMIT: no systemd user session; launching UNCAPPED" 3
  else
    # --scope (not --service): systemd-run allocates the unit and then execs
    # bwrap in place, so the PID, the controlling TTY, the exit status and the
    # inherited seccomp fd 10 all pass straight through to it. --collect reaps
    # the unit if the sandbox dies on a cap (a MemoryMax OOM-kill leaves a
    # failed scope behind otherwise).
    launcher=(
      systemd-run --user --scope --quiet --collect
      --description="sandbox $DIR"
    )
    if [[ -n "$slice" ]]; then
      log "SLICE: $slice" 6
      launcher+=( --slice="$slice" )
    fi
    for (( i=0; i<${#limit[@]}; i+=2 )); do
      log "LIMIT: ${limit[i]}=${limit[i+1]}" 6
      launcher+=( --property="${limit[i]}=${limit[i+1]}" )
    done
    # Terminate systemd-run's own options: bwrap's first argument is --proc,
    # which a permuting getopt would otherwise try to claim.
    launcher+=( -- )
  fi
fi

# systemd-run builds its child's argv itself, so the exec -a argv[0] rewrite
# (which makes the sandbox show up under the command's own name rather than as
# "bwrap") survives only on the uncapped path.
launch() {
  if (( ${#launcher[@]} )); then
    exec "${launcher[@]}" bwrap "${args[@]}" -- "$@"
  fi
  exec -a "$1" bwrap "${args[@]}" -- "$@"
}

# --show-command: print the fully assembled bwrap invocation instead of
# running it. pre/post hooks are skipped — nothing is executed. bwrap reads
# the seccomp filter from fd 10, so the redirection feeding it is printed
# too, keeping the command runnable as-is.
if [[ "$MODE" == "show-command" ]]; then
  cmd="$(printf '%q ' "${launcher[@]}" bwrap "${args[@]}" -- "$@")"
  cmd="${cmd% }"
  if [[ -n "$SECCOMP_FILTER" ]]; then
    cmd+=" 10<$(printf '%q' "$SECCOMP_FILTER")"
  fi
  printf '%s\n' "$cmd"
  exit 0
fi

# pre/post hooks from the cfg: eval'd here (outside the sandbox), with $DIR
# and $CFG in scope. A failing pre command aborts the launch (set -e).
for cmd in "${pre[@]}"; do
  log "PRE: $cmd" 6
  eval "$cmd"
done

log "EXEC: ${launcher[*]} bwrap ${args[*]} -- $*" 7

if [[ ${#post[@]} -eq 0 ]]; then
  launch "$@"
fi
# post hooks need this shell to outlive bwrap: trade exec for a subshell
# (keeping the argv[0] trick) and wait. They run on normal exit, not when
# the wrapper itself is killed by a signal.
rc=0
( launch "$@" ) || rc=$?
for cmd in "${post[@]}"; do
  log "POST: $cmd" 6
  eval "$cmd"
done
exit $rc
