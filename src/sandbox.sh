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
# stock default.cfg shipped with the package; SANDBOX_DEFAULT_CFG overrides
# the path outright), then the optional per-user default.cfg under XDG,
# then the project cfg. Declared empty here only so set -u (and shellcheck)
# survive a default cfg that drops entries — the policy itself lives in the
# cfgs.
args=()
tmpfs=()
ro=()
rw=()
bind=()
overlay=()
mask=()
link=()
env=( inherit )
pre=()
post=()
net=1
seccomp=default

DEFAULT_CFG="${SANDBOX_DEFAULT_CFG:-/etc/sandbox.cfg}"
if [[ ! -f "$DEFAULT_CFG" ]]; then
  DEFAULT_CFG="@sandboxDefaultCfg@"
fi
log "SOURCE: $DEFAULT_CFG" 6
# shellcheck disable=SC1090
source "$DEFAULT_CFG"

USER_CFG="${XDG_CONFIG_HOME:-$HOME/.config}/sandbox/default.cfg"
if [[ -f "$USER_CFG" ]]; then
  log "SOURCE: $USER_CFG" 6
  # shellcheck disable=SC1090
  source "$USER_CFG"
fi

log "SOURCE: $CFG" 6
# shellcheck disable=SC1090
source "$CFG"

# Cfg paths may contain "." or ".." segments (e.g. "$DIR/../shared"), which
# both bwrap's mountpoint creation and the mask/bind prefix matching below
# take literally. Normalize them lexically (-s: no symlink resolution, so
# NixOS symlinks like /etc/resolv.conf keep binding the symlink path itself;
# -m: allow paths that don't exist yet). Symlink targets in link[] stay
# literal — only mount paths are normalized.
normalize() {
  local -n paths="$1"
  local i start="${2:-0}" step="${3:-1}"
  for (( i=start; i<${#paths[@]}; i+=step )); do
    paths[i]="$(realpath -sm -- "${paths[i]}")"
  done
}
normalize tmpfs
normalize ro
normalize rw
normalize bind
normalize overlay
normalize mask
normalize link 1 2

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
  show_array bind 2
  show_array overlay 2
  show_array mask 1
  show_array link 2
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
  printf '%snet=%q\n' "$comment" "$net"
  printf '%sseccomp=%q\n' "$comment" "$seccomp"
  exit 0
fi

if [[ "$net" == "1" ]]; then
	log "NET: ENABLED" 6
  args+=( --share-net )
else
	log "NET: DISABLED" 6
fi

if [[ "$seccomp" == "none" ]]; then
	log "SECCOMP: DISABLED" 6
else
  if [[ ! -e "$SECCOMP_DIR/$seccomp.bpf" ]]; then
    log "SECCOMP: filter not found ($SECCOMP_DIR/$seccomp.bpf)" 3
    exit 1
  fi
	log "SECCOMP: ENABLED ($SECCOMP_DIR/$seccomp.bpf)" 6
  # Open the filter on fd 10; the exec'd bwrap inherits it and reads its
  # BPF program from there.
  exec 10<"$SECCOMP_DIR/$seccomp.bpf"
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

for mount in "${ro[@]}"; do
	log "RO: $mount" 7
  args+=( --ro-bind "$mount" "$mount" )
done

for mount in "${rw[@]}"; do
	log "RW: $mount" 7
  args+=( --bind "$mount" "$mount" )
done

for (( i=0; i<${#bind[@]}; i+=2 )); do
	log "BIND: ${bind[i]} -> ${bind[i+1]}" 7
  args+=( --bind "${bind[i]}" "${bind[i+1]}" )
done

# Overlays act like rw binds that divert writes: the host path becomes the
# read-only lower layer of an overlayfs, and writes go to the store dir
# instead (modified files as copied-up whole files, deletions as whiteout
# character devices). The store and the empty work dir overlayfs requires
# on the same filesystem (kept beside the store as "<store>.work") are
# created here on first use.
for (( i=0; i<${#overlay[@]}; i+=2 )); do
  path="${overlay[i]}"
  store="${overlay[i+1]%/}"
	log "OVERLAY: $path -> $store" 7
  if [[ "$MODE" == "run" ]]; then
    mkdir -p "$store" "$store.work"
  fi
  args+=( --overlay-src "$path" --overlay "$store" "$store.work" "$path" )
done

# Masks shadow whatever the binds above exposed (later mounts win in bwrap):
# directories get an empty tmpfs, files a read-only /dev/null bind — the same
# mechanism systemd uses for masking. A mask is emitted even for paths absent
# on the host, so a file appearing later is already shadowed; bwrap creates
# the missing mountpoint itself, which leaves an empty placeholder on the
# host under a rw bind and fails the launch under a ro one. Dir-vs-file is
# decided on the host, after translating the path through the bind pairs so
# masks under a bind dest resolve against the real source.
for mount in "${mask[@]}"; do
  hostpath="$mount"
  for (( i=0; i<${#bind[@]}; i+=2 )); do
    if [[ "$mount" == "${bind[i+1]}" || "$mount" == "${bind[i+1]}"/* ]]; then
      hostpath="${bind[i]}${mount#"${bind[i+1]}"}"
      break
    fi
  done
  if [[ -d "$hostpath" ]]; then
	  log "MASK (tmpfs): $mount" 7
    args+=( --tmpfs "$mount" )
  else
	  log "MASK (/dev/null): $mount" 7
    args+=( --ro-bind /dev/null "$mount" )
  fi
done

for (( i=0; i<${#link[@]}; i+=2 )); do
	log "LINK: ${link[i]} -> ${link[i+1]}" 7
  args+=( --symlink "${link[i]}" "${link[i+1]}" )
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

# --show-command: print the fully assembled bwrap invocation instead of
# running it. pre/post hooks are skipped — nothing is executed.
if [[ "$MODE" == "show-command" ]]; then
  cmd="$(printf '%q ' bwrap "${args[@]}" -- "$@")"
  printf '%s\n' "${cmd% }"
  exit 0
fi

# pre/post hooks from the cfg: eval'd here (outside the sandbox), with $DIR
# and $CFG in scope. A failing pre command aborts the launch (set -e).
for cmd in "${pre[@]}"; do
  log "PRE: $cmd" 6
  eval "$cmd"
done

log "EXEC: bwrap ${args[*]} -- $*" 7

if [[ ${#post[@]} -eq 0 ]]; then
  exec -a "$1" bwrap "${args[@]}" -- "$@"
fi
# post hooks need this shell to outlive bwrap: trade exec for a subshell
# (keeping the argv[0] trick) and wait. They run on normal exit, not when
# the wrapper itself is killed by a signal.
rc=0
( exec -a "$1" bwrap "${args[@]}" -- "$@" ) || rc=$?
for cmd in "${post[@]}"; do
  log "POST: $cmd" 6
  eval "$cmd"
done
exit $rc
