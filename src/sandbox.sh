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
Usage: $(basename "$0") [dir] [-- command [args...]]
       $(basename "$0") --help

  dir   Directory to sandbox into (default: current directory)
  --    Separator before the command to run inside the sandbox
        Without --, opens \$SHELL inside the sandbox

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

# Parse optional leading dir arg
if [[ $# -ge 1 && "$1" != "--" ]]; then
  if [[ "$1" == "--help" ]]; then
    usage
    exit 0
  elif [[ -d "$1" ]]; then
    DIR="$(readlink -f "$1")"
    cd "$DIR" || { echo "Cannot enter directory: $DIR" >&2; exit 1; }
  else
    log "Not a directory: $1" 3
    exit 1
  fi
  shift
else
	DIR="$PWD"
fi

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

# config variables (inherits)
args=(
  --proc /proc
  --dev /dev
  --unshare-all
  --die-with-parent

)
tmpfs=(
  /tmp
  "$HOME"
)
ro=(
	/nix
	/run/current-system
  /etc/static
  /etc/passwd
  /etc/group
  /etc/resolv.conf
  /etc/ssl
  /etc/hosts
  /etc/localtime
)
rw=()
bind=()
mask=()
link=()
env=( inherit )
pre=()
post=()
net=1
seccomp=default

log "SOURCE: $CFG" 6
# shellcheck disable=SC1090
source "$CFG"

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
# "am I sandboxed?" detection; the policy itself is readable from the mounted cfg.
log "RO $CFG" 7
args+=( --ro-bind "$CFG" "$CFG" )
log "ENV: SANDBOX=$CFG" 7
args+=( --setenv SANDBOX "$CFG" )

[[ $# -ge 1 && "$1" == "--" ]] && shift
[[ $# -ge 1 ]] || set -- "${SHELL:-zsh}"

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
