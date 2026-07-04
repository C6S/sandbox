#!/usr/bin/env bash
# In-sandbox enforcement checks: run this *inside* a sandbox to validate that
# the loaded .sandbox.cfg is actually enforced — binds, tmpfs, hide-by-omission,
# net, and the seccomp profile. From a project directory containing this repo:
#
#   sandbox -- bash test/inside.sh
#
# (invoke via `bash`: /usr/bin/env does not exist inside the sandbox, so the
# shebang cannot be resolved there)
#
# Exit: 0 all checks pass, 1 any failure, 2 not inside a sandbox.
set -uo pipefail

pass=0 fail=0 skipped=0
ok()   { printf 'ok:   %s\n' "$1"; pass=$((pass + 1)); }
bad()  { printf 'FAIL: %s\n' "$1"; fail=$((fail + 1)); }
skip() { printf 'skip: %s\n' "$1"; skipped=$((skipped + 1)); }

if [[ -z "${SANDBOX:-}" || ! -f "${SANDBOX:-}" ]]; then
  echo "SANDBOX not set or unreadable - not inside a sandbox?" >&2
  exit 2
fi

# Re-source the mounted cfg (over the same defaults sandbox.sh uses) to learn
# the policy. Only cfg-declared paths are probed; the base defaults are
# covered by the invariant checks below.
# DIR is referenced by the sourced cfg; pre/post are sourced but not probed.
# shellcheck disable=SC2034
DIR="${SANDBOX%/.sandbox.cfg}"
# shellcheck disable=SC2034
tmpfs=() ro=() rw=() link=() env=( inherit ) pre=() post=()
net=1
seccomp=default
# shellcheck disable=SC1090
source "$SANDBOX"

fstype() { stat -f -c %T "$1" 2>/dev/null; }

# Probe write access by creating and removing a file; meaningful only for
# directories the current user could write to were they not read-only.
can_write() {
  local f="$1/.sandbox-enforce-probe.$$"
  if ( : >"$f" ) 2>/dev/null; then
    rm -f "$f"
    return 0
  fi
  return 1
}

is_bound() {
  local p
  for p in "${ro[@]}" "${rw[@]}" "${tmpfs[@]}"; do
    [[ "$1" == "$p" || "$1" == "$p"/* ]] && return 0
  done
  return 1
}

## Base invariants
for p in "$HOME" /tmp; do
  if [[ "$(fstype "$p")" == tmpfs ]]; then
    ok "$p is tmpfs"
  else
    bad "$p is not tmpfs (got: $(fstype "$p"))"
  fi
done
if [[ -d /nix/store ]]; then ok "/nix/store present"; else bad "/nix/store missing"; fi
if [[ ! -w "$SANDBOX" ]]; then ok "cfg is read-only"; else bad "cfg is writable"; fi

## Hide-by-omission: host paths that exist outside must be absent unless bound
for p in /root /boot /etc/shadow /usr "$HOME/.ssh" "$HOME/.gnupg"; do
  if is_bound "$p"; then
    skip "$p is bound by cfg"
  elif [[ -e "$p" ]]; then
    bad "$p leaked into the sandbox"
  else
    ok "$p absent"
  fi
done

## Cfg-declared binds
for p in "${rw[@]}"; do
  if [[ -d "$p" ]]; then
    if can_write "$p"; then ok "rw dir writable: $p"; else bad "rw dir not writable: $p"; fi
  elif [[ -e "$p" ]]; then
    if [[ -w "$p" ]]; then ok "rw file writable: $p"; else bad "rw file not writable: $p"; fi
  else
    bad "rw path missing: $p"
  fi
done

for p in "${ro[@]}"; do
  if [[ -d "$p" ]]; then
    # Only user-writable-on-host dirs discriminate EROFS from EACCES; root-owned
    # ones fail either way, which is still the correct observable behavior.
    if can_write "$p"; then bad "ro dir writable: $p"; else ok "ro dir read-only: $p"; fi
  elif [[ -e "$p" ]]; then
    if [[ -w "$p" ]]; then bad "ro file writable: $p"; else ok "ro file read-only: $p"; fi
  else
    bad "ro path missing: $p"
  fi
done

for (( i = 0; i < ${#link[@]}; i += 2 )); do
  if [[ "$(readlink "${link[i+1]}" 2>/dev/null)" == "${link[i]}" ]]; then
    ok "link ${link[i+1]} -> ${link[i]}"
  else
    bad "link ${link[i+1]} does not point to ${link[i]}"
  fi
done

## Declared env pairs
if [[ "${env[0]:-}" == "inherit" ]]; then
  envpairs=( "${env[@]:1}" )
else
  envpairs=( "${env[@]}" )
fi
for (( i = 0; i < ${#envpairs[@]}; i += 2 )); do
  name="${envpairs[i]}" want="${envpairs[i+1]}"
  if [[ "${!name:-}" == "$want" ]]; then
    ok "env $name set"
  else
    bad "env $name='${!name:-}' (want '$want')"
  fi
done

## Network
if command -v ip >/dev/null; then
  ifaces=$(ip -o link show 2>/dev/null | wc -l)
  if [[ "$net" == "1" ]]; then
    if [[ "$ifaces" -gt 1 ]]; then ok "net shared ($ifaces interfaces)"; else bad "net=1 but only loopback visible"; fi
  else
    if [[ "$ifaces" -le 1 ]]; then ok "net isolated (loopback only)"; else bad "net=0 but $ifaces interfaces visible"; fi
  fi
else
  skip "net check (no ip command)"
fi

## Seccomp profile
if command -v unshare >/dev/null; then
  if [[ "$seccomp" == "default" ]]; then
    if err=$(unshare -U true 2>&1); then
      bad "userns creation allowed under default profile"
    elif [[ "$err" == *"not permitted"* ]]; then
      ok "userns creation blocked (EPERM)"
    else
      bad "userns creation failed unexpectedly: $err"
    fi
  elif [[ "$seccomp" == "allow-userns" ]]; then
    if unshare -U true 2>/dev/null; then ok "userns creation allowed"; else bad "userns creation blocked under allow-userns"; fi
    if unshare -rm true 2>/dev/null; then ok "mount ns allowed"; else bad "mount ns blocked under allow-userns"; fi
  else # none
    if unshare -U true 2>/dev/null; then ok "userns creation allowed (no filter)"; else bad "userns blocked despite seccomp=none"; fi
  fi
else
  skip "userns check (no unshare command)"
fi

# Syscall-level probes need python3 and x86_64 syscall numbers.
if command -v python3 >/dev/null && [[ "$(uname -m)" == "x86_64" ]]; then
  # keyctl(2) is a clean discriminator: unfiltered it fails with ENOKEY/EINVAL,
  # filtered it returns EPERM (errno 1). Exit code = errno.
  python3 -c '
import ctypes, sys
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall(250, 0, 0, 0, 0, 0)  # __NR_keyctl on x86_64
sys.exit(ctypes.get_errno())
'
  e=$?
  if [[ "$seccomp" == "none" ]]; then
    if [[ "$e" -ne 1 ]]; then ok "keyctl unfiltered (errno $e, probe works)"; else bad "keyctl EPERM despite seccomp=none"; fi
  else
    if [[ "$e" -eq 1 ]]; then ok "keyctl denied (EPERM)"; else bad "keyctl not denied (errno $e)"; fi
  fi

  # ioctl(TIOCSTI): 0 = injected (vulnerable), errno 1 = seccomp EPERM,
  # errno 5 = kernel EIO from dev.tty.legacy_tiocsti=0, 99 = no tty.
  python3 -c '
import fcntl, os, sys
try:
    fd = os.open("/dev/tty", os.O_RDWR)
except OSError:
    sys.exit(99)
try:
    fcntl.ioctl(fd, 0x5412, b"\x00")  # TIOCSTI
    sys.exit(0)
except OSError as e:
    sys.exit(e.errno)
'
  e=$?
  case "$e" in
    99) skip "TIOCSTI check (no controlling tty)" ;;
    0)  bad "TIOCSTI succeeded - terminal injection possible" ;;
    1)  ok "TIOCSTI blocked by seccomp (EPERM)" ;;
    5)  if [[ "$seccomp" == "none" ]]; then
          ok "TIOCSTI blocked by sysctl only (EIO)"
        else
          bad "TIOCSTI hit the sysctl (EIO), not seccomp - filter not applied?"
        fi ;;
    *)  bad "TIOCSTI failed with unexpected errno $e" ;;
  esac
else
  skip "syscall probes (need python3 on x86_64)"
fi

echo
echo "passed: $pass  failed: $fail  skipped: $skipped"
[[ "$fail" -eq 0 ]]
