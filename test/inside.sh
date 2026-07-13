#!/usr/bin/env bash
# In-sandbox enforcement checks: run this *inside* a sandbox to validate that
# the loaded .sandbox.cfg is actually enforced — binds, tmpfs, masks,
# hide-by-omission, net, and the seccomp profile. From a project directory containing this repo:
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
tmpfs=() ro=() rw=() bind=() overlay=() mask=() link=() env=( inherit ) pre=() post=()
net=1
seccomp=default
# shellcheck disable=SC1090
source "$SANDBOX"

fstype() { stat -f -c %T "$1" 2>/dev/null; }

# Probe write access by creating and removing a file; meaningful only for
# directories the current user could write to were they not read-only.
can_write() {
  local file="$1/.sandbox-enforce-probe.$$"
  if ( : >"$file" ) 2>/dev/null; then
    rm -f "$file"
    return 0
  fi
  return 1
}

is_bound() {
  local path i
  for path in "${ro[@]}" "${rw[@]}" "${tmpfs[@]}"; do
    [[ "$1" == "$path" || "$1" == "$path"/* ]] && return 0
  done
  for (( i = 1; i < ${#bind[@]}; i += 2 )); do
    [[ "$1" == "${bind[i]}" || "$1" == "${bind[i]}"/* ]] && return 0
  done
  for (( i = 0; i < ${#overlay[@]}; i += 2 )); do
    [[ "$1" == "${overlay[i]}" || "$1" == "${overlay[i]}"/* ]] && return 0
  done
  return 1
}

## Base invariants
for path in "$HOME" /tmp; do
  if [[ "$(fstype "$path")" == tmpfs ]]; then
    ok "$path is tmpfs"
  else
    bad "$path is not tmpfs (got: $(fstype "$path"))"
  fi
done
if [[ -d /nix/store ]]; then ok "/nix/store present"; else bad "/nix/store missing"; fi
if [[ ! -w "$SANDBOX" ]]; then ok "cfg is read-only"; else bad "cfg is writable"; fi

## Hide-by-omission: host paths that exist outside must be absent unless bound
for path in /root /boot /etc/shadow /usr "$HOME/.ssh" "$HOME/.gnupg"; do
  if is_bound "$path"; then
    skip "$path is bound by cfg"
  elif [[ -e "$path" ]]; then
    bad "$path leaked into the sandbox"
  else
    ok "$path absent"
  fi
done

## Cfg-declared binds
for path in "${rw[@]}"; do
  if [[ -d "$path" ]]; then
    if can_write "$path"; then ok "rw dir writable: $path"; else bad "rw dir not writable: $path"; fi
  elif [[ -e "$path" ]]; then
    if [[ -w "$path" ]]; then ok "rw file writable: $path"; else bad "rw file not writable: $path"; fi
  else
    bad "rw path missing: $path"
  fi
done

for path in "${ro[@]}"; do
  if [[ -d "$path" ]]; then
    # Only user-writable-on-host dirs discriminate EROFS from EACCES; root-owned
    # ones fail either way, which is still the correct observable behavior.
    if can_write "$path"; then bad "ro dir writable: $path"; else ok "ro dir read-only: $path"; fi
  elif [[ -e "$path" ]]; then
    if [[ -w "$path" ]]; then bad "ro file writable: $path"; else ok "ro file read-only: $path"; fi
  else
    bad "ro path missing: $path"
  fi
done

for (( i = 0; i < ${#bind[@]}; i += 2 )); do
  dest="${bind[i+1]}"
  if [[ ! -e "$dest" ]]; then
    bad "bind dest missing: $dest"
  elif [[ -d "$dest" ]]; then
    if can_write "$dest"; then ok "bind dest writable: $dest"; else bad "bind dest not writable: $dest"; fi
  else
    if [[ -w "$dest" ]]; then ok "bind dest writable: $dest"; else bad "bind dest not writable: $dest"; fi
  fi
done

for (( i = 0; i < ${#overlay[@]}; i += 2 )); do
  dest="${overlay[i]}"
  if [[ "$(fstype "$dest")" != overlayfs ]]; then
    bad "overlay dest not overlayfs: $dest (got: $(fstype "$dest"))"
  elif can_write "$dest"; then
    ok "overlay dest writable: $dest"
  else
    bad "overlay dest not writable: $dest"
  fi
done

## Masks: dirs must be an empty tmpfs; files must be /dev/null (reads empty,
## writes discarded). Masks are emitted even for paths absent on the host,
## so a path missing inside means the mask was not applied.
for path in "${mask[@]}"; do
  if [[ -d "$path" ]]; then
    if [[ "$(fstype "$path")" == tmpfs && -z "$(ls -A "$path" 2>/dev/null)" ]]; then
      ok "mask dir is empty tmpfs: $path"
    else
      bad "mask dir not masked: $path"
    fi
  elif [[ -c "$path" ]]; then
    if [[ -z "$(cat "$path" 2>/dev/null)" ]]; then
      ok "mask file reads empty: $path"
    else
      bad "mask file has content: $path"
    fi
  elif [[ -e "$path" ]]; then
    bad "mask path not masked: $path"
  else
    bad "mask path missing: $path"
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
