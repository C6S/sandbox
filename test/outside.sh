#!/usr/bin/env bash
# Cfg matrix tests: generate dummy project dirs with various .sandbox.cfg
# files, launch a sandbox on each, and validate the resulting policy — via
# test/inside.sh within the sandbox, plus driver-side checks it cannot do
# (env clearing, rw write-through to the host, pre/post hooks, refusal paths).
#
# Must run OUTSIDE any sandbox: the default seccomp profile blocks the user
# namespaces bwrap needs, so nested launches fail by design.
#
#   bash test/outside.sh
#
# SANDBOX_BIN overrides the wrapper under test (default: ./result/bin/sandbox,
# falling back to `sandbox` on PATH).
#
# Exit: 0 all fixtures pass, 1 any failure, 2 cannot run (sandboxed, no bin,
# or ./result is older than the sources it was built from).
set -uo pipefail

pass=0
fail=0
pass() { printf 'ok:   %s\n' "$1"; pass=$((pass + 1)); }
fail() { printf 'FAIL: %s\n' "$1"; fail=$((fail + 1)); }

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSIDE="$REPO/test/inside.sh"

if [[ -n "${SANDBOX:-}" ]]; then
  echo "already inside a sandbox - nested launches are blocked by seccomp; run from an unsandboxed shell" >&2
  exit 2
fi

SANDBOX_BIN="${SANDBOX_BIN:-$REPO/result/bin/sandbox}"
if [[ ! -x "$SANDBOX_BIN" ]]; then
  SANDBOX_BIN="$(command -v sandbox || true)"
fi
if [[ -z "$SANDBOX_BIN" || ! -x "$SANDBOX_BIN" ]]; then
  echo "no sandbox binary: build the package (nix build) or set SANDBOX_BIN" >&2
  exit 2
fi

# Refuse a stale ./result: a wrapper built from older sources fails these
# tests in misleading ways. Store contents have epoch mtimes, so compare the
# result symlink's own mtime (stat lstats by default) against the files that
# feed the build.
if [[ "$SANDBOX_BIN" == "$REPO/result/bin/sandbox" ]]; then
  built="$(stat -c %Y "$REPO/result")"
  for file in "$REPO"/src/sandbox.sh "$REPO"/src/seccomp-gen.c "$REPO"/src/package.nix; do
    if [[ "$(stat -c %Y "$file")" -gt "$built" ]]; then
      echo "stale build: ${file#"$REPO"/} is newer than ./result - run nix build first (or set SANDBOX_BIN)" >&2
      exit 2
    fi
  done
fi

root="$(mktemp -d "${TMPDIR:-/tmp}/sandbox-cfgs.XXXXXX")"
trap 'rm -rf "$root"' EXIT

# Keep the run hermetic: point XDG at a test-owned dir so the wrapper
# auto-creates (and the fixtures use) a fresh stock default.cfg instead of
# whatever the host has configured.
export XDG_CONFIG_HOME="$root/xdg"

# fixture <name> reads the cfg body from stdin and creates $root/<name>
# containing it plus a copy of inside.sh. Heredocs are unquoted on purpose
# where a driver path must be baked in literally; $DIR/$HOME stay escaped so
# the cfg resolves them itself (both at launch and when inside.sh re-sources).
fixture() {
  local dir="$root/$1"
  mkdir -p "$dir"
  cat >"$dir/.sandbox.cfg"
  cp "$INSIDE" "$dir/inside.sh"
}

# in_sandbox <name> [cmd...]: launch the fixture's sandbox and run cmd inside
# (default: inside.sh). Output is kept and shown only on failure.
in_sandbox() {
  local dir="$root/$1"
  shift
  [[ $# -ge 1 ]] || set -- bash "$dir/inside.sh"
  "$SANDBOX_BIN" "$dir" -- "$@"
}

# check <label> <name> [cmd...]: in_sandbox must succeed
check() {
  local label="$1" out
  shift
  if out="$(in_sandbox "$@" 2>&1)"; then
    pass "$label"
  else
    fail "$label"
    printf '%s\n' "$out" | sed 's/^/      /'
  fi
}

# check_fails <label> <name> [cmd...]: in_sandbox must fail
check_fails() {
  local label="$1" out
  shift
  if out="$(in_sandbox "$@" 2>&1)"; then
    fail "$label"
    printf '%s\n' "$out" | sed 's/^/      /'
  else
    pass "$label"
  fi
}

export SANDBOX_CFGTEST_CANARY=yes

## defaults: rw project, inherited env, net on, default seccomp
fixture defaults <<'EOF'
rw+=( "$DIR" )
EOF
check "defaults: inside.sh passes" defaults
# shellcheck disable=SC2016 # expansion happens inside the sandbox
check "defaults: env inherited (canary visible)" defaults \
  bash -c '[[ "${SANDBOX_CFGTEST_CANARY:-}" == yes ]]'
if [[ -f "$XDG_CONFIG_HOME/sandbox/default.cfg" ]]; then
  pass "defaults: default.cfg auto-created"
else
  fail "defaults: default.cfg not created"
fi

## ro project: $DIR bound read-only instead of rw
fixture ro-project <<'EOF'
ro+=( "$DIR" )
EOF
check "ro-project: inside.sh passes" ro-project

## isolated network
fixture net-isolated <<'EOF'
rw+=( "$DIR" )
net=0
EOF
check "net-isolated: inside.sh passes" net-isolated

## seccomp variants
fixture allow-userns <<'EOF'
rw+=( "$DIR" )
seccomp=allow-userns
EOF
check "allow-userns: inside.sh passes" allow-userns

fixture seccomp-none <<'EOF'
rw+=( "$DIR" )
seccomp=none
EOF
check "seccomp-none: inside.sh passes" seccomp-none

## env pairs appended over inherit
fixture env-pairs <<'EOF'
rw+=( "$DIR" )
env+=(
  CFGTEST_A "alpha"
  CFGTEST_B "$DIR/state"
)
EOF
check "env-pairs: inside.sh passes" env-pairs

## env replaced: environment cleared, declared pairs win
fixture env-replace <<'EOF'
rw+=( "$DIR" )
env=( CFGTEST_ONLY "solo" )
EOF
check "env-replace: inside.sh passes" env-replace
# shellcheck disable=SC2016 # expansion happens inside the sandbox
check "env-replace: host env cleared (canary absent)" env-replace \
  bash -c '[[ -z "${SANDBOX_CFGTEST_CANARY:-}" ]]'

## symlinks created inside
fixture links <<'EOF'
rw+=( "$DIR" )
link+=(
  "$DIR"     "$HOME/project"
  /nix/store "$HOME/store"
)
EOF
check "links: inside.sh passes" links

## extra host binds: ro stays read-only, rw writes reach the host
mkdir -p "$root/shared-ro" "$root/shared-rw"
echo data >"$root/shared-ro/file"
fixture binds <<EOF
rw+=(
  "\$DIR"
  "$root/shared-rw"
)
ro+=( "$root/shared-ro" )
EOF
check "binds: inside.sh passes" binds
check "binds: rw write reaches the host" binds \
  bash -c "echo from-inside >$root/shared-rw/probe"
if [[ "$(cat "$root/shared-rw/probe" 2>/dev/null)" == from-inside ]]; then
  pass "binds: rw write visible outside"
else
  fail "binds: rw write not visible outside"
fi

## bind pairs: host src mounted at a different path inside, writes reach the host
mkdir -p "$root/bind-src"
echo bind-data >"$root/bind-src/file"
fixture bind-pairs <<EOF
rw+=( "\$DIR" )
bind+=( "$root/bind-src" /var/bind-dest )
EOF
check "bind-pairs: inside.sh passes" bind-pairs
# shellcheck disable=SC2016 # expansion happens inside the sandbox
check "bind-pairs: src content visible at dest" bind-pairs \
  bash -c '[[ "$(cat /var/bind-dest/file)" == bind-data ]]'
check "bind-pairs: dest is writable" bind-pairs \
  bash -c 'echo from-inside >/var/bind-dest/probe'
if [[ "$(cat "$root/bind-src/probe" 2>/dev/null)" == from-inside ]]; then
  pass "bind-pairs: dest write visible at host src"
else
  fail "bind-pairs: dest write not visible at host src"
fi

## overlays: reads come from the host path, writes divert to the store dir
mkdir -p "$root/overlay-lower"
echo lower-data >"$root/overlay-lower/file"
fixture overlays <<EOF
rw+=( "\$DIR" )
overlay+=( "$root/overlay-lower" "$root/overlay-store" )
EOF
check "overlays: inside.sh passes" overlays
check "overlays: lower content visible" overlays \
  bash -c "[[ \"\$(cat $root/overlay-lower/file)\" == lower-data ]]"
check "overlays: dest accepts writes" overlays \
  bash -c "echo from-inside >$root/overlay-lower/probe && echo modified >$root/overlay-lower/file"
if [[ ! -e "$root/overlay-lower/probe" && \
      "$(cat "$root/overlay-lower/file" 2>/dev/null)" == lower-data ]]; then
  pass "overlays: host lower untouched"
else
  fail "overlays: writes leaked into the lower dir"
fi
if [[ "$(cat "$root/overlay-store/probe" 2>/dev/null)" == from-inside && \
      "$(cat "$root/overlay-store/file" 2>/dev/null)" == modified ]]; then
  pass "overlays: writes landed in the store"
else
  fail "overlays: writes missing from the store"
fi
check "overlays: store persists across launches" overlays \
  bash -c "[[ \"\$(cat $root/overlay-lower/file)\" == modified && \"\$(cat $root/overlay-lower/probe)\" == from-inside ]]"

## masks: secrets under an rw bind are hidden, host copies stay intact
fixture masks <<'EOF'
rw+=( "$DIR" )
mask+=(
  "$DIR/secret-dir"
  "$DIR/secret-file"
  "$DIR/never-existed"
)
EOF
mkdir -p "$root/masks/secret-dir"
echo top-secret >"$root/masks/secret-dir/inner"
echo top-secret >"$root/masks/secret-file"
check "masks: inside.sh passes" masks
check "masks: dir content hidden" masks \
  bash -c "[[ ! -e $root/masks/secret-dir/inner ]]"
check "masks: file reads empty" masks \
  bash -c "[[ -z \$(cat $root/masks/secret-file) ]]"
check "masks: absent path masked as /dev/null" masks \
  bash -c "[[ -c $root/masks/never-existed ]]"
if [[ "$(cat "$root/masks/secret-dir/inner" 2>/dev/null)" == top-secret && \
      "$(cat "$root/masks/secret-file" 2>/dev/null)" == top-secret ]]; then
  pass "masks: host copies intact"
else
  fail "masks: host copies damaged"
fi
# bwrap creates the mountpoint for an absent mask through the rw bind: an
# empty regular file must remain on the host afterwards.
if [[ -f "$root/masks/never-existed" && ! -s "$root/masks/never-existed" ]]; then
  pass "masks: placeholder left on host"
else
  fail "masks: placeholder missing on host"
fi

## masks under a bind dest: dir-vs-file resolved against the bind source
mkdir -p "$root/bind-mask-src/secret-dir"
echo top-secret >"$root/bind-mask-src/secret-dir/inner"
echo top-secret >"$root/bind-mask-src/secret-file"
fixture bind-mask <<EOF
rw+=( "\$DIR" )
bind+=( "$root/bind-mask-src" /var/bind-mask )
mask+=(
  /var/bind-mask/secret-dir
  /var/bind-mask/secret-file
)
EOF
check "bind-mask: inside.sh passes" bind-mask
# shellcheck disable=SC2016 # expansion happens inside the sandbox
check "bind-mask: dir masked as tmpfs at dest" bind-mask \
  bash -c '[[ -d /var/bind-mask/secret-dir && ! -e /var/bind-mask/secret-dir/inner ]]'
# shellcheck disable=SC2016 # expansion happens inside the sandbox
check "bind-mask: file reads empty at dest" bind-mask \
  bash -c '[[ -c /var/bind-mask/secret-file && -z "$(cat /var/bind-mask/secret-file)" ]]'

## pre/post hooks run outside, exit code passes through
fixture hooks <<'EOF'
rw+=( "$DIR" )
pre+=(  'touch "$DIR/.pre-ran"' )
post+=( 'touch "$DIR/.post-ran"' )
EOF
in_sandbox hooks bash -c 'exit 7' 2>/dev/null
rc=$?
if [[ "$rc" -eq 7 ]]; then pass "hooks: exit code passed through"; else fail "hooks: exit code $rc (want 7)"; fi
if [[ -f "$root/hooks/.pre-ran"  ]]; then pass "hooks: pre ran";  else fail "hooks: pre did not run";  fi
if [[ -f "$root/hooks/.post-ran" ]]; then pass "hooks: post ran"; else fail "hooks: post did not run"; fi

## failing pre aborts the launch before anything runs inside
fixture pre-fails <<'EOF'
rw+=( "$DIR" )
pre+=( 'false' )
EOF
check_fails "pre-fails: launch aborted" pre-fails touch "$root/pre-fails/.ran"
if [[ ! -e "$root/pre-fails/.ran" ]]; then
  pass "pre-fails: command never ran"
else
  fail "pre-fails: command ran despite failing pre"
fi

## unknown seccomp filter name refuses to launch
fixture bad-seccomp <<'EOF'
rw+=( "$DIR" )
seccomp=no-such-filter
EOF
check_fails "bad-seccomp: launch refused" bad-seccomp true

## no cfg anywhere up the tree refuses to launch
mkdir -p "$root/no-cfg"
found=
walk="$root/no-cfg"
while :; do
  [[ -f "$walk/.sandbox.cfg" ]] && { found=1; break; }
  [[ "$walk" == "/" || -z "$walk" ]] && break
  walk="${walk%/*}"
done
if [[ -n "$found" ]]; then
  printf 'skip: no-cfg check (an ancestor of %s has a .sandbox.cfg)\n' "$root"
else
  if "$SANDBOX_BIN" "$root/no-cfg" -- true 2>/dev/null; then
    fail "no-cfg: launched without a cfg"
  else
    pass "no-cfg: launch refused"
  fi
fi

echo
echo "passed: $pass  failed: $fail"
[[ "$fail" -eq 0 ]]
