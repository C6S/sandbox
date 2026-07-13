# The sandbox package: compiles the seccomp BPF filters from seccomp-gen.c and
# installs sandbox.sh with the filter directory substituted in.
#
# Both filters deny rarely-needed kernel-attack-surface syscalls (keyring, bpf,
# userfaultfd, perf, module load, kexec, ptrace, ...) and the TIOCSTI/TIOCLINUX
# terminal-injection ioctls. Rules return EPERM (not SIGKILL) so a blocked call
# is debuggable. The C is built natively for the host arch (nix picks the
# builder's arch) and additionally covers that arch's co-resident 32-bit ABI
# (i386+x32 on x86_64, arm on aarch64) so a compat syscall cannot bypass the
# native rules. The build emits two blobs, selected by the `seccomp` config
# var in .sandbox.cfg (the blob is "$seccomp.bpf"):
#   default.bpf      - additionally blocks creation of new user namespaces
#                      (via a CLONE_NEWUSER flag filter, so ordinary
#                      fork/threads are unaffected) and the mount syscalls.
#   allow-userns.bpf - omits the user-namespace/mount rules, for projects that
#                      run rootless podman or nested nix/bubblewrap
#                      (seccomp=allow-userns).
#
# sandboxSrc is overridable so a consumer can build a fetched release of this
# repo with this same recipe (see the README's consuming section). It cannot
# be named plain `src`: callPackage would silently fill that argument from the
# nixpkgs top-level `src` alias attribute instead of using the `./.` default.
# The `./.` default resolves relative to this file, i.e. to the src/ directory
# itself — so the phases below reference sandbox.sh and seccomp-gen.c without
# a src/ prefix, and consumers must not pass the repo root as sandboxSrc.
{
  lib,
  stdenv,
  libseccomp,
  makeWrapper,
  shellcheck,
  bubblewrap,
  coreutils,
  zsh,
  sandboxSrc ? ./.,
}:

stdenv.mkDerivation {
  pname = "sandbox";
  version = "0.1.5";
  src = sandboxSrc;

  nativeBuildInputs = [ makeWrapper ];
  buildInputs = [ libseccomp ];
  nativeCheckInputs = [ shellcheck ];
  doCheck = true;

  buildPhase = ''
    runHook preBuild
    cc seccomp-gen.c -lseccomp -o gen
    ./gen default > default.bpf
    ./gen allow-userns > allow-userns.bpf
    runHook postBuild
  '';

  checkPhase = ''
    runHook preCheck
    shellcheck sandbox.sh default.cfg
    runHook postCheck
  '';

  installPhase = ''
    runHook preInstall
    install -Dm444 -t $out/share/sandbox default.bpf allow-userns.bpf default.cfg
    install -Dm755 sandbox.sh $out/bin/sandbox
    substituteInPlace $out/bin/sandbox \
      --replace-fail '@sandboxSeccompDir@' "$out/share/sandbox" \
      --replace-fail '@sandboxDefaultCfg@' "$out/share/sandbox/default.cfg"
    wrapProgram $out/bin/sandbox \
      --prefix PATH : ${
        lib.makeBinPath [
          bubblewrap
          coreutils
          zsh
        ]
      }
    runHook postInstall
  '';

  meta = {
    description = "Bubblewrap sandbox wrapper";
    homepage = "https://github.com/C6S/sandbox";
    platforms = lib.platforms.linux;
    mainProgram = "sandbox";
  };
}
