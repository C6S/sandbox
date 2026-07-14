{ pkgs, ... }:
{
  claude.code = {
    enable = true;
    hooks.git-hooks-run.enable = false;
  };

  packages = [
    pkgs.git
    pkgs.nixfmt
    pkgs.statix
    pkgs.deadnix
  ];

  git-hooks.hooks = {
    shellcheck.enable = true;
    nixfmt-rfc-style = {
      enable = true;
      package = pkgs.nixfmt;
    };
    statix.enable = true;
    deadnix.enable = true;
  };

  scripts = {
    nix-fmt.exec = "nixfmt **/*.nix";
    nix-lint.exec = "statix check && deadnix .";
  };
}
