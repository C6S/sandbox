{
  pkgs ? import <nixpkgs> { },
}:
pkgs.callPackage ./src/package.nix { }
