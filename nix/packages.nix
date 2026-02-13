{ pkgs }:

let
  core = pkgs.callPackage ./ms-sso-openconnect-core.nix { };
  nmPlugin = pkgs.callPackage ./networkmanager-ms-sso.nix {
    ms-sso-openconnect-core = core;
  };
in
{
  ms-sso-openconnect-core = core;
  networkmanager-ms-sso = nmPlugin;
}
