{
  description = "GNOME NetworkManager plugin for MS SSO OpenConnect";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    let
      overlay = import ./nix/overlay.nix;
      nixosModule = import ./nix/nixos-module.nix;
    in
    (flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ overlay ];
        };
        localPackages = import ./nix/packages.nix { inherit pkgs; };
      in
      {
        packages = localPackages // {
          default = localPackages.networkmanager-ms-sso;
        };

        apps.install = {
          type = "app";
          program = toString (pkgs.writeShellScript "install-networkmanager-ms-sso" ''
            set -euo pipefail
            nix profile install "${self}#networkmanager-ms-sso"
            echo "Installed networkmanager-ms-sso into your user profile."
            echo "For NixOS system-wide usage, import this flake's NixOS module."
          '');
        };

        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            meson
            ninja
            pkg-config
            libnm
            gtk4
            glib
            libadwaita
            libsecret
            python3
            python3Packages.pygobject3
            python3Packages.dbus-python
          ];
        };

        formatter = pkgs.nixfmt-rfc-style;
      }))
    // {
      overlays.default = overlay;
      nixosModules.default = nixosModule;
    };
}
