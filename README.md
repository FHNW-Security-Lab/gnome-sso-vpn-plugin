# gnome-ms-sso-plugin

Standalone GNOME NetworkManager plugin for MS SSO OpenConnect.

## What This Repo Contains

- NetworkManager VPN plugin service and auth dialog (`src/`)
- GNOME Settings editor plugin (`src/editor/`)
- Plugin metadata and D-Bus policy (`data/`)
- Shared Python runtime used by the plugin (`src/python/core/`)
- Debian packaging assets (`packaging/debian/`)
- Nix packaging + NixOS module (`nix/`, `flake.nix`)

## Build Debian Package

```bash
./build.sh
```

Output artifacts are placed under `dist/`.

## Nix Flake Usage

Build package:

```bash
nix build "path:$PWD#networkmanager-ms-sso"
```

Install to user profile:

```bash
nix run "path:$PWD#install"
```

## NixOS Module

In your system flake:

```nix
{
  inputs.gnome-ms-sso-plugin.url = "github:FHNW-Security-Lab/gnome-ms-sso-plugin";

  outputs = { self, nixpkgs, gnome-ms-sso-plugin, ... }: {
    nixosConfigurations.my-host = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        gnome-ms-sso-plugin.nixosModules.default
        ({ ... }: {
          networking.networkmanager.enable = true;
          services.gnome-ms-sso-plugin.enable = true;
        })
      ];
    };
  };
}
```
