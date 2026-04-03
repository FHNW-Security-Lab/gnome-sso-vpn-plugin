# gnome-ms-sso-plugin

Standalone GNOME NetworkManager plugin for MS SSO OpenConnect.

## What This Repo Contains

- NetworkManager VPN plugin service and auth dialog (`src/`)
- GNOME Settings editor plugin (`src/editor/`)
- Plugin metadata and D-Bus policy (`data/`)
- Shared Python runtime used by the plugin (`src/python/core/`)
- Debian packaging assets (`packaging/debian/`)
- Arch packaging assets (`packaging/arch/`)
- Nix packaging + NixOS module (`nix/`, `flake.nix`)

## Build Debian Package

```bash
./build.sh
```

Output artifacts are placed under `dist/`.

## Build Or Install On Arch

Arch packaging is provided as an AUR-style `-git` package in `packaging/arch/`.

Build and install locally:

```bash
./build-arch.sh
```

Install with `paru` from a local checkout:

```bash
paru -Bi packaging/arch --rebuild
```

Or build it manually:

```bash
cd packaging/arch
makepkg -si --syncdeps --cleanbuild
```

The package installs as `networkmanager-ms-sso-git`.

The Arch package automatically creates writable runtime caches under
`/var/cache/ms-sso-openconnect` and installs the Playwright Chromium runtime
into `/var/cache/ms-playwright` during `paru`/`pacman` installation.

If that automatic Playwright step fails because of network restrictions, run:

```bash
sudo PLAYWRIGHT_BROWSERS_PATH=/var/cache/ms-playwright playwright install chromium
```

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

If your setup uses a separate `flake/packages.nix` mapping, add:

```nix
gnome-sso-vpn = {
  input = "gnome-sso-vpn";
  package = "default";
  modulePath = "nix/nixos-module.nix";
  overlayPath = "nix/overlay.nix";
  enableOptionPath = [ "services" "gnome-ms-sso-plugin" "enable" ];
  enableOptionValue = true;
};
```
