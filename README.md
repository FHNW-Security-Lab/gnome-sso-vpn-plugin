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

To remove the package again:

```bash
sudo pacman -Rns networkmanager-ms-sso-git
sudo rm -rf /var/cache/ms-playwright /var/cache/ms-sso-openconnect
```

If you also want to remove the configured VPN connection, delete it from
NetworkManager or with `nmcli connection delete "<connection name>"`.

## GlobalProtect OS Version

For GlobalProtect, OpenConnect's `--os` option only accepts broad values such
as `linux-64`; it cannot be set to a distro string. Configure the distro/version
reported to GlobalProtect in the VPN editor's `GP OS Version` field. The value
is sent as the prelogin `os-version` and in the HIP report. Empty uses the
default `Ubuntu 26.04 LTS`.

The same value can be configured with `nmcli`:

```bash
nmcli connection modify "<connection name>" +vpn.data gp-os-version "Ubuntu 26.04 LTS"
```

GlobalProtect and AnyConnect SAML use a fresh browser session by default. This
avoids stale cached IdP state that can hang before TOTP or return no login
cookies. If your provider requires reusing browser SSO state, enable it
explicitly:

```bash
nmcli connection modify "<connection name>" +vpn.data enable-browser-session-cache 1
```

GlobalProtect emits only the first VPN DNS server by default. This avoids slow
failover behavior when a secondary VPN DNS server is reachable but degraded.
Override it if your VPN needs more DNS servers:

```bash
nmcli connection modify "<connection name>" +vpn.data dns-server-limit 2
```

AnyConnect keeps all pushed VPN DNS servers by default. During reconnects, a
tunnel that pushes VPN DNS is only accepted after at least one pushed DNS server
responds.

Slow AnyConnect SAML/MFA flows send a STARTED keepalive after 45 seconds to
avoid NetworkManager's connect timeout. IP routes and DNS are still only emitted
after OpenConnect has created and validated a real tunnel.

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
