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

Install the exact package path printed by the build with APT so its runtime
dependencies are resolved automatically. For example:

```bash
sudo apt install "$PWD/dist/network-manager-ms-sso_2.0.1-1_amd64.deb"
```

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

GlobalProtect and AnyConnect SAML reuse a browser session by default. This keeps
Microsoft/IdP SSO state across reconnects, avoids repeated TOTP prompts, and
makes long-running AnyConnect deployments such as FHNW less fragile. If a stale
IdP session causes problems, force a fresh browser session explicitly:

```bash
nmcli connection modify "<connection name>" +vpn.data disable-browser-session-cache 1
```

Microsoft MFA is adaptive and TOTP-first by default (`mfa-preference=auto`).
When a TOTP secret is configured, a visible code field is filled automatically.
If Microsoft first shows a passkey or Authenticator number-matching prompt, the
plugin chooses password/another sign-in method and switches to the registered
TOTP method instead of waiting for phone approval. A persistent number-matching
notification is used only when adaptive mode has no configured TOTP secret, or when
`mfa-preference=push` explicitly requests phone approval. A mandatory passkey
still cannot be completed because the headless VPN service has no interactive
browser/OS hardware UI.

You can force a registered MFA method for troubleshooting:

```bash
nmcli connection modify "<connection name>" +vpn.data mfa-preference push
nmcli connection modify "<connection name>" +vpn.data mfa-preference totp
```

Use `auto`, `push`, or `totp`; `auto` is recommended.

GlobalProtect emits only the first VPN DNS server by default. This avoids slow
failover behavior when a secondary VPN DNS server is reachable but degraded.
Override it if your VPN needs more DNS servers:

```bash
nmcli connection modify "<connection name>" +vpn.data dns-server-limit 2
```

AnyConnect keeps all pushed VPN DNS servers by default. The plugin waits for a
real tunnel interface with IPv4 configuration before publishing the VPN routes
and DNS settings to NetworkManager.

AnyConnect does not emit a pre-tunnel "started" state by default. This avoids a
half-connected NetworkManager state where the UI shows a tunnel but no VPN IP,
routes, or DNS are usable yet. IP routes and DNS are only emitted after
OpenConnect has created and validated a real tunnel.

AnyConnect profiles created or saved through this editor use a 180-second
NetworkManager activation timeout so slow SAML/MFA can finish without a forced
reconnect. Existing profiles can be updated once with:

```bash
nmcli connection modify "<connection name>" vpn.timeout 180
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
  inputs.gnome-ms-sso-plugin.url = "github:FHNW-Security-Lab/gnome-sso-vpn-plugin";

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
