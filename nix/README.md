# Nix Packaging

Build all plugin-related packages:

```bash
nix build "path:$PWD#networkmanager-ms-sso"
```

Available package attributes:

- `ms-sso-openconnect-core`
- `networkmanager-ms-sso`

NixOS module is available as `nixosModules.default` from `flake.nix`.
## Enable on NixOS

Import `nixosModules.default` into your configuration, then enable:

```nix
networking.networkmanager.enable = true;
services.gnome-ms-sso-plugin.enable = true;
```

The module installs the plugin, DNS-policy migration and recovery dispatcher,
and enables `nm-ms-sso-reconnect.service`. Building the package alone does not
activate these system services. See the [root README](../README.md#nixos-module)
for a complete flake example.

The reconnect observer remembers manually enabled VPNs for the current boot.
It waits for network recovery after sleep and forgets the previous Connect
choice on reboot. An enabled observer does not imply boot-time VPN activation.

## Observe connections

```bash
systemctl status nm-ms-sso-reconnect.service --no-pager
nmcli -f NAME,TYPE,STATE connection show
journalctl -f -t nm-ms-sso -t nm-ms-sso-reconnect
```

The same log messages and retry controls apply on NixOS. See
[Connection progress and troubleshooting](../docs/troubleshooting.md) for details.
