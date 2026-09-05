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

## Connect and watch progress

Connect using GNOME Settings → Network → VPN, or start the saved FHNW profile
from a terminal:

```bash
nmcli --wait 360 connection up id FHNW
```

Watch SSO steps, tunnel validation, and reconnect attempts in another terminal:

```bash
journalctl -f -t nm-ms-sso -t nm-ms-sso-reconnect
```

Press Ctrl+C to stop viewing logs without disconnecting. If journal access is
restricted, run the log command with `sudo`. Authentication runs in a headless
browser, so progress appears as log messages rather than a browser window.

Check the current connection and observer status:

```bash
nmcli -f NAME,TYPE,STATE connection show
systemctl status nm-ms-sso-reconnect.service --no-pager
```

`FHNW` should show `activated` once connected. The reconnect service can be
`active (running)` even when the VPN is off: it observes future Connect requests.
Its being enabled on boot does not enable VPN autoconnect after reboot.

See [Connection progress and troubleshooting](docs/troubleshooting.md) for log
messages, process IDs, retry controls, known limitations, and diagnostic reports.
For NixOS installation, see [Nix packaging](nix/README.md).

## Build Debian Package

```bash
./build.sh
```

Output artifacts are placed under `dist/`.

Install the exact package path printed by the build with APT so its runtime
dependencies are resolved automatically. For example:

```bash
sudo apt install "$PWD/dist/network-manager-ms-sso_2.0.7-1_amd64.deb"
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
host's detected `/etc/os-release` name (for example Ubuntu, Arch Linux, or
NixOS). Set an explicit value only when a gateway requires a compatibility
override.

The same value can be configured with `nmcli`:

```bash
nmcli connection modify "<connection name>" +vpn.data "gp-os-version=Ubuntu 26.04 LTS"
```

GlobalProtect profiles authenticate through the portal by default. When the
profile gateway itself provides SAML, direct gateway authentication avoids the
second portal-to-gateway credential prompt and shortens the connection setup:

```bash
nmcli connection modify "<connection name>" +vpn.data "gp-auth-interface=gateway"
```

Use `portal` for deployments that require portal discovery. This setting only
affects GlobalProtect; AnyConnect profiles keep their existing connection path.

### UniBas reconnect settings

The reconnect observer in version 2.0.7 supports both AnyConnect and
GlobalProtect. It selects profiles by this plugin's NetworkManager service type,
not by institution or VPN protocol. UniBas therefore has the same retry,
network-recovery, sleep/resume, manual-disconnect, and reboot policy as FHNW.
No additional reconnect helper or package is required.

Explicitly enable it for the saved `Unibas` profile and allow up to 360 seconds
for a NetworkManager activation:

```bash
nmcli connection modify Unibas +vpn.data 'auto-reconnect=true' vpn.timeout 360
```

This extends the activation deadline without adding a delay to successful
connections. It does not change GlobalProtect's separate SAML timeout or replace
an existing tunnel. Preserve a larger activation timeout if already configured.
The editor's GlobalProtect default remains 300 seconds, and it preserves an
explicit 360-second value when the profile is saved.

Keep the UniBas gateway and registered MFA configuration. Direct gateway
profiles use `gp-auth-interface=gateway`; TOTP profiles use `mfa-preference=totp`.
GlobalProtect keeps its own cookie handling: a consumed gateway prelogin cookie
cannot be reused, so a reconnect can require SSO again. Shared DNS validation
and exclusive VPN DNS policy apply to both protocols.

This plugin supports one active VPN at a time. To switch from FHNW to UniBas,
disconnect FHNW first, then connect UniBas:

```bash
nmcli connection down id FHNW
nmcli --wait 360 connection up id Unibas
```

Run the first command only if FHNW is active. To disable future UniBas retries:

```bash
nmcli connection modify Unibas +vpn.data 'auto-reconnect=false'
```

Changing the retry policy does not disconnect an established tunnel; use
`nmcli connection down id Unibas` for that. See the
[troubleshooting guide](docs/troubleshooting.md#connect-disconnect-and-stop-retries)
for live progress and the full retry controls.

GlobalProtect and interactive AnyConnect SAML reuse a browser session by
default. Browser state is isolated by VPN protocol, gateway, and account so
switching between institutions cannot reuse the other connection's tenant or
account selection. AnyConnect profiles explicitly configured for TOTP use a
fresh browser session on every activation when a TOTP secret is stored. That
flow is already self-contained, and a clean session prevents a timed-out
Microsoft page from making the next reconnect depend on stale UI state. Set
`enable-browser-session-cache=1` to opt back into reuse for such a profile.

If a persistent AnyConnect page stops advancing, the plugin invalidates that
profile. A pre-credential stall falls back to one clean ephemeral session in the
same NetworkManager activation; a post-password or post-MFA stall fails closed
without replaying the sensitive action, and the next activation starts clean.
UI state is checked continuously: static pages use a short recovery threshold,
while submitted forms, visible processing, and MFA method transitions receive
bounded extra time only while they are still active. Submitted forms start with
a 20-second fast path and progressively extend only as needed, up to the
protocol deadline; they are never automatically reloaded or submitted twice.

If an IdP session still causes problems, force a fresh browser session explicitly:

```bash
nmcli connection modify "<connection name>" +vpn.data "disable-browser-session-cache=1"
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
nmcli connection modify "<connection name>" +vpn.data "mfa-preference=push"
nmcli connection modify "<connection name>" +vpn.data "mfa-preference=totp"
```

Use `auto`, `push`, or `totp`; `auto` is recommended.

Both protocols use leak-safe DNS by default. Before reporting a connection as
active, the plugin verifies that each selected resolver is routed through and
answers on the exact tunnel interface. It then installs the route-only DNS root
(`~.`), gives the VPN an exclusive negative NetworkManager DNS priority, and
refuses the connection instead of falling back to a physical-link resolver.
UniBas uses its two known tunnel resolvers when GlobalProtect does not push DNS;
FHNW keeps the DNS servers pushed by AnyConnect.

Both UniBas resolvers are retained by default for reliable failover. Override
the maximum for a gateway only when required:

```bash
nmcli connection modify "<connection name>" +vpn.data "dns-server-limit=2"
```

AnyConnect keeps all pushed VPN DNS servers by default. The plugin waits for a
real tunnel interface with IPv4 configuration before publishing the VPN routes
and DNS settings to NetworkManager.

An institution-specific resolver list can be configured as VPN data. Every
address is still route-checked and queried through the tunnel before use:

```bash
nmcli connection modify "<connection name>" +vpn.data "dns-servers=10.0.0.53,10.0.0.54"
```

Because both supported VPNs are IPv4-only, direct public IPv6 is blocked while
either is active. An owned nftables output policy blocks physical IPv6 even when
a more-specific route or alternate policy-routing table exists; only loopback,
the owned VPN tunnel, and kernel-confirmed WireGuard interfaces remain allowed.
The unreachable IPv6 default remains as defense in depth, so WireGuard-specific
routes still win by longest-prefix routing. Standard DNS and DNS-over-TLS egress
(TCP/UDP ports 53 and 853) is also restricted to loopback and the owned VPN
tunnel, preventing a physical or WireGuard resolver fallback. Install/upgrade
hooks migrate existing profiles to exclusive DNS priority before their next
activation. All owned firewall, route, and resolver state is removed on
disconnect and by the crash-recovery dispatcher.

Applications explicitly configured to send DNS inside ordinary HTTPS (custom
DoH) are outside the operating-system resolver path and cannot be separated
from normal split-tunnel HTTPS traffic. Disable custom application DoH when the
institutional tunnel resolver must be authoritative.

AnyConnect does not emit a pre-tunnel "started" state by default. This avoids a
half-connected NetworkManager state where the UI shows a tunnel but no VPN IP,
routes, or DNS are usable yet. IP routes and DNS are only emitted after
OpenConnect has created and validated a real tunnel.

AnyConnect profiles created or saved through this editor use at least a
360-second NetworkManager activation timeout so slow or first-time SAML/MFA can
finish without NetworkManager cancelling a connection that is still making
progress. A larger maximum does not slow successful connections; it only gives
a delayed login more time to finish. Existing profiles can be updated once
without opening the editor:

```bash
nmcli connection modify "<connection name>" vpn.timeout 360
```

When starting the profile from a terminal, also raise `nmcli`'s independent
command wait. Its default 90-second wait can expire while NetworkManager is
still completing a valid SAML/MFA activation; that does not mean the VPN has
failed. Use:

```bash
nmcli --wait 360 connection up id "<connection name>"
```

For example, use `"FHNW"` as the connection name for the FHNW AnyConnect
profile. GlobalProtect profiles keep their existing timeout behavior.

## Reconnect behavior

The `nm-ms-sso-reconnect` system service observes manually started VPNs. Clicking
Connect keeps that profile enabled for the current boot:

| Event | Behavior |
| --- | --- |
| Server session expires, tunnel exits, or activation fails | Start a fresh NetworkManager activation after cleanup |
| Sleep or loss of the underlying network | Wait for resume and a usable uplink, then reconnect |
| Disconnect in GNOME or `nmcli connection down` | Stop reconnecting, including during authentication |
| Reboot or shutdown | Forget the previous Connect choice; do not activate a saved profile |

Retries continue without an attempt limit, with delays increasing from 5 seconds
to at most 5 minutes after repeated failures. Successful connections reset the
delay. Valid VPN cookies are reused; an expired session runs SSO again. MFA may
still require user interaction when required by the identity provider.

To disable retries even while waiting for the network, set the profile policy:

```bash
nmcli connection modify "FHNW" +vpn.data "auto-reconnect=false"
```

Set `auto-reconnect=true` and press Connect to enable it again. Do not configure
an uplink's `connection.secondaries` to activate this VPN if you want it to stay
off after reboot. Reconnect intent is held in memory, so restarting the observer
while disconnected also clears it.

Debian, Arch and the NixOS module enable the observer on installation. With a
manual Meson installation, enable it once:

```bash
sudo systemctl enable --now nm-ms-sso-reconnect.service
```

Microsoft authentication prefers structural field and method identifiers and
supports English, German, French and Italian password/TOTP picker labels. It
waits for document readiness and exposed reactive form bindings before password
entry, instead of adding a fixed login delay. New page structures can still
require adaptation; no client can guarantee availability or unchanged SSO pages.

Run regression checks with:

```bash
python3 -m unittest discover -s tests
meson test -C build-test --print-errorlogs
```

The browser readiness tests require the Playwright Chromium runtime. They serve
all browser requests from local fixtures and do not contact an identity provider.

Some FHNW sign-in attempts can still stall after the password-form action.
Automatic retries have recovered an observed session-expiry disconnect, but
first-attempt login and physical suspend/resume still need further validation.
See the [known limitations](docs/troubleshooting.md#known-limitations-in-207).

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
