# Connection progress and troubleshooting

These commands use the profile name `FHNW`. Replace it with your saved
NetworkManager profile name when using another institution. Status commands
are read-only and do not interrupt the tunnel.

## Watch a connection live

Start this before pressing Connect in GNOME Settings:

```bash
journalctl -f -t nm-ms-sso -t nm-ms-sso-reconnect
```

Both `-t` filters are included: `nm-ms-sso` reports SSO, OpenConnect, DNS checks,
and connection state; `nm-ms-sso-reconnect` reports the reconnect observer's
activation requests and retry scheduling. Press Ctrl+C to stop viewing logs;
this does not disconnect the VPN. Prefix `journalctl` with `sudo` if your account
cannot read the system journal.

The plugin uses a headless browser. The journal shows authentication milestones;
there is no browser window or percentage progress bar. An MFA number-matching
notification can appear when phone approval is required.

| Log message | Meaning |
| --- | --- |
| `SAML flow: portal-ready` | The login portal is open |
| `SAML flow: password-form-hydrating` | Waiting for the Microsoft form's scripts/bindings to be ready |
| `SAML flow: password-action-submitted` | A password-form action was taken; authentication is not yet complete |
| `SAML flow: credential-lookup-method-picker` | Microsoft is choosing the primary sign-in method |
| `SAML flow: mfa-totp-submitted` | A verification code was submitted |
| `SAML flow: waiting-for-vpn-callback` | Waiting for the VPN portal to finish SSO |
| `State changed to 3` | The plugin is connecting |
| `State changed to 4` | The plugin reported the connection as started; confirm NetworkManager says `activated` |
| `State changed to 6` | This plugin activation stopped; the observer may schedule a retry |
| `VPN ended ... reconnect scheduled` | The observer has scheduled another activation |
| `Reconnecting VPN ... (attempt N)` | The observer requested a fresh NetworkManager activation |

Messages may be absent on cached-session connections or differ by MFA method.
A retry message means another attempt started, not that a tunnel is already up.
Numeric `reason` values in observer messages are NetworkManager state reasons,
not HTTP or Microsoft error codes; inspect the accompanying plugin error.

## Check current connection and service status

```bash
nmcli -f NAME,TYPE,STATE connection show
nmcli -f GENERAL.STATE,GENERAL.VPN connection show FHNW
systemctl status nm-ms-sso-reconnect.service --no-pager
systemctl is-enabled nm-ms-sso-reconnect.service
```

`FHNW` with state `activated` is NetworkManager's current VPN status. An `active
(running)` reconnect service only means the observer is running; it can be idle
with the VPN switched off. `enabled` means the observer starts on boot, not that
it will automatically connect a saved VPN after reboot.

For a continuously refreshed status list:

```bash
watch -n 1 'nmcli -f NAME,TYPE,STATE connection show'
```

To inspect process IDs without printing process arguments:

```bash
systemctl show -p MainPID --value nm-ms-sso-reconnect.service
ps -C openconnect -o pid,ppid,etime,comm
```

The observer runs continuously. The D-Bus-activated `nm-ms-sso-service` helper
runs during authentication and tunnel operation and normally exits after two
idle minutes. OpenConnect appears after SSO hands off to tunnel setup; its
presence alone does not prove the tunnel has passed validation.

## Read recent errors

```bash
journalctl -b -t nm-ms-sso -t nm-ms-sso-reconnect --since '15 minutes ago' --no-pager
journalctl -b -u NetworkManager --since '15 minutes ago' --no-pager
```

Use the first command for SSO errors, failed validation, and retry history. The
second shows NetworkManager's view of activation and the underlying network.
To capture a report for an issue:

```bash
journalctl -b -t nm-ms-sso -t nm-ms-sso-reconnect --since '15 minutes ago' --no-pager > vpn-diagnostics.log
```

Include the installed version, approximate failure time, and whether the failure
followed Connect, sleep, or session expiry. Review the report before sharing:
logs can contain account identifiers, hostnames, internal addresses, and network
configuration. Do not include saved passwords, TOTP seeds, or session cookies.
On Debian/Ubuntu, read the installed version with:

```bash
dpkg-query -W -f='${Version}\n' network-manager-ms-sso
```

## Connect, disconnect, and stop retries

To connect from a terminal with enough time for SSO/MFA:

```bash
nmcli --wait 360 connection up id FHNW
```

The terminal command waits for completion; use the live journal command in a
second terminal for individual steps. Expiration of the terminal wait is not
itself proof that NetworkManager stopped the activation; check the status.

Disconnect using GNOME's VPN switch or:

```bash
nmcli connection down id FHNW
```

To disable future retries while the VPN is already disconnected or waiting for
the underlying network, set the persistent profile policy:

```bash
nmcli connection modify FHNW +vpn.data 'auto-reconnect=false'
```

That policy does not disconnect an established tunnel or cancel an activation
already requested. To disable retries and disconnect an active VPN, set the
policy first and then run the disconnect command above. If no active VPN
exists, `nmcli connection down` can report that it is not active; the policy
still disables subsequent retries.

To re-enable reconnect behavior:

```bash
nmcli connection modify FHNW +vpn.data 'auto-reconnect=true'
nmcli --wait 360 connection up id FHNW
```

Retries use increasing delays from 5 seconds to at most 5 minutes. They pause
while the underlying network is unavailable. The next activation also waits
for tunnel cleanup and network readiness, so the delay is not the total time
to reconnect. A successful connection resets the retry delay.

Avoid restarting the observer just to see progress. It holds intent in memory;
restarting it while the VPN is disconnected forgets that you wanted to reconnect.
After reboot, press Connect again. For behavior details, see
[Reconnect behavior](../README.md#reconnect-behavior).

## UniBas / GlobalProtect

The same reconnect service and journal filters apply to `Unibas`. For a saved
GlobalProtect profile, enable retries and set the activation allowance with:

```bash
nmcli connection modify Unibas +vpn.data 'auto-reconnect=true' vpn.timeout 360
nmcli -f GENERAL.STATE,GENERAL.VPN connection show Unibas
journalctl -f -t nm-ms-sso -t nm-ms-sso-reconnect
```

Keep an existing timeout above 360 seconds. These settings take effect for the
next activation; they do not switch away from a currently active FHNW tunnel.
The plugin supports one active VPN at a time. Disconnect the active VPN before
starting `nmcli --wait 360 connection up id Unibas`.

The configured UniBas gateway and registered MFA method should remain in place.
GlobalProtect direct-gateway authentication uses a single-use prelogin cookie,
so reconnecting may run SSO again even when browser-session caching is enabled.
A mock lifecycle test passing for GlobalProtect does not validate the live
UniBas identity provider, physical suspend/resume, or its session-expiry policy.

See [UniBas reconnect settings](../README.md#unibas-reconnect-settings) for the
protocol-specific details. To disable UniBas retries, use `auto-reconnect=false`
on that profile as described above for FHNW.

## Known limitations in 2.0.7

Some FHNW Microsoft sign-in attempts can still stall after the password-form
action. Automatic retries have recovered an observed session-expiry disconnect,
but this does not establish that first-attempt login is fixed. Inspect both the
failed attempt and the subsequent successful attempt when reporting this issue.

The regression suite exercises reconnect state transitions and local Chromium
fixtures. Physical suspend/resume, every identity-provider page variant, and a
guaranteed connection-speed improvement have not been established by those
tests. Identity-provider policy may still require interactive MFA.

## Installation notice about `_apt`

APT may say a local `.deb` was accessed unsandboxed as root because `_apt` could
not read a file inside your home directory. If unpacking and setup completed,
this notice does not indicate plugin installation failure. Check the installed
version and observer status using the commands above. Package installation
restarts NetworkManager and can briefly interrupt network connectivity.
