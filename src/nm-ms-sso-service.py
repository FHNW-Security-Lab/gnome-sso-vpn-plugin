#!/usr/bin/env python3
"""
NetworkManager VPN Plugin Service for MS SSO OpenConnect

This service implements the org.freedesktop.NetworkManager.VPN.Plugin
D-Bus interface to handle VPN connections via NetworkManager.

It uses the unified core module for:
- SAML authentication via headless browser
- OpenConnect VPN connection
- Keyring credential storage
- TOTP generation
"""

import json
import os
import re
import sys
import signal
import subprocess
import threading
import time
import logging
import socket
import ipaddress
import shutil
import stat
from pathlib import Path
from typing import Optional

# Set up logging - use syslog for reliability
log = logging.getLogger('nm-ms-sso')
log.setLevel(logging.DEBUG)

# Use syslog handler (most reliable for system services)
try:
    from logging.handlers import SysLogHandler
    syslog_handler = SysLogHandler(address='/dev/log')
    syslog_handler.setLevel(logging.DEBUG)
    syslog_handler.setFormatter(logging.Formatter('nm-ms-sso: %(message)s'))
    log.addHandler(syslog_handler)
except Exception:
    pass

# Also log to stderr (journalctl captures this from systemd services)
stderr_handler = logging.StreamHandler(sys.stderr)
stderr_handler.setLevel(logging.DEBUG)
stderr_handler.setFormatter(logging.Formatter('[nm-ms-sso] %(message)s'))
log.addHandler(stderr_handler)

# Try to also log to a file
try:
    file_handler = logging.FileHandler('/tmp/nm-ms-sso.log')
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
    log.addHandler(file_handler)
except Exception:
    pass

import gi
gi.require_version('NM', '1.0')
from gi.repository import GLib, NM

import dbus
import dbus.service
import dbus.mainloop.glib


def _setup_core_module():
    """Add core module to path if not already importable."""
    try:
        import core
        return
    except ImportError:
        pass

    # Development checkout: walk up until src/python/core exists.
    for repo_root in Path(__file__).resolve().parents:
        python_root = repo_root / "src" / "python"
        if python_root.exists() and (python_root / "core").exists():
            if str(python_root) not in sys.path:
                sys.path.insert(0, str(python_root))
            return

    # System installation paths
    system_paths = [
        Path("/usr/share/network-manager-ms-sso/python"),
        Path("/usr/lib/network-manager-ms-sso/python"),
        # Legacy install locations kept for backwards compatibility.
        Path("/usr/share/ms-sso-openconnect"),
        Path("/usr/lib/ms-sso-openconnect"),
        Path("/opt/ms-sso-openconnect"),
    ]
    for path in system_paths:
        if (path / "core").exists():
            if str(path) not in sys.path:
                sys.path.insert(0, str(path))
            return

    raise ImportError(
        "Cannot find core module. "
        f"Searched system paths: {', '.join(str(p) for p in system_paths)}"
    )


# Setup core module on import
_setup_core_module()

# Import from core module
from core import (
    do_saml_auth,
    PROTOCOLS,
)
from core.cookies import (
    store_nm_cookies,
    get_nm_stored_cookies,
    clear_nm_cookies,
)
from core.platform_info import get_gp_hip_report_wrapper, get_gp_os_version, get_openconnect_binary


# NetworkManager VPN Plugin D-Bus interface
NM_VPN_DBUS_PLUGIN_PATH = "/org/freedesktop/NetworkManager/VPN/Plugin"
NM_VPN_DBUS_PLUGIN_INTERFACE = "org.freedesktop.NetworkManager.VPN.Plugin"
NM_DBUS_SERVICE = "org.freedesktop.NetworkManager.ms-sso"

# VPN Plugin states (from NM headers)
NM_VPN_SERVICE_STATE_UNKNOWN = 0
NM_VPN_SERVICE_STATE_INIT = 1
NM_VPN_SERVICE_STATE_SHUTDOWN = 2
NM_VPN_SERVICE_STATE_STARTING = 3
NM_VPN_SERVICE_STATE_STARTED = 4
NM_VPN_SERVICE_STATE_STOPPING = 5
NM_VPN_SERVICE_STATE_STOPPED = 6

# Failure reasons
NM_VPN_PLUGIN_FAILURE_LOGIN_FAILED = 0
NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED = 1
NM_VPN_PLUGIN_FAILURE_BAD_IP_CONFIG = 2


class VPNPluginService(dbus.service.Object):
    """NetworkManager VPN Plugin D-Bus Service."""

    def __init__(self, bus):
        self.bus = bus
        self.state = NM_VPN_SERVICE_STATE_INIT
        self.vpn_process = None
        self.vpn_process_generation = None
        self.connection_thread = None
        self.mainloop = None
        self.inactivity_timeout = None
        # Store connection info for config emission
        self.current_gateway = None
        self.current_tun_device = None
        self.current_protocol = None
        self.current_gateway_host = None
        self.current_gateway_port = 443
        self.current_dns_server_limit = 3
        self.vpn_dns_servers = []
        self.vpn_domains = []
        self.vpn_tunnel_all_dns = None
        self.vpn_split_excludes = []
        self.vpn_split_includes = []
        self.owned_tun_devices = set()
        self.ipv6_leak_protection_enabled = False
        # Track GP connection timing so we can delay initial Config/UI state.
        self.gp_connect_start_time = None
        self.auth_in_progress = False
        self.saml_start_time = None
        self._auth_started_guard_triggered = False
        # Cancel flag (e.g. NM timeout/user disconnect) so we don't continue
        # long-running auth and connect behind NetworkManager's back.
        self.cancel_requested = False
        # Generation counter to invalidate stale overlapping connect threads.
        self._connect_generation = 0

        # Register on D-Bus
        bus_name = dbus.service.BusName(NM_DBUS_SERVICE, bus=bus)
        dbus.service.Object.__init__(self, bus_name, NM_VPN_DBUS_PLUGIN_PATH)

        log.info("Core module loaded successfully")

        # Set initial state
        self._set_state(NM_VPN_SERVICE_STATE_INIT)

        # Start inactivity timeout (quit after 2 minutes of inactivity)
        self._reset_inactivity_timeout()

    def _reset_inactivity_timeout(self):
        """Reset the inactivity timeout."""
        if self.inactivity_timeout is not None:
            # Check if source still exists before removing to avoid GLib warning
            source = GLib.main_context_default().find_source_by_id(self.inactivity_timeout)
            if source is not None:
                GLib.source_remove(self.inactivity_timeout)
            self.inactivity_timeout = None
        self.inactivity_timeout = GLib.timeout_add_seconds(120, self._on_inactivity_timeout)

    def _on_inactivity_timeout(self):
        """Called when the service has been inactive for too long."""
        # Keep the service alive while a connection worker is still active.
        if self.connection_thread and self.connection_thread.is_alive():
            return True
        # Mark timeout as fired so we don't try to remove it later.
        self.inactivity_timeout = None
        if self.state in (NM_VPN_SERVICE_STATE_INIT, NM_VPN_SERVICE_STATE_STOPPED):
            log.info("Inactivity timeout, shutting down")
            self._shutdown()
        return False

    def _shutdown(self):
        """Shutdown the service."""
        self._set_state(NM_VPN_SERVICE_STATE_SHUTDOWN)
        if self.mainloop:
            self.mainloop.quit()

    def _set_state(self, state):
        """Set and emit the VPN service state."""
        if self.state != state:
            self.state = state
            self.StateChanged(state)

    def _get_connection_secrets(self, settings):
        """Extract secrets from connection settings."""
        secrets = {}

        # Debug: print full settings structure
        log.info(f"Full settings keys: {list(settings.keys())}")

        # Get VPN settings
        vpn_settings = settings.get('vpn', {})
        vpn_data = vpn_settings.get('data', {})
        vpn_secrets = vpn_settings.get('secrets', {})

        log.info(f"VPN settings keys: {list(vpn_settings.keys())}")
        log.info(f"VPN data: {vpn_data}")
        log.info(f"VPN secrets keys: {list(vpn_secrets.keys())}")

        # Extract data fields
        secrets['gateway'] = vpn_data.get('gateway', '')
        secrets['protocol'] = vpn_data.get('protocol', 'anyconnect')
        secrets['username'] = vpn_data.get('username', '')
        secrets['gp_os_version'] = vpn_data.get('gp-os-version', '')
        secrets['disable_cookie_cache'] = vpn_data.get('disable-cookie-cache', '')
        secrets['disable_browser_session_cache'] = vpn_data.get('disable-browser-session-cache', '')
        secrets['enable_browser_session_cache'] = vpn_data.get('enable-browser-session-cache', '')
        secrets['skip_gp_cookie_cache'] = vpn_data.get('skip-gp-cookie-cache', '')
        secrets['auto_reconnect'] = vpn_data.get('auto-reconnect', '')
        secrets['reconnect_delay_seconds'] = vpn_data.get('reconnect-delay-seconds', '')
        secrets['reconnect_max_delay_seconds'] = vpn_data.get('reconnect-max-delay-seconds', '')
        secrets['reconnect_max_attempts'] = vpn_data.get('reconnect-max-attempts', '')
        secrets['dns_server_limit'] = vpn_data.get('dns-server-limit', '')

        # Extract secrets
        secrets['password'] = vpn_secrets.get('password', '')
        secrets['totp_secret'] = vpn_secrets.get('totp-secret', '')

        # If secrets not provided, try to get from keyring using libsecret
        # Use UUID (stable identifier) not connection name
        if not secrets['password'] or not secrets['totp_secret']:
            log.info(f"Secrets not in connection, trying keyring...")
            conn_uuid = settings.get('connection', {}).get('uuid', '')
            log.info(f"Connection UUID for keyring: {conn_uuid}")
            if conn_uuid:
                try:
                    # Use GObject introspection for libsecret (same schema as C editor)
                    gi.require_version('Secret', '1')
                    from gi.repository import Secret

                    schema = Secret.Schema.new(
                        "org.freedesktop.NetworkManager.ms-sso",
                        Secret.SchemaFlags.DONT_MATCH_NAME,
                        {
                            "connection-id": Secret.SchemaAttributeType.STRING,
                            "secret-type": Secret.SchemaAttributeType.STRING,
                        }
                    )

                    if not secrets['password']:
                        pw = Secret.password_lookup_sync(
                            schema, {"connection-id": conn_uuid, "secret-type": "password"}, None
                        )
                        if pw:
                            secrets['password'] = pw
                            log.info(f"Found password in keyring")
                        else:
                            log.info(f"Password not found in keyring")

                    if not secrets['totp_secret']:
                        totp = Secret.password_lookup_sync(
                            schema, {"connection-id": conn_uuid, "secret-type": "totp-secret"}, None
                        )
                        if totp:
                            secrets['totp_secret'] = totp
                            log.info(f"Found TOTP secret in keyring")
                        else:
                            log.info(f"TOTP secret not found in keyring")

                except Exception as ke:
                    log.info(f"Keyring error: {ke}")
                    import traceback
                    traceback.print_exc()

        return secrets

    def _is_truthy(self, value) -> bool:
        """Return True for common truthy config values."""
        if isinstance(value, bool):
            return value
        if value is None:
            return False
        return str(value).strip().lower() in {"1", "true", "yes", "on"}

    def _parse_bool(self, value):
        """Parse bool-like values; return True/False or None when unset/unknown."""
        if value is None:
            return None
        text = str(value).strip().lower()
        if text in {"1", "true", "yes", "on"}:
            return True
        if text in {"0", "false", "no", "off"}:
            return False
        return None

    def _has_usable_anyconnect_cookies(self, cookies) -> bool:
        """Return True when cookies contain a final Cisco WebVPN session."""
        if not cookies:
            return False
        return bool(
            cookies.get('webvpn')
            and (
                cookies.get('webvpnc')
                or cookies.get('webvpnaac')
                or cookies.get('SVPNCOOKIE')
            )
        )

    def _gp_early_started_enabled(self) -> bool:
        """Whether GP should optimistically report STARTED during auth."""
        value = self._parse_bool(os.environ.get("MS_SSO_NM_GP_EARLY_STARTED"))
        if value is None:
            # Default on: avoids NM connect-timeout for long GP SAML/MFA flows.
            return True
        return value

    def _get_tunnel_connect_timeout_seconds(self, protocol: str) -> int:
        """Return tunnel bring-up timeout (seconds) for protocol."""
        env_candidates = []
        if protocol == 'gp':
            env_candidates.append("MS_SSO_NM_GP_TUNNEL_TIMEOUT_SECONDS")
        if protocol == 'anyconnect':
            env_candidates.append("MS_SSO_NM_ANYCONNECT_TUNNEL_TIMEOUT_SECONDS")
        env_candidates.append("MS_SSO_NM_TUNNEL_TIMEOUT_SECONDS")

        for env_name in env_candidates:
            value = os.environ.get(env_name, "").strip()
            if not value:
                continue
            try:
                parsed = int(value)
                if parsed > 0:
                    return parsed
            except Exception:
                log.warning(f"Ignoring invalid {env_name} value: {value!r}")

        if protocol == 'anyconnect':
            return 45
        return 30

    def _list_tun_devices(self):
        """Return current tun* interface names."""
        tun_devs = set()
        try:
            links = subprocess.run(
                ["ip", "-o", "link", "show"],
                capture_output=True,
                text=True,
                check=False,
            )
            for line in links.stdout.splitlines():
                if ":" not in line:
                    continue
                parts = line.split(":", 2)
                if len(parts) < 2:
                    continue
                dev = parts[1].strip()
                if "@" in dev:
                    dev = dev.split("@", 1)[0]
                if dev.startswith("tun"):
                    tun_devs.add(dev)
        except Exception:
            pass
        return tun_devs

    def _tun_char_device_ready(self) -> bool:
        """Return True when /dev/net/tun can be opened."""
        try:
            fd = os.open("/dev/net/tun", os.O_RDWR | os.O_NONBLOCK)
            os.close(fd)
            return True
        except OSError as e:
            log.info(f"TUN device check failed: {e}")
            return False

    def _create_tun_char_device(self) -> None:
        """Best-effort creation of the standard /dev/net/tun character device."""
        try:
            os.makedirs("/dev/net", exist_ok=True)
            if not os.path.exists("/dev/net/tun"):
                os.mknod(
                    "/dev/net/tun",
                    stat.S_IFCHR | 0o666,
                    os.makedev(10, 200),
                )
                log.info("Created missing /dev/net/tun character device")
            os.chmod("/dev/net/tun", 0o666)
        except PermissionError as e:
            log.warning(f"No permission to create /dev/net/tun: {e}")
        except FileExistsError:
            pass
        except Exception as e:
            log.warning(f"Could not create /dev/net/tun: {e}")

    def _ensure_tun_available(self) -> bool:
        """Ensure OpenConnect can open /dev/net/tun before consuming cookies."""
        if self._tun_char_device_ready():
            return True

        modprobe = shutil.which("modprobe")
        if modprobe:
            try:
                result = subprocess.run(
                    [modprobe, "tun"],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=10,
                )
                if result.returncode == 0:
                    log.info("Loaded tun kernel module")
                else:
                    log.warning(
                        "modprobe tun failed: "
                        f"{(result.stderr or result.stdout).strip()}"
                    )
            except Exception as e:
                log.warning(f"modprobe tun failed: {e}")
        else:
            log.warning("modprobe not found in PATH; cannot auto-load tun module")

        self._create_tun_char_device()

        for _ in range(20):
            if self._tun_char_device_ready():
                return True
            time.sleep(0.25)

        log.error("TUN device unavailable: /dev/net/tun cannot be opened")
        return False

    def _parse_gateway_host(self, gateway: str) -> str:
        """Return the hostname part of the configured VPN gateway."""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(gateway if "://" in gateway else f"//{gateway}")
            return parsed.hostname or gateway
        except Exception:
            return gateway

    def _parse_gateway_port(self, gateway: str) -> int:
        """Return the port part of the configured VPN gateway."""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(gateway if "://" in gateway else f"//{gateway}")
            return parsed.port or 443
        except Exception:
            return 443

    def _get_openconnect_resolve_arg(self) -> Optional[str]:
        """Return a stable --resolve argument for reconnects when possible."""
        gateway_host = getattr(self, "current_gateway_host", None)
        gateway_ip = getattr(self, "current_gateway_ip", None)
        if not gateway_host or not gateway_ip or gateway_host == gateway_ip:
            return None
        return f"--resolve={gateway_host}:{gateway_ip}"

    def _probe_gateway(self, timeout_seconds: float = 3.0) -> bool:
        """Best-effort probe to detect dead uplinks while tun still exists."""
        gateway_ip = getattr(self, "current_gateway_ip", None)
        if not gateway_ip:
            return True
        gateway_port = getattr(self, "current_gateway_port", 443)
        try:
            with socket.create_connection((gateway_ip, gateway_port), timeout=timeout_seconds):
                return True
        except Exception:
            return False

    def _consume_vpn_stdout(self, output_buffer: str, openconnect_reported_up: bool, process=None):
        """Drain any available OpenConnect output without blocking."""
        process = process or self.vpn_process
        if not process or not process.stdout:
            return output_buffer, openconnect_reported_up

        while True:
            try:
                chunk = process.stdout.read(4096)
            except (BlockingIOError, IOError):
                break
            except Exception:
                break

            if not chunk:
                break

            text = chunk.decode('utf-8', errors='replace')
            output_buffer += text
            if len(output_buffer) > 65536:
                output_buffer = output_buffer[-65536:]

            for line in text.split('\n'):
                stripped = line.strip()
                if not stripped:
                    continue
                line_lc = line.lower()
                if 'DNS' in line.upper():
                    log.info(f"OpenConnect DNS info: {stripped}")
                    ips = re.findall(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b', line)
                    for ip in ips:
                        if ip not in self.vpn_dns_servers:
                            self.vpn_dns_servers.append(ip)
                            log.info(f"Captured VPN DNS: {ip}")
                if 'domain' in line_lc or 'search' in line_lc:
                    log.info(f"OpenConnect domain info: {stripped}")
                    self._capture_vpn_domains(stripped)
                if 'x-cstp-tunnel-all-dns' in line_lc:
                    value = stripped.split(':', 1)[1].strip() if ':' in stripped else ''
                    parsed = self._parse_bool(value)
                    if parsed is not None:
                        self.vpn_tunnel_all_dns = parsed
                        log.info(f"Captured Tunnel-All-DNS: {self.vpn_tunnel_all_dns}")
                if 'x-cstp-split-exclude' in line_lc:
                    self._capture_split_route(stripped, self.vpn_split_excludes, "exclude")
                if 'x-cstp-split-include' in line_lc:
                    self._capture_split_route(stripped, self.vpn_split_includes, "include")
                if any(marker in line_lc for marker in (
                    'x-cstp-split',
                    'x-cstp-address',
                    'x-cstp-netmask',
                    'x-cstp-route',
                    'route',
                )):
                    log.info(f"OpenConnect route info: {stripped}")
                if (
                    "connected as " in line_lc
                    or "cstp connected" in line_lc
                    or "esp session established" in line_lc
                    or "dtls connected" in line_lc
                    or "tun opened" in line_lc
                ):
                    if not openconnect_reported_up:
                        openconnect_reported_up = True
                        log.info("OpenConnect reported tunnel session up")

        return output_buffer, openconnect_reported_up

    def _capture_vpn_domains(self, line: str):
        """Capture DNS/search domains reported by OpenConnect."""
        if ':' not in line:
            return
        key, value = line.split(':', 1)
        key_lc = key.lower()
        if not any(token in key_lc for token in ('domain', 'search', 'split-dns')):
            return
        for domain in re.split(r'[\s,;]+', value.strip()):
            domain = domain.strip().strip('.')
            if not domain or domain == '-' or domain.lower() in {'none', 'false', 'true'}:
                continue
            if re.fullmatch(r'\d{1,3}(?:\.\d{1,3}){3}', domain):
                continue
            if not re.fullmatch(r'~?[A-Za-z0-9_.-]+', domain):
                continue
            if domain not in self.vpn_domains:
                self.vpn_domains.append(domain)
                log.info(f"Captured VPN DNS domain: {domain}")

    def _capture_split_route(self, line: str, target: list, route_type: str):
        """Capture split include/exclude route lines for routing decisions."""
        if ':' not in line:
            return
        value = line.split(':', 1)[1].strip()
        if not value or value in target:
            return
        target.append(value)
        log.info(f"Captured AnyConnect split {route_type}: {value}")

    def _ipv4_to_nm_uint32(self, ip_addr: str) -> int:
        """Return NetworkManager's host-order IPv4 uint32 representation."""
        parts = [int(x) for x in ip_addr.split('.')]
        if len(parts) != 4 or any(part < 0 or part > 255 for part in parts):
            raise ValueError(f"invalid IPv4 address: {ip_addr}")
        return parts[0] | (parts[1] << 8) | (parts[2] << 16) | (parts[3] << 24)

    def _reverse_ipv4_octets(self, ip_addr: str) -> Optional[str]:
        """Return an IPv4 address with reversed octets, or None if invalid."""
        try:
            parts = [int(x) for x in ip_addr.split('.')]
            if len(parts) != 4 or any(part < 0 or part > 255 for part in parts):
                return None
            return '.'.join(str(part) for part in reversed(parts))
        except Exception:
            return None

    def _get_tun_ipv4_config(self, tun_dev: str):
        """Return (ip, prefix) for a tunnel device, or (None, 32)."""
        try:
            result = subprocess.run(
                ['ip', '-4', 'addr', 'show', tun_dev],
                capture_output=True,
                text=True,
                check=False,
            )
        except Exception as e:
            log.warning(f"Could not read IPv4 config for {tun_dev}: {e}")
            return None, 32

        ip_addr = None
        prefix = 32
        for line in result.stdout.split('\n'):
            if 'inet ' not in line:
                continue
            parts = line.strip().split()
            if len(parts) < 2:
                continue
            addr_prefix = parts[1]
            if '/' in addr_prefix:
                ip_addr, prefix_str = addr_prefix.split('/', 1)
                try:
                    prefix = int(prefix_str)
                except Exception:
                    prefix = 32
            else:
                ip_addr = addr_prefix
            break

        return ip_addr, prefix

    def _build_dns_probe_query(self, name: str) -> tuple[bytes, bytes]:
        """Build a minimal DNS A query and return (transaction_id, packet)."""
        transaction_id = os.urandom(2)
        labels = [part for part in name.strip(".").split(".") if part]
        question = b"".join(
            bytes([len(label.encode("ascii", errors="ignore"))])
            + label.encode("ascii", errors="ignore")
            for label in labels
            if len(label.encode("ascii", errors="ignore")) <= 63
        )
        question += b"\x00\x00\x01\x00\x01"
        header = transaction_id + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        return transaction_id, header + question

    def _probe_dns_server(self, server: str, timeout_seconds: float = 2.0) -> bool:
        """Return True if a VPN DNS server responds to a basic UDP query."""
        query_name = self.current_gateway_host or self.current_gateway or "example.com"
        try:
            transaction_id, packet = self._build_dns_probe_query(query_name)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout_seconds)
                sock.sendto(packet, (server, 53))
                response, _addr = sock.recvfrom(512)
            return len(response) >= 12 and response[:2] == transaction_id
        except Exception as e:
            log.debug(f"DNS probe failed for {server}: {e}")
            return False

    def _vpn_dns_usable(self) -> bool:
        """Return True if at least one pushed VPN DNS server responds."""
        dns_servers = self._normalize_dns_servers(getattr(self, "vpn_dns_servers", []))
        if not dns_servers:
            return False
        for server in dns_servers:
            if self._probe_dns_server(server):
                log.info(f"VPN DNS probe succeeded via {server}")
                return True
        log.warning(f"VPN DNS probe failed for all servers: {dns_servers}")
        return False

    def _wait_for_vpn_dns_usable(
            self,
            connect_generation: Optional[int],
            timeout_seconds: int = 20,
            process=None,
    ) -> bool:
        """Wait until pushed VPN DNS responds after NetworkManager config is emitted."""
        dns_servers = self._normalize_dns_servers(getattr(self, "vpn_dns_servers", []))
        if not dns_servers:
            return True

        deadline = time.monotonic() + max(1, timeout_seconds)
        while time.monotonic() < deadline:
            if self._is_connect_cancelled(connect_generation):
                return False
            vpn_process = process or self.vpn_process
            if vpn_process and vpn_process.poll() is not None:
                return False
            if self._vpn_dns_usable():
                return True
            time.sleep(1)
        return False

    def _wait_for_usable_tunnel(
            self,
            protocol: str,
            tun_dev: str,
            connect_generation: Optional[int],
            min_stable_seconds: int = 0,
            timeout_seconds: int = 8,
            process=None,
    ):
        """Wait until the tunnel has IPv4 config and survives an optional stability window."""
        deadline = time.monotonic() + max(1, timeout_seconds)
        stable_since = None

        while time.monotonic() < deadline:
            if self._is_connect_cancelled(connect_generation):
                return False, "Connect cancelled while validating tunnel", None, 32
            vpn_process = process or self.vpn_process
            if vpn_process and vpn_process.poll() is not None:
                return False, "OpenConnect exited while validating tunnel", None, 32

            ip_addr, prefix = self._get_tun_ipv4_config(tun_dev)
            if ip_addr:
                if min_stable_seconds <= 0:
                    return True, None, ip_addr, prefix
                if stable_since is None:
                    stable_since = time.monotonic()
                elif time.monotonic() - stable_since >= min_stable_seconds:
                    return True, None, ip_addr, prefix
            else:
                stable_since = None

            time.sleep(0.5)

        return False, f"Tunnel {tun_dev} did not become usable with IPv4 config", None, 32

    def _stop_vpn_process(
            self,
            preserve_session: bool = True,
            force: bool = False,
            process=None,
            connect_generation: Optional[int] = None,
    ) -> None:
        """Stop OpenConnect while letting vpnc-script clean up when possible."""
        process = process or self.vpn_process
        if not process or process.poll() is not None:
            return
        if (
            process is self.vpn_process
            and connect_generation is not None
            and self.vpn_process_generation != connect_generation
        ):
            log.info(
                "Skipping OpenConnect stop from stale connect generation "
                f"{connect_generation}; current is {self.vpn_process_generation}"
            )
            return

        sig = signal.SIGHUP if preserve_session else signal.SIGTERM
        try:
            process.send_signal(sig)
            process.wait(timeout=5)
            return
        except ProcessLookupError:
            return
        except subprocess.TimeoutExpired:
            pass
        except Exception as e:
            log.warning(f"Failed to stop OpenConnect with {sig.name}: {e}")

        if force:
            try:
                process.kill()
                process.wait(timeout=5)
            except Exception:
                pass

    def _parse_positive_int(self, value, default: int) -> int:
        """Parse non-negative integer config values."""
        if value is None:
            return default
        text = str(value).strip()
        if not text:
            return default
        try:
            parsed = int(text)
            if parsed >= 0:
                return parsed
        except Exception:
            pass
        return default

    def _get_dns_server_limit(self, protocol: str, configured_value: str = "") -> int:
        """Return how many VPN DNS servers to hand to NetworkManager."""
        env_candidates = []
        if protocol == 'gp':
            env_candidates.append("MS_SSO_NM_GP_DNS_SERVER_LIMIT")
        if protocol == 'anyconnect':
            env_candidates.append("MS_SSO_NM_ANYCONNECT_DNS_SERVER_LIMIT")
        env_candidates.append("MS_SSO_NM_DNS_SERVER_LIMIT")

        default = 1 if protocol == 'gp' else 3
        limit = self._parse_positive_int(configured_value, -1)
        if limit >= 0:
            return limit

        for env_name in env_candidates:
            limit = self._parse_positive_int(os.environ.get(env_name), -1)
            if limit >= 0:
                return limit

        return default

    def _normalize_dns_servers(self, dns_servers):
        """Deduplicate textual IPv4 DNS servers and apply the active limit."""
        normalized = []
        seen = set()
        for ns in dns_servers:
            text = str(ns).strip()
            if not text or text in seen:
                continue
            try:
                parts = [int(x) for x in text.split('.')]
                if len(parts) != 4 or any(part < 0 or part > 255 for part in parts):
                    continue
            except Exception:
                continue
            normalized.append(text)
            seen.add(text)

        limit = self.current_dns_server_limit
        if limit == 0:
            log.info("VPN DNS server emission disabled by configuration")
            return []
        if len(normalized) > limit:
            dropped = normalized[limit:]
            log.info(
                "Limiting VPN DNS servers to "
                f"{limit}: using {normalized[:limit]}, dropping {dropped}"
            )
        return normalized[:limit]

    def _normalize_vpn_domains(self):
        """Return DNS domains to emit to NetworkManager."""
        domains = []
        seen = set()
        for domain in getattr(self, "vpn_domains", []):
            text = str(domain).strip().strip('.')
            if not text:
                continue
            route_only = text.startswith('~')
            bare = text[1:] if route_only else text
            if not re.fullmatch(r'[A-Za-z0-9_.-]+', bare):
                continue
            if self.current_protocol == 'anyconnect' and not self.vpn_tunnel_all_dns:
                text = f"~{bare}"
            elif route_only:
                text = f"~{bare}"
            else:
                text = bare
            if text not in seen:
                domains.append(text)
                seen.add(text)
        return domains

    def _anyconnect_preserve_default_route(self) -> bool:
        """Return True when AnyConnect should keep a default route over tun."""
        preserve = self._parse_bool(os.environ.get("MS_SSO_NM_ANYCONNECT_PRESERVE_DEFAULT_ROUTE"))
        if preserve is not None:
            return preserve
        if getattr(self, "vpn_split_excludes", []):
            # Cisco split-exclude means "route everything through VPN except these".
            return True
        if getattr(self, "vpn_split_includes", []):
            return False
        # Full-tunnel DNS normally implies the server expects full-tunnel routing.
        return bool(self.vpn_tunnel_all_dns)

    def _anyconnect_route_spec_to_cidr(self, route_spec: str) -> Optional[str]:
        """Convert Cisco split route notation to a CIDR route string."""
        try:
            if not route_spec:
                return None
            text = str(route_spec).strip()
            if "/" not in text:
                return str(ipaddress.ip_network(text, strict=False))
            addr, mask = text.split("/", 1)
            if "." in mask:
                return str(ipaddress.ip_network(f"{addr}/{mask}", strict=False))
            return str(ipaddress.ip_network(text, strict=False))
        except Exception as e:
            log.info(f"Could not parse AnyConnect route spec {route_spec!r}: {e}")
            return None

    def _cleanup_anyconnect_physical_routes(self) -> None:
        """Remove routes that vpnc-script may leave on the physical uplink."""
        if self.current_protocol != 'anyconnect':
            return

        route_cidrs = []
        for route_spec in getattr(self, "vpn_split_excludes", []):
            cidr = self._anyconnect_route_spec_to_cidr(route_spec)
            if cidr and cidr not in route_cidrs:
                route_cidrs.append(cidr)
        if getattr(self, "current_gateway_ip", None):
            route_cidrs.append(f"{self.current_gateway_ip}/32")
            reversed_gateway_ip = self._reverse_ipv4_octets(self.current_gateway_ip)
            if reversed_gateway_ip and reversed_gateway_ip != self.current_gateway_ip:
                route_cidrs.append(f"{reversed_gateway_ip}/32")
        if not route_cidrs:
            return

        tun_names = set(self.owned_tun_devices)
        if self.current_tun_device:
            tun_names.add(self.current_tun_device)
        tun_names.update(self._list_tun_devices())

        for cidr in route_cidrs:
            try:
                result = subprocess.run(
                    ["ip", "-4", "route", "show", cidr],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=5,
                )
            except Exception as e:
                log.info(f"Route inspection failed for {cidr}: {e}")
                continue

            for line in [line.strip() for line in result.stdout.splitlines() if line.strip()]:
                if not line.startswith(cidr.split("/", 1)[0]) and not line.startswith(cidr):
                    continue
                if any(f" dev {tun_dev}" in line for tun_dev in tun_names):
                    continue
                try:
                    delete = subprocess.run(
                        ["ip", "-4", "route", "del", cidr],
                        capture_output=True,
                        text=True,
                        check=False,
                        timeout=5,
                    )
                    if delete.returncode == 0:
                        log.info(f"Removed leaked AnyConnect physical route: {line}")
                    elif delete.stderr.strip():
                        log.info(
                            f"Could not remove leaked route {cidr}: "
                            f"{delete.stderr.strip()}"
                        )
                except Exception as e:
                    log.info(f"Leaked route cleanup failed for {cidr}: {e}")

    def _remove_tun_default_routes(self, tun_dev: str):
        """Best-effort cleanup for accidental full-tunnel defaults."""
        if not tun_dev:
            return False
        try:
            result = subprocess.run(
                ["ip", "-4", "route", "show", "default", "dev", tun_dev],
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )
            defaults = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        except Exception as e:
            log.info(f"Default route inspection failed for {tun_dev}: {e}")
            return False

        if not defaults:
            return False

        removed = False
        for route in defaults:
            try:
                subprocess.run(
                    ["ip", "-4", "route", "del", "default", "dev", tun_dev],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=5,
                )
                removed = True
                log.info(f"Removed VPN default route from {tun_dev}: {route}")
            except Exception as e:
                log.info(f"Default route cleanup failed for {tun_dev}: {e}")
        return removed

    def _apply_split_dns_resolved(self, tun_dev: str, domains):
        """Force route-only DNS after NetworkManager has processed Ip4Config."""
        if not tun_dev or self.current_protocol != 'anyconnect' or self.vpn_tunnel_all_dns:
            return False
        if self._anyconnect_preserve_default_route():
            log.info(
                "Keeping VPN DNS as a default resolver on full-tunnel/split-exclude "
                f"AnyConnect link {tun_dev}"
            )
            return False
        if not shutil.which("resolvectl"):
            return False

        route_domains = [domain for domain in domains if str(domain).startswith('~')]
        try:
            if route_domains:
                subprocess.run(
                    ["resolvectl", "domain", tun_dev, *route_domains],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=5,
                )
                log.info(f"Applied route-only VPN DNS domains on {tun_dev}: {route_domains}")
            subprocess.run(
                ["resolvectl", "default-route", tun_dev, "false"],
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )
            log.info(f"Disabled DNS default route on {tun_dev}")
        except Exception as e:
            log.info(f"Split DNS adjustment failed for {tun_dev}: {e}")

        if not self._anyconnect_preserve_default_route():
            self._remove_tun_default_routes(tun_dev)
        return False

    def _is_connect_cancelled(self, connect_generation: Optional[int] = None) -> bool:
        """Return True when the active connect flow should abort."""
        if self.cancel_requested:
            return True
        if connect_generation is not None and connect_generation != self._connect_generation:
            return True
        return False

    def _interruptible_sleep(self, seconds: int, connect_generation: Optional[int] = None) -> bool:
        """Sleep up to `seconds`, aborting early if disconnect is requested."""
        if seconds <= 0:
            return not self._is_connect_cancelled(connect_generation)
        end_time = time.monotonic() + seconds
        while time.monotonic() < end_time:
            if self._is_connect_cancelled(connect_generation):
                return False
            time.sleep(min(0.5, end_time - time.monotonic()))
        return not self._is_connect_cancelled(connect_generation)

    def _connect_thread(self, settings, connect_generation: int):
        """Worker thread for VPN connection."""
        try:
            self._reset_inactivity_timeout()
            if connect_generation != self._connect_generation:
                return
            self.cancel_requested = False

            def _connect_cancelled() -> bool:
                return self._is_connect_cancelled(connect_generation)

            # Extract connection parameters
            secrets = self._get_connection_secrets(settings)
            gateway = secrets['gateway']
            protocol = secrets['protocol']
            username = secrets['username']
            password = secrets['password']
            totp_secret = secrets['totp_secret']
            gp_os_version = (secrets.get('gp_os_version') or '').strip()
            disable_cookie_cache = (
                self._is_truthy(secrets.get('disable_cookie_cache'))
                or self._is_truthy(os.environ.get("MS_SSO_NM_DISABLE_COOKIE_CACHE"))
            )
            skip_gp_cookie_cache = (
                protocol == 'gp'
                and (
                    self._is_truthy(secrets.get('skip_gp_cookie_cache'))
                    or self._is_truthy(os.environ.get("MS_SSO_NM_GP_SKIP_COOKIE_CACHE"))
                )
            )
            force_enable_browser_session_cache = (
                self._is_truthy(secrets.get('enable_browser_session_cache'))
                or self._is_truthy(os.environ.get("MS_SSO_NM_ENABLE_BROWSER_SESSION_CACHE"))
                or (
                    protocol == 'gp'
                    and self._is_truthy(os.environ.get("MS_SSO_NM_GP_ENABLE_BROWSER_SESSION_CACHE"))
                )
                or (
                    protocol == 'anyconnect'
                    and self._is_truthy(os.environ.get("MS_SSO_NM_ANYCONNECT_ENABLE_BROWSER_SESSION_CACHE"))
                )
            )
            disable_browser_session_cache = (
                self._is_truthy(secrets.get('disable_browser_session_cache'))
                or self._is_truthy(os.environ.get("MS_SSO_NM_DISABLE_BROWSER_SESSION_CACHE"))
                or (protocol in {'gp', 'anyconnect'} and not force_enable_browser_session_cache)
            )
            if force_enable_browser_session_cache:
                disable_browser_session_cache = False
            log.info(
                "Browser session cache: "
                f"{'disabled' if disable_browser_session_cache else 'enabled'}"
            )
            if protocol in {'gp', 'anyconnect'} and disable_browser_session_cache and not force_enable_browser_session_cache:
                log.info(
                    f"{protocol} uses a fresh browser session by default; "
                    "set enable-browser-session-cache=1 to reuse SSO browser state"
                )

            if not gateway:
                raise Exception("No gateway specified")

            if not username:
                raise Exception("No username specified")

            log.info(f"Connecting to {gateway} via {protocol}")
            log.info(f"Username: {username}")
            if protocol == 'gp':
                log.info(f"GlobalProtect OS version: {gp_os_version or get_gp_os_version()}")
            log.debug(f"Password: {'(set)' if password else '(not set)'}")
            log.debug(f"TOTP: {'(set)' if totp_secret else '(not set)'}")

            # Store gateway for config emission
            self.current_gateway = gateway
            self.current_protocol = protocol
            self.current_gateway_host = self._parse_gateway_host(gateway)
            self.current_gateway_port = self._parse_gateway_port(gateway)
            self.current_dns_server_limit = self._get_dns_server_limit(
                protocol,
                secrets.get('dns_server_limit', ''),
            )
            log.info(f"VPN DNS server limit: {self.current_dns_server_limit}")

            # IMPORTANT: Resolve gateway IP NOW, before VPN connects
            # After VPN connects, DNS switches to VPN DNS servers which can't resolve external hostnames
            self.current_gateway_ip = None
            gateway_lookup = gateway
            try:
                from urllib.parse import urlparse
                parsed = urlparse(gateway if "://" in gateway else f"//{gateway}")
                if parsed.hostname:
                    gateway_lookup = parsed.hostname
            except Exception:
                gateway_lookup = gateway
            try:
                self.current_gateway_ip = socket.gethostbyname(gateway_lookup)
                log.info(f"Pre-resolved gateway {gateway_lookup} -> {self.current_gateway_ip}")
            except Exception as e:
                log.warning(f"Failed to pre-resolve gateway {gateway_lookup}: {e}")
                # If gateway is already an IP address, use it
                if gateway and gateway[0].isdigit():
                    self.current_gateway_ip = gateway
                    log.info(f"Gateway appears to be an IP address: {gateway}")

            # Safeguard: remove bogus on-link /32 host route to gateway IP if present.
            # Some networks inject a host route that forces ARP on LAN and breaks reachability.
            if self.current_gateway_ip:
                self._clear_onlink_host_route(self.current_gateway_ip)
                self._cleanup_anyconnect_physical_routes()

            # Only GP gets pre-tunnel Config keepalives. For AnyConnect this can
            # make NetworkManager show "connected" even though SAML produced no
            # cookie and no tun device exists yet.
            if protocol == 'gp':
                # Delay GP's first Config emission as well; keep UI in "connecting".
                self.gp_connect_start_time = time.monotonic()
                if os.environ.get("MS_SSO_NM_GP_EARLY_CONFIG", "").lower() in {"1", "true", "yes"}:
                    GLib.idle_add(self._emit_initial_config)
            # NetworkManager expects the plugin to reach STARTED in a timely manner or it
            # may cancel the connection (observed ~60s). GlobalProtect SAML/MFA flows can
            # easily exceed that, so GP defaults to optimistic STARTED during auth.
            # Set MS_SSO_NM_GP_EARLY_STARTED=0 to keep "Connecting" until tunnel up.
            if protocol == 'gp':
                if self._gp_early_started_enabled():
                    GLib.idle_add(self._emit_started_for_auth)

            # Connection name for cookie cache
            connection_name = f"nm-{gateway}"
            log.debug(f"Cookie cache connection name: {connection_name}")
            # Auto-reconnect watchdog configuration
            conn_auto_reconnect = self._parse_bool(secrets.get('auto_reconnect'))
            env_auto_reconnect = self._parse_bool(os.environ.get("MS_SSO_NM_AUTO_RECONNECT"))
            gp_env_auto_reconnect = self._parse_bool(os.environ.get("MS_SSO_NM_GP_AUTO_RECONNECT")) if protocol == 'gp' else None
            if conn_auto_reconnect is not None:
                auto_reconnect = conn_auto_reconnect
            elif gp_env_auto_reconnect is not None:
                auto_reconnect = gp_env_auto_reconnect
            elif env_auto_reconnect is not None:
                auto_reconnect = env_auto_reconnect
            else:
                auto_reconnect = True

            reconnect_delay_seconds = self._parse_positive_int(
                secrets.get('reconnect_delay_seconds'),
                self._parse_positive_int(
                    os.environ.get("MS_SSO_NM_GP_RECONNECT_DELAY_SECONDS") if protocol == 'gp' else None,
                    self._parse_positive_int(os.environ.get("MS_SSO_NM_RECONNECT_DELAY_SECONDS"), 5),
                ),
            )
            reconnect_max_delay_seconds = self._parse_positive_int(
                secrets.get('reconnect_max_delay_seconds'),
                self._parse_positive_int(
                    os.environ.get("MS_SSO_NM_GP_RECONNECT_MAX_DELAY_SECONDS") if protocol == 'gp' else None,
                    self._parse_positive_int(os.environ.get("MS_SSO_NM_RECONNECT_MAX_DELAY_SECONDS"), 60),
                ),
            )
            reconnect_default_max_attempts = 0 if protocol == 'anyconnect' else 5
            reconnect_max_attempts = self._parse_positive_int(
                secrets.get('reconnect_max_attempts'),
                self._parse_positive_int(
                    os.environ.get("MS_SSO_NM_GP_RECONNECT_MAX_ATTEMPTS") if protocol == 'gp' else None,
                    self._parse_positive_int(
                        os.environ.get("MS_SSO_NM_RECONNECT_MAX_ATTEMPTS"),
                        reconnect_default_max_attempts,
                    ),
                ),
            )
            reconnect_limit_label = "inf" if reconnect_max_attempts == 0 else str(reconnect_max_attempts)
            reconnect_reset_seconds = self._parse_positive_int(os.environ.get("MS_SSO_NM_RECONNECT_RESET_SECONDS"), 120)
            watchdog_interval_seconds = self._parse_positive_int(os.environ.get("MS_SSO_NM_WATCHDOG_INTERVAL_SECONDS"), 5)
            watchdog_missing_tun_limit = self._parse_positive_int(os.environ.get("MS_SSO_NM_WATCHDOG_TUN_MISS_LIMIT"), 3)
            anyconnect_wait_existing_auth_seconds = 0
            anyconnect_fresh_retries = 0
            anyconnect_retry_delay_seconds = 0
            anyconnect_unstable_session_seconds = 0
            anyconnect_fast_reconnect_retries = 0
            if protocol == 'anyconnect':
                anyconnect_wait_existing_auth_seconds = self._parse_positive_int(
                    os.environ.get("MS_SSO_NM_ANYCONNECT_WAIT_AUTH_SECONDS"),
                    90,
                )
                anyconnect_fresh_retries = self._parse_positive_int(
                    os.environ.get("MS_SSO_NM_ANYCONNECT_FRESH_RETRIES"),
                    0,
                )
                anyconnect_retry_delay_seconds = self._parse_positive_int(
                    os.environ.get("MS_SSO_NM_ANYCONNECT_RETRY_DELAY_SECONDS"),
                    2,
                )
                anyconnect_unstable_session_seconds = self._parse_positive_int(
                    os.environ.get("MS_SSO_NM_ANYCONNECT_UNSTABLE_SESSION_SECONDS"),
                    20,
                )
                anyconnect_fast_reconnect_retries = self._parse_positive_int(
                    os.environ.get("MS_SSO_NM_ANYCONNECT_FAST_RECONNECT_RETRIES"),
                    2,
                )
            log.info(
                "Auto-reconnect: "
                f"{'enabled' if auto_reconnect else 'disabled'}, "
                f"delay={reconnect_delay_seconds}s, max-delay={reconnect_max_delay_seconds}s, "
                f"max-attempts={reconnect_limit_label}"
            )
            if protocol == 'anyconnect':
                log.info(
                    "AnyConnect fresh-auth retries: "
                    f"{anyconnect_fresh_retries} (delay={anyconnect_retry_delay_seconds}s)"
                )
                log.info(
                    "AnyConnect wait-for-existing-auth window: "
                    f"{anyconnect_wait_existing_auth_seconds}s"
                )
                log.info(
                    "AnyConnect unstable-session handling: "
                    f"threshold={anyconnect_unstable_session_seconds}s, "
                    f"fast-retries={anyconnect_fast_reconnect_retries}"
                )

            reconnect_attempt = 0
            anyconnect_fast_reconnect_attempt = 0
            force_fresh_auth = False
            saml_keepalive_seconds = self._parse_positive_int(
                os.environ.get("MS_SSO_NM_AUTH_KEEPALIVE_SECONDS"),
                self._parse_positive_int(
                    os.environ.get("MS_SSO_NM_GP_AUTH_KEEPALIVE_SECONDS") if protocol == 'gp' else None,
                    10,
                ),
            )

            while not _connect_cancelled():
                # Try connection with retry on cookie rejection.
                max_attempts = 2 + anyconnect_fresh_retries
                connection_ended = False
                connection_uptime_seconds = 0
                final_error = None
                session_used_cache = False
                fresh_auth_attempts = 0

                for attempt in range(max_attempts):
                    log.info(f"Connection attempt {attempt + 1}/{max_attempts}")
                    if _connect_cancelled():
                        log.info("Connect cancelled before authentication; aborting")
                        return

                    # Try cached cookies first (unless explicitly disabled).
                    cookies = None
                    used_cache = False

                    if attempt == 0 and force_fresh_auth:
                        log.info("Skipping cached cookies for this cycle; forcing fresh authentication")
                    elif attempt == 0 and skip_gp_cookie_cache:
                        log.info("GlobalProtect cookie cache disabled by configuration; forcing fresh authentication")
                    elif attempt == 0 and disable_cookie_cache:
                        log.info("Cookie cache disabled; forcing fresh authentication")
                    elif attempt == 0:
                        log.debug("Checking for cached cookies...")
                        cached = get_nm_stored_cookies(connection_name, max_age_hours=12)
                        if cached:
                            # cached is tuple (cookies_dict, usergroup)
                            cookies, usergroup = cached
                            used_cache = True
                            if protocol == 'anyconnect' and not self._has_usable_anyconnect_cookies(cookies):
                                log.warning(
                                    "Ignoring incomplete cached AnyConnect cookies "
                                    f"(keys: {list(cookies.keys()) if cookies else 'none'})"
                                )
                                clear_nm_cookies(connection_name)
                                cookies = None
                                used_cache = False
                            else:
                                log.info(f"Using cached cookies (keys: {list(cookies.keys()) if cookies else 'none'})")
                            # Optional sensitive debug dump; disabled by default.
                            if cookies and self._is_truthy(os.environ.get("MS_SSO_NM_DEBUG_DUMP_COOKIES")):
                                try:
                                    with open('/tmp/nm-vpn-cached-cookies.json', 'w') as f:
                                        json.dump({"source": "cache", "cookies": cookies, "usergroup": usergroup}, f, indent=2)
                                    log.debug("Cached cookies written to /tmp/nm-vpn-cached-cookies.json")
                                except Exception as e:
                                    log.debug(f"Could not write cached cookies debug file: {e}")
                        else:
                            log.info("No valid cached cookies found")

                    # If no cached cookies or this is a retry, authenticate
                    if not cookies:
                        if (
                            protocol == 'anyconnect'
                            and anyconnect_wait_existing_auth_seconds > 0
                            and self.auth_in_progress
                        ):
                            log.info(
                                "AnyConnect authentication already in progress in another worker; "
                                f"waiting up to {anyconnect_wait_existing_auth_seconds}s for reusable cookies"
                            )
                            wait_deadline = time.monotonic() + anyconnect_wait_existing_auth_seconds
                            while time.monotonic() < wait_deadline:
                                if _connect_cancelled():
                                    log.info("Connect cancelled while waiting for existing authentication")
                                    return
                                cached = get_nm_stored_cookies(connection_name, max_age_hours=12)
                                if cached:
                                    cookies, usergroup = cached
                                    if self._has_usable_anyconnect_cookies(cookies):
                                        used_cache = True
                                        log.info("Reused cookies generated by concurrent AnyConnect authentication")
                                        break
                                    log.warning(
                                        "Ignoring incomplete AnyConnect cookies generated by concurrent authentication "
                                        f"(keys: {list(cookies.keys()) if cookies else 'none'})"
                                    )
                                    clear_nm_cookies(connection_name)
                                    cookies = None
                                if not self.auth_in_progress:
                                    break
                                if not self._interruptible_sleep(2, connect_generation):
                                    return

                    if not cookies:
                        log.info("Performing SAML authentication...")
                        fresh_auth_attempts += 1
                        self.auth_in_progress = True
                        self.saml_start_time = time.monotonic()
                        self._auth_started_guard_triggered = False

                        # Keep NetworkManager from timing out while SAML is in progress.
                        # Some SSO/MFA flows exceed NM's observed ~60s activation timeout.
                        stop_keepalive = threading.Event()

                        def _saml_keepalive():
                            while not stop_keepalive.wait(max(1, saml_keepalive_seconds)):
                                if _connect_cancelled():
                                    return
                                if self._auth_initial_config_allowed(protocol):
                                    GLib.idle_add(self._emit_initial_config)
                                # Keep NetworkManager from thinking the connection stalled.
                                if self._should_emit_started_keepalive(protocol):
                                    GLib.idle_add(self._emit_started_keepalive)
                                else:
                                    GLib.idle_add(self._emit_starting_keepalive)

                        keepalive_thread = threading.Thread(target=_saml_keepalive, daemon=True)
                        keepalive_thread.start()
                        auth_failed = False

                        # Ensure playwright can find the browser.
                        import glob
                        browser_paths = [
                            "/root/.cache/ms-playwright",
                            "/var/cache/ms-playwright",
                        ]
                        # Expand user home directories
                        home_paths = glob.glob("/home/*/.cache/ms-playwright")
                        browser_paths.extend(home_paths)

                        # Try to find existing playwright installation
                        playwright_path_found = False
                        for p in browser_paths:
                            if not os.path.isdir(p):
                                continue
                            # Check for chromium directory (e.g., chromium-1234)
                            chromium_dirs = glob.glob(os.path.join(p, "chromium*"))
                            if chromium_dirs:
                                os.environ['PLAYWRIGHT_BROWSERS_PATH'] = p
                                log.info(f"Using playwright browsers from: {p}")
                                playwright_path_found = True
                                break

                        if not playwright_path_found:
                            log.warning(f"No playwright browser found in any of: {browser_paths}")

                        try:
                            cookies = do_saml_auth(
                                vpn_server=gateway,
                                vpn_server_ip=self.current_gateway_ip,
                                username=username,
                                password=password,
                                totp_secret=totp_secret,
                                auto_totp=True,
                                headless=True,
                                debug=True,  # Enable debug to see screenshots
                                protocol=protocol,  # Pass protocol for correct SAML URL
                                disable_browser_session_cache=disable_browser_session_cache,
                                gp_os_version=gp_os_version or None,
                            )
                            log.info(f"SAML auth returned cookies: {list(cookies.keys()) if cookies else 'none'}")
                            if protocol == 'anyconnect' and cookies and not self._has_usable_anyconnect_cookies(cookies):
                                log.warning(
                                    "Ignoring incomplete AnyConnect SAML cookies "
                                    f"(keys: {list(cookies.keys())})"
                                )
                                cookies = None
                            # Optional sensitive debug dump; disabled by default.
                            if self._is_truthy(os.environ.get("MS_SSO_NM_DEBUG_DUMP_COOKIES")):
                                try:
                                    with open('/tmp/nm-vpn-fresh-cookies.json', 'w') as f:
                                        json.dump({"source": "fresh_saml", "cookies": cookies}, f, indent=2)
                                    log.debug("Fresh cookies written to /tmp/nm-vpn-fresh-cookies.json")
                                except Exception as e:
                                    log.debug(f"Could not write fresh cookies debug file: {e}")
                        except Exception as auth_err:
                            log.error(f"SAML auth error: {auth_err}")
                            import traceback
                            traceback.print_exc()
                            final_error = f"SAML authentication error: {auth_err}"
                            auth_failed = True
                        finally:
                            self.auth_in_progress = False
                            self.saml_start_time = None
                            self._auth_started_guard_triggered = False
                            stop_keepalive.set()

                        if auth_failed:
                            break
                        if not cookies:
                            final_error = "SAML authentication returned no cookies"
                            break

                        # Store fresh cookies unless cache is explicitly disabled.
                        # Store before cancellation check so NM-triggered reconnects can
                        # reuse fresh auth result and skip duplicate browser auth flows.
                        if not disable_cookie_cache and not skip_gp_cookie_cache and not used_cache:
                            store_nm_cookies(connection_name, cookies, usergroup='portal:prelogin-cookie')

                        if _connect_cancelled():
                            log.info("Connect cancelled during authentication; fresh cookies preserved for retry")
                            return

                    # Try to connect with these cookies
                    if _connect_cancelled():
                        log.info("Connect cancelled before starting OpenConnect; aborting")
                        return
                    success, error_msg, uptime_seconds = self._attempt_vpn_connection(
                        gateway,
                        protocol,
                        cookies,
                        username,
                        used_cache=used_cache,
                        gp_os_version=gp_os_version,
                        connect_generation=connect_generation,
                        watchdog_interval_seconds=watchdog_interval_seconds,
                        watchdog_missing_tun_limit=watchdog_missing_tun_limit,
                    )

                    if _connect_cancelled():
                        log.info("Connect cancelled after OpenConnect attempt; preserving cookie cache")
                        return

                    if success:
                        connection_ended = True
                        connection_uptime_seconds = uptime_seconds
                        session_used_cache = used_cache
                        log.info("VPN connection established and later ended")
                        break
                    elif used_cache and attempt < max_attempts - 1:
                        if (
                            error_msg
                            and 'cookie' in error_msg.lower()
                            and (
                                'reject' in error_msg.lower()
                                or 'invalid' in error_msg.lower()
                                or 'fail' in error_msg.lower()
                            )
                        ):
                            log.warning("Cached cookie rejected, clearing cache and re-authenticating...")
                            clear_nm_cookies(connection_name)
                            continue
                        log.warning(
                            "Cached AnyConnect cookie did not establish a usable tunnel; "
                            "preserving cache and letting reconnect retry it"
                        )
                        final_error = error_msg or "VPN connection failed"
                        break
                    elif (
                        protocol == 'anyconnect'
                        and not used_cache
                        and attempt < max_attempts - 1
                        and fresh_auth_attempts <= anyconnect_fresh_retries
                    ):
                        # First-time AnyConnect auth can be flaky on some deployments.
                        # Retry fresh auth once (or configured times) before failing.
                        log.warning(
                            "AnyConnect fresh-auth connect attempt failed; "
                            "clearing cached fresh cookie and retrying authentication..."
                        )
                        clear_nm_cookies(connection_name)
                        if anyconnect_retry_delay_seconds > 0:
                            if not self._interruptible_sleep(anyconnect_retry_delay_seconds, connect_generation):
                                return
                        continue
                    else:
                        if (
                            not used_cache
                            and not (
                                protocol == 'anyconnect'
                                and error_msg
                                and 'dns' in error_msg.lower()
                            )
                        ):
                            clear_nm_cookies(connection_name)
                        final_error = error_msg or "VPN connection failed"
                        break

                if _connect_cancelled():
                    return

                if not connection_ended:
                    reconnect_attempt += 1
                    if not auto_reconnect:
                        raise Exception(final_error or "VPN connection failed")
                    if reconnect_max_attempts > 0 and reconnect_attempt > reconnect_max_attempts:
                        raise Exception(
                            (final_error or "VPN connection failed")
                            + f" (watchdog retry limit reached: {reconnect_max_attempts})"
                        )

                    self._cleanup_dns()
                    backoff_step = min(max(reconnect_attempt - 1, 0), 6)
                    delay_seconds = min(
                        reconnect_delay_seconds * (2 ** backoff_step),
                        reconnect_max_delay_seconds,
                    ) if reconnect_max_delay_seconds > 0 else reconnect_delay_seconds
                    log.warning(
                        "Watchdog: VPN connection failed; "
                        f"retrying in {delay_seconds}s (attempt {reconnect_attempt}/{reconnect_limit_label})"
                    )
                    if protocol == 'gp' and self._gp_early_started_enabled():
                        GLib.idle_add(self._emit_started_keepalive)
                    else:
                        GLib.idle_add(self._emit_starting_keepalive)
                    if protocol == 'gp' and self._gp_initial_config_allowed():
                        GLib.idle_add(self._emit_initial_config)
                    if not self._interruptible_sleep(delay_seconds, connect_generation):
                        return
                    continue

                # Connection was up and then ended (e.g., network loss/session timeout).
                if (
                    protocol == 'anyconnect'
                    and anyconnect_unstable_session_seconds > 0
                    and 0 < connection_uptime_seconds < anyconnect_unstable_session_seconds
                ):
                    if session_used_cache:
                        clear_nm_cookies(connection_name)
                        force_fresh_auth = True
                    else:
                        force_fresh_auth = False

                    if anyconnect_fast_reconnect_attempt < anyconnect_fast_reconnect_retries:
                        anyconnect_fast_reconnect_attempt += 1
                        delay_seconds = max(1, anyconnect_retry_delay_seconds)
                        log.warning(
                            "AnyConnect tunnel ended shortly after connect "
                            f"(uptime={connection_uptime_seconds}s < {anyconnect_unstable_session_seconds}s); "
                            f"retrying quickly in {delay_seconds}s "
                            f"(fast attempt {anyconnect_fast_reconnect_attempt}/{anyconnect_fast_reconnect_retries})"
                        )
                        self._cleanup_dns()
                        # Keep NetworkManager in a reconnecting state until a new
                        # tunnel is actually established. Advertising STARTED
                        # here leaves stale VPN routing/DNS active.
                        GLib.idle_add(self._emit_starting_keepalive)
                        if not self._interruptible_sleep(delay_seconds, connect_generation):
                            return
                        continue

                anyconnect_fast_reconnect_attempt = 0
                force_fresh_auth = False
                if connection_uptime_seconds >= reconnect_reset_seconds:
                    reconnect_attempt = 0
                else:
                    reconnect_attempt += 1

                if not auto_reconnect:
                    GLib.idle_add(self._emit_disconnected)
                    return
                if reconnect_max_attempts > 0 and reconnect_attempt > reconnect_max_attempts:
                    raise Exception(
                        "VPN tunnel ended unexpectedly and watchdog retry limit was reached "
                        f"({reconnect_max_attempts})"
                    )

                self._cleanup_dns()
                backoff_step = min(max(reconnect_attempt - 1, 0), 6)
                delay_seconds = min(
                    reconnect_delay_seconds * (2 ** backoff_step),
                    reconnect_max_delay_seconds,
                ) if reconnect_max_delay_seconds > 0 else reconnect_delay_seconds
                log.warning(
                    "Watchdog: VPN tunnel ended unexpectedly "
                    f"(uptime={connection_uptime_seconds}s); reconnecting in {delay_seconds}s "
                    f"(attempt {reconnect_attempt}/{reconnect_limit_label})"
                )
                if protocol == 'gp' and self._gp_early_started_enabled():
                    GLib.idle_add(self._emit_started_keepalive)
                else:
                    GLib.idle_add(self._emit_starting_keepalive)
                if protocol == 'gp' and self._gp_initial_config_allowed():
                    GLib.idle_add(self._emit_initial_config)
                if not self._interruptible_sleep(delay_seconds, connect_generation):
                    return

        except Exception as e:
            error_msg = str(e)
            log.error(f"Connection error: {error_msg}")
            import traceback
            traceback.print_exc()
            GLib.idle_add(lambda msg=error_msg: self._emit_failure(msg))

    def _attempt_vpn_connection(
            self,
            gateway,
            protocol,
            cookies,
            username=None,
            used_cache=False,
            gp_os_version=None,
            connect_generation: Optional[int] = None,
            watchdog_interval_seconds=5,
            watchdog_missing_tun_limit=3,
    ):
        """Attempt to establish VPN connection with given cookies.

        Returns:
            Tuple of:
                success: tunnel was established at least once
                error_message: connection error details when success=False
                uptime_seconds: connected runtime before exit (0 on failure)
        """
        try:
            # Log cookie info for debugging
            log.debug(f"Cookie keys: {list(cookies.keys())}")

            # Connect to VPN
            # We use subprocess so we can monitor and return control
            proto_flag = PROTOCOLS.get(protocol, {}).get('flag', 'anyconnect')
            openconnect_bin = get_openconnect_binary(protocol)
            resolve_arg = self._get_openconnect_resolve_arg()
            reconnect_arg = "--reconnect-timeout=300"
            dpd_arg = "--force-dpd=30"

            if not self._ensure_tun_available():
                return (
                    False,
                    "TUN device unavailable: could not open /dev/net/tun",
                    0,
                )

            if protocol == 'gp' and 'prelogin-cookie' in cookies:
                cookie_str = cookies.get('prelogin-cookie', '')
                gp_env = os.environ.copy()
                if gp_os_version:
                    gp_env["MS_SSO_GP_OS_VERSION"] = gp_os_version
                else:
                    gp_env.setdefault("MS_SSO_GP_OS_VERSION", get_gp_os_version())
                gp_hip_wrapper = get_gp_hip_report_wrapper()
                log.debug(f"Using GlobalProtect prelogin-cookie (len={len(cookie_str)})")
                cmd = [
                    openconnect_bin,
                    "--verbose",
                    f"--protocol={proto_flag}",
                    reconnect_arg,
                    dpd_arg,
                    "--passwd-on-stdin",
                    "--useragent=PAN GlobalProtect",
                    "--usergroup=portal:prelogin-cookie",
                    "--os=linux-64",
                    gateway,
                ]
                if gp_hip_wrapper:
                    cmd.insert(-1, f"--csd-wrapper={gp_hip_wrapper}")
                    log.info(
                        "Using GlobalProtect HIP wrapper: "
                        f"{gp_hip_wrapper} (OS={gp_env.get('MS_SSO_GP_OS_VERSION')})"
                    )
                if resolve_arg:
                    cmd.insert(3, resolve_arg)
                # Add username if available (required for GlobalProtect)
                if username:
                    cmd.insert(7 if resolve_arg else 6, f"--user={username}")
                self.vpn_process = subprocess.Popen(
                    cmd,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    env=gp_env,
                )
                vpn_process = self.vpn_process
                self.vpn_process_generation = connect_generation
                vpn_process.stdin.write(f"{cookie_str}\n".encode())
                vpn_process.stdin.flush()
            else:
                cookie_str = "; ".join([f"{k}={v}" for k, v in cookies.items()])
                log.debug(f"Using AnyConnect cookie (len={len(cookie_str)})")
                # Log first/last parts of cookie for debugging (without revealing sensitive parts)
                if len(cookie_str) > 40:
                    log.debug(f"Cookie preview: {cookie_str[:20]}...{cookie_str[-20:]}")
                cmd = [
                    openconnect_bin,
                    "--verbose",
                    f"--protocol={proto_flag}",
                    reconnect_arg,
                    dpd_arg,
                    f"--cookie={cookie_str}",
                    gateway,
                ]
                if resolve_arg:
                    cmd.insert(3, resolve_arg)
                log.debug(
                    f"OpenConnect command: {openconnect_bin} --verbose "
                    f"--protocol={proto_flag} --cookie=[redacted] {gateway}"
                )
                # Optional sensitive debug dump; disabled by default.
                if self._is_truthy(os.environ.get("MS_SSO_NM_DEBUG_DUMP_COOKIES")):
                    try:
                        with open('/tmp/nm-vpn-debug-cmd.txt', 'w') as f:
                            f.write(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                            f.write(f"Cookie string length: {len(cookie_str)}\n")
                            f.write(f"Cookie keys: {list(cookies.keys())}\n")
                            f.write(f"Cookie string: {cookie_str}\n")
                    except Exception:
                        pass
                self.vpn_process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT
                )
                vpn_process = self.vpn_process
                self.vpn_process_generation = connect_generation

            log.info(f"OpenConnect started (PID {vpn_process.pid})")
            if openconnect_bin != "openconnect":
                log.info(f"Using protocol-specific OpenConnect binary: {openconnect_bin}")
            if resolve_arg:
                log.info(f"Using {resolve_arg} for OpenConnect reconnects")

            # Initialize DNS server list
            self.vpn_dns_servers = []
            self.vpn_domains = []
            self.vpn_tunnel_all_dns = None
            self.vpn_split_excludes = []
            self.vpn_split_includes = []

            # Monitor for interface up and parse output for DNS
            # Wait for tun interface to come up
            timeout = self._get_tunnel_connect_timeout_seconds(protocol)
            log.info(f"Waiting up to {timeout}s for tunnel interface")
            start_time = time.time()
            connected = False
            output_buffer = ""
            openconnect_reported_up = False
            baseline_tun_devs = self._list_tun_devices()

            # Set stdout to non-blocking so we can read while checking interface
            import fcntl
            import os as os_module
            fd = vpn_process.stdout.fileno()
            fl = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, fl | os_module.O_NONBLOCK)

            while time.time() - start_time < timeout:
                if self._is_connect_cancelled(connect_generation):
                    self._stop_vpn_process(
                        preserve_session=True,
                        force=True,
                        process=vpn_process,
                        connect_generation=connect_generation,
                    )
                    return (False, "Connect cancelled", 0)
                if vpn_process.poll() is not None:
                    # Process exited - read remaining output
                    try:
                        remaining = vpn_process.stdout.read()
                        if remaining:
                            output_buffer += remaining.decode('utf-8', errors='replace')
                    except:
                        pass
                    exit_code = vpn_process.returncode
                    log.error(f"OpenConnect exited prematurely with code {exit_code}")
                    log.error(f"OpenConnect output:\n{output_buffer}")
                    raise Exception(f"OpenConnect exited (code {exit_code}): {output_buffer[-500:]}")

                # Try to read any available output (non-blocking)
                output_buffer, openconnect_reported_up = self._consume_vpn_stdout(
                    output_buffer,
                    openconnect_reported_up,
                    process=vpn_process,
                )

                # Check tunnel interfaces. For AnyConnect, require an OpenConnect
                # "session up" marker so we don't falsely bind to stale tun devices.
                tun_devs_now = self._list_tun_devices()
                candidate_tun = None
                new_tun_devs = sorted(tun_devs_now - baseline_tun_devs)
                if new_tun_devs:
                    candidate_tun = new_tun_devs[0]
                elif self.current_tun_device and self.current_tun_device in tun_devs_now:
                    candidate_tun = self.current_tun_device
                elif openconnect_reported_up and tun_devs_now:
                    candidate_tun = sorted(tun_devs_now)[0]

                if candidate_tun:
                    self.current_tun_device = candidate_tun
                    self.owned_tun_devices.add(candidate_tun)
                    if protocol != 'anyconnect' or openconnect_reported_up:
                        log.info(f"Found tun device: {self.current_tun_device}")
                        connected = True
                        break

                time.sleep(0.5)

            if not connected:
                # Ensure failed/timeout attempts do not leave a stray OpenConnect
                # process or DNS state behind.
                try:
                    if vpn_process and vpn_process.poll() is None:
                        self._stop_vpn_process(
                            preserve_session=True,
                            force=True,
                            process=vpn_process,
                            connect_generation=connect_generation,
                        )
                except Exception:
                    pass
                self._cleanup_dns()

                # Check if it's a cookie rejection
                if 'cookie' in output_buffer.lower() and ('reject' in output_buffer.lower() or 'invalid' in output_buffer.lower() or 'fail' in output_buffer.lower()):
                    return (False, "Cookie rejected by server", 0)
                return (False, f"VPN connection timeout after {timeout}s", 0)

            # A tun device alone is not enough. Cached AnyConnect cookies can
            # sometimes produce a half-up tunnel that leaves DNS/routes slow or
            # broken. Only report STARTED after IPv4 config exists, and require
            # cached-cookie tunnels to survive a short stability window.
            stable_seconds = self._parse_positive_int(
                os.environ.get("MS_SSO_NM_ANYCONNECT_CACHE_STABLE_SECONDS"),
                3 if protocol == 'anyconnect' and used_cache else 0,
            )
            usable, unusable_reason, ip_addr, prefix = self._wait_for_usable_tunnel(
                protocol,
                self.current_tun_device,
                connect_generation,
                min_stable_seconds=stable_seconds,
                process=vpn_process,
            )
            if not usable:
                log.warning(f"VPN tunnel is not usable: {unusable_reason}")
                try:
                    if vpn_process and vpn_process.poll() is None:
                        self._stop_vpn_process(
                            preserve_session=True,
                            force=True,
                            process=vpn_process,
                            connect_generation=connect_generation,
                        )
                except Exception:
                    pass
                self._cleanup_dns()
                if protocol == 'anyconnect' and used_cache:
                    return (False, "Cached cookie produced an unusable tunnel", 0)
                return (False, unusable_reason or "VPN tunnel is not usable", 0)

            log.info(f"Validated tunnel {self.current_tun_device}: {ip_addr}/{prefix}")

            log.info(f"VPN DNS servers captured: {self.vpn_dns_servers}")

            # Emit full IP config now that interface is up
            GLib.idle_add(self._emit_connected)
            if protocol == 'anyconnect' and self.vpn_dns_servers:
                dns_probe_timeout = self._parse_positive_int(
                    os.environ.get("MS_SSO_NM_ANYCONNECT_DNS_PROBE_AFTER_CONFIG_SECONDS"),
                    0,
                )
                if dns_probe_timeout > 0 and not self._wait_for_vpn_dns_usable(
                    connect_generation,
                    timeout_seconds=dns_probe_timeout,
                    process=vpn_process,
                ):
                    log.warning(
                        "VPN tunnel DNS did not become usable after NetworkManager config; "
                        "continuing with tunnel up to avoid reconnect/TOTP loop"
                    )

            # Watchdog loop: keep an eye on process and tunnel device.
            connected_at = time.monotonic()
            missing_tun_checks = 0
            watch_interval = max(1, int(watchdog_interval_seconds))
            tun_miss_limit = max(1, int(watchdog_missing_tun_limit))
            gateway_probe_timeout = max(1, self._parse_positive_int(
                os.environ.get("MS_SSO_NM_GATEWAY_PROBE_TIMEOUT_SECONDS"),
                3,
            ))
            gateway_probe_fail_limit = max(1, self._parse_positive_int(
                os.environ.get("MS_SSO_NM_GATEWAY_PROBE_FAIL_LIMIT"),
                3,
            ))
            gateway_probe_enabled = self._parse_bool(
                os.environ.get(
                    "MS_SSO_NM_ANYCONNECT_GATEWAY_PROBE"
                    if protocol == 'anyconnect'
                    else "MS_SSO_NM_GP_GATEWAY_PROBE"
                )
            )
            if gateway_probe_enabled is None:
                gateway_probe_enabled = self._parse_bool(
                    os.environ.get("MS_SSO_NM_GATEWAY_PROBE")
                )
            if gateway_probe_enabled is None:
                gateway_probe_enabled = protocol != 'anyconnect'
            log.info(
                "Gateway probe watchdog: "
                f"{'enabled' if gateway_probe_enabled else 'disabled'} "
                f"(timeout={gateway_probe_timeout}s, fail-limit={gateway_probe_fail_limit})"
            )
            gateway_probe_failures = 0
            while vpn_process.poll() is None:
                if self._is_connect_cancelled(connect_generation):
                    break
                output_buffer, openconnect_reported_up = self._consume_vpn_stdout(
                    output_buffer,
                    openconnect_reported_up,
                    process=vpn_process,
                )
                tun_dev = self.current_tun_device
                if tun_dev:
                    check = subprocess.run(
                        ["ip", "link", "show", tun_dev],
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    if check.returncode != 0:
                        missing_tun_checks += 1
                        log.warning(
                            "Watchdog: missing tunnel device "
                            f"{tun_dev} ({missing_tun_checks}/{tun_miss_limit})"
                        )
                        if missing_tun_checks >= tun_miss_limit:
                            log.warning("Watchdog: tunnel device vanished; restarting connection")
                            try:
                                self._stop_vpn_process(
                                    preserve_session=True,
                                    force=True,
                                    process=vpn_process,
                                    connect_generation=connect_generation,
                                )
                            except Exception:
                                pass
                            break
                    else:
                        missing_tun_checks = 0

                if gateway_probe_enabled:
                    if self._probe_gateway(timeout_seconds=float(gateway_probe_timeout)):
                        gateway_probe_failures = 0
                    else:
                        gateway_probe_failures += 1
                        log.warning(
                            "Watchdog: gateway probe failed "
                            f"({gateway_probe_failures}/{gateway_probe_fail_limit})"
                        )
                        if gateway_probe_failures >= gateway_probe_fail_limit:
                            log.warning("Watchdog: uplink to VPN gateway appears down; restarting connection")
                            try:
                                self._stop_vpn_process(
                                    preserve_session=True,
                                    force=True,
                                    process=vpn_process,
                                    connect_generation=connect_generation,
                                )
                            except Exception:
                                pass
                            break
                time.sleep(watch_interval)

            # Wait for process to fully exit and report uptime
            try:
                output_buffer, openconnect_reported_up = self._consume_vpn_stdout(
                    output_buffer,
                    openconnect_reported_up,
                    process=vpn_process,
                )
                exit_code = vpn_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                exit_code = vpn_process.poll()
                if exit_code is None:
                    log.warning("Watchdog: OpenConnect did not exit in time; forcing kill")
                    try:
                        self._stop_vpn_process(
                            preserve_session=True,
                            force=True,
                            process=vpn_process,
                            connect_generation=connect_generation,
                        )
                    except Exception:
                        pass
                    try:
                        exit_code = vpn_process.wait(timeout=5)
                    except Exception:
                        exit_code = vpn_process.poll()
            uptime_seconds = int(max(0, time.monotonic() - connected_at))
            if exit_code not in (0, None) and not self._is_connect_cancelled(connect_generation):
                log.warning(f"OpenConnect exited with code {exit_code} after {uptime_seconds}s")

            return (True, None, uptime_seconds)

        except Exception as e:
            error_msg = str(e)
            log.info(f"Attempt error: {error_msg}")
            try:
                if 'vpn_process' in locals() and vpn_process and vpn_process.poll() is None:
                    self._stop_vpn_process(
                        preserve_session=True,
                        force=True,
                        process=vpn_process,
                        connect_generation=connect_generation,
                    )
            except Exception:
                pass
            self._cleanup_dns()
            # Check if it's a cookie rejection error
            if 'cookie' in error_msg.lower() and ('reject' in error_msg.lower() or 'invalid' in error_msg.lower()):
                return (False, "Cookie rejected by server", 0)
            return (False, error_msg, 0)

    def _emit_initial_config(self):
        """Emit initial Config signal before interface is created (called from main thread).

        Note: We DON'T include tundev here because NetworkManager will try to look it up
        immediately and fail if it doesn't exist yet.
        """
        try:
            if self.current_protocol not in {'gp', 'anyconnect'}:
                log.info(
                    "Skipping pre-tunnel initial Config for "
                    f"{self.current_protocol or 'unknown'}; waiting for real tunnel"
                )
                return False
            if not self._auth_initial_config_allowed(self.current_protocol or ''):
                return False

            gateway = self.current_gateway or ''

            log.info(f"Emitting initial config (no tundev), gateway {gateway}")

            # Use pre-resolved gateway IP (resolved before VPN connected, when external DNS was available)
            gateway_ip = getattr(self, 'current_gateway_ip', None)
            if not gateway_ip and gateway:
                try:
                    from urllib.parse import urlparse
                    parsed = urlparse(gateway if "://" in gateway else f"//{gateway}")
                    lookup = parsed.hostname or gateway
                    gateway_ip = socket.gethostbyname(lookup)
                    self.current_gateway_ip = gateway_ip
                    log.info(f"Late-resolved gateway {lookup} -> {gateway_ip}")
                except Exception as e:
                    log.warning(f"Late gateway resolve failed for {gateway}: {e}")
            if gateway_ip:
                log.info(f"Using pre-resolved gateway IP: {gateway_ip}")
            else:
                log.warning(f"No pre-resolved gateway IP available, gateway uint will be 0")

            # NetworkManager VPN config uses host-order uint32 for IPv4 values.
            gateway_uint = 0
            if gateway_ip:
                try:
                    gateway_uint = self._ipv4_to_nm_uint32(gateway_ip)
                    log.info(f"Gateway host-order uint32: {gateway_uint} (0x{gateway_uint:08x})")
                except Exception as e:
                    log.info(f"Warning: Could not convert gateway IP '{gateway_ip}': {e}")

            # Emit Config signal WITHOUT tundev - just gateway info.
            # Do not emit gateway=0: NetworkManager treats it as invalid config.
            if gateway_uint == 0:
                log.warning("Skipping initial Config emission until gateway IP is known")
                return False

            # tundev and has-ip4 are only advertised in the full Config after the
            # tunnel is up. Claiming IPv4 here can leave stale VPN routing state
            # behind when reconnect/auth attempts fail.
            has_ip4 = False
            config = dbus.Dictionary({
                'gateway': dbus.UInt32(gateway_uint),
                'has-ip4': dbus.Boolean(has_ip4),
                'has-ip6': dbus.Boolean(False),
            }, signature='sv')
            self.Config(config)
            log.info(f"Emitted initial Config signal (gateway only)")

        except Exception as e:
            log.info(f"Error emitting initial config: {e}")
            import traceback
            traceback.print_exc()

        return False

    def _auth_initial_config_allowed(self, protocol: str) -> bool:
        """Return True when slow SAML auth may emit gateway-only Config."""
        if protocol == 'gp':
            return self._gp_initial_config_allowed()
        if protocol == 'anyconnect':
            return self._anyconnect_initial_config_allowed()
        return False

    def _initial_config_delay_elapsed(self, protocol_label: str, env_name: str, default_seconds: int) -> bool:
        """Return True when delayed gateway-only Config may be emitted."""
        delay_env = os.environ.get(env_name, "").strip()
        try:
            delay_seconds = int(delay_env) if delay_env else default_seconds
        except Exception:
            delay_seconds = default_seconds
        if delay_seconds < 0:
            delay_seconds = default_seconds

        start_time = None
        if getattr(self, "auth_in_progress", False) and getattr(self, "saml_start_time", None):
            start_time = self.saml_start_time
        elif protocol_label == "GP" and getattr(self, "gp_connect_start_time", None):
            start_time = self.gp_connect_start_time
        if not start_time:
            return False

        elapsed = time.monotonic() - start_time
        if elapsed < delay_seconds:
            log.info(
                f"Skipping initial Config for {protocol_label} to keep UI in connecting state "
                f"(elapsed {elapsed:.0f}s < {delay_seconds}s)"
            )
            return False
        return True

    def _gp_initial_config_allowed(self) -> bool:
        """Return True if GP initial Config may be emitted (delay elapsed or explicitly allowed)."""
        allow_early = os.environ.get("MS_SSO_NM_GP_EARLY_CONFIG", "").lower() in {"1", "true", "yes"}
        if allow_early:
            return True
        # Default below NetworkManager's observed connect timeout window.
        return self._initial_config_delay_elapsed("GP", "MS_SSO_NM_GP_CONFIG_DELAY", 20)

    def _anyconnect_initial_config_allowed(self) -> bool:
        """Return True if AnyConnect gateway-only Config may be emitted during slow auth."""
        allow_early = os.environ.get("MS_SSO_NM_ANYCONNECT_EARLY_CONFIG", "").lower() in {"1", "true", "yes"}
        if allow_early:
            return True
        # This emits no tundev and has-ip4=false, so it keeps NM alive without
        # installing tunnel DNS/routes before OpenConnect creates the interface.
        return self._initial_config_delay_elapsed(
            "AnyConnect",
            "MS_SSO_NM_ANYCONNECT_CONFIG_DELAY",
            30,
        )

    def _get_auth_started_guard_seconds(self, protocol: str) -> int:
        """Return seconds after which we emit STARTED keepalive during slow auth."""
        env_candidates = []
        if protocol == 'anyconnect':
            env_candidates.append("MS_SSO_NM_ANYCONNECT_AUTH_TIMEOUT_GUARD_SEC")
        if protocol == 'gp':
            env_candidates.append("MS_SSO_NM_GP_AUTH_TIMEOUT_GUARD_SEC")
        env_candidates.append("MS_SSO_NM_AUTH_TIMEOUT_GUARD_SEC")

        for env_name in env_candidates:
            value = os.environ.get(env_name, "").strip()
            if not value:
                continue
            try:
                parsed = int(value)
                if parsed >= 0:
                    return parsed
            except Exception:
                log.warning(f"Ignoring invalid {env_name} value: {value!r}")

        if protocol == 'anyconnect':
            # FHNW SAML/TOTP often takes longer than NetworkManager's observed
            # ~60s activation timeout. Emit STARTED shortly before that without
            # pre-tunnel Config, so NM keeps waiting but gets no stale IP/DNS.
            return 45
        return 45

    def _should_emit_started_keepalive(self, protocol: str) -> bool:
        """Return True when we should send STARTED keepalive to avoid NM timeout."""
        if protocol == 'gp' and self._gp_early_started_enabled():
            return True

        if not getattr(self, "auth_in_progress", False):
            return False
        if not getattr(self, "saml_start_time", None):
            return False

        guard_seconds = self._get_auth_started_guard_seconds(protocol)
        if guard_seconds <= 0:
            return False

        elapsed = time.monotonic() - self.saml_start_time
        if elapsed < guard_seconds:
            return False

        if not self._auth_started_guard_triggered:
            self._auth_started_guard_triggered = True
            log.info(
                f"Auth timeout guard active after {elapsed:.0f}s (threshold {guard_seconds}s): "
                "emitting STARTED keepalive to avoid NetworkManager connect timeout"
            )
        return True

    def _clear_onlink_host_route(self, gateway_ip: str) -> None:
        """Remove a bogus on-link /32 host route to the VPN gateway if present."""
        try:
            ip_obj = ipaddress.ip_address(gateway_ip)
            if ip_obj.version != 4:
                return
        except Exception:
            return

        # Don't touch routes if the gateway is within a local interface subnet.
        try:
            addr_out = subprocess.run(
                ["ip", "-4", "addr", "show"],
                capture_output=True,
                text=True,
                check=False,
            ).stdout
            for line in addr_out.splitlines():
                line = line.strip()
                if not line.startswith("inet "):
                    continue
                parts = line.split()
                if len(parts) < 2:
                    continue
                cidr = parts[1]
                try:
                    network = ipaddress.ip_network(cidr, strict=False)
                    if ip_obj in network:
                        return
                except Exception:
                    continue
        except Exception:
            pass

        try:
            routes = subprocess.run(
                ["ip", "route", "show", gateway_ip],
                capture_output=True,
                text=True,
                check=False,
            ).stdout.splitlines()
        except Exception:
            return

        for line in routes:
            if "scope link" not in line or " via " in line:
                continue
            parts = line.split()
            if "dev" not in parts:
                continue
            dev = parts[parts.index("dev") + 1]
            log.warning(f"Removing on-link host route to {gateway_ip} dev {dev}")
            try:
                subprocess.run(
                    ["ip", "route", "del", f"{gateway_ip}/32", "dev", dev],
                    capture_output=True,
                    text=True,
                    check=False,
                )
            except Exception as e:
                log.warning(f"Failed to delete on-link host route: {e}")

    def _apply_ipv6_leak_protection(self) -> None:
        """Block local IPv6 egress while this IPv4-only VPN is active."""
        if self.ipv6_leak_protection_enabled:
            return
        if not self._is_truthy(os.environ.get("MS_SSO_NM_BLOCK_IPV6", "1")):
            return

        try:
            result = subprocess.run(
                ["ip", "-6", "route", "replace", "unreachable", "::/0", "metric", "50"],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode == 0:
                self.ipv6_leak_protection_enabled = True
                log.info("Enabled IPv6 leak protection with unreachable default route")
            else:
                log.warning(
                    "Failed to enable IPv6 leak protection: "
                    f"{(result.stderr or result.stdout).strip()}"
                )
        except Exception as e:
            log.warning(f"Failed to enable IPv6 leak protection: {e}")

    def _remove_ipv6_leak_protection(self) -> None:
        """Remove the temporary IPv6 block route added for VPN leak protection."""
        if not self.ipv6_leak_protection_enabled:
            return
        try:
            subprocess.run(
                ["ip", "-6", "route", "del", "unreachable", "::/0", "metric", "50"],
                capture_output=True,
                text=True,
                check=False,
            )
        except Exception as e:
            log.warning(f"Failed to remove IPv6 leak protection: {e}")
        finally:
            self.ipv6_leak_protection_enabled = False

    def _emit_starting_keepalive(self):
        """Emit a keepalive STARTING state to reduce NM connect timeouts."""
        try:
            # Intentionally emit even if our internal state didn't change.
            self.StateChanged(NM_VPN_SERVICE_STATE_STARTING)
        except Exception:
            pass
        return False

    def _emit_started_for_auth(self):
        """Enter STARTED while authentication is still in progress.

        NetworkManager may cancel VPN connections that stay in STARTING too long.
        This is common for GlobalProtect SAML flows with MFA. We later emit the
        full Config/Ip4Config once the tunnel device exists.
        """
        try:
            self._set_state(NM_VPN_SERVICE_STATE_STARTED)
        except Exception:
            pass
        return False

    def _emit_started_keepalive(self):
        """Emit a keepalive STARTED state."""
        try:
            # Keep local property state consistent with emitted signal.
            if self.state != NM_VPN_SERVICE_STATE_STARTED:
                self._set_state(NM_VPN_SERVICE_STATE_STARTED)
            else:
                self.StateChanged(NM_VPN_SERVICE_STATE_STARTED)
        except Exception:
            pass
        return False

    def _emit_connected(self):
        """Emit IP config after interface is up (called from main thread)."""
        import struct

        try:
            # Get IP configuration from tun device
            tun_dev = self.current_tun_device or 'tun0'
            gateway = self.current_gateway or ''

            log.info(f"Emitting config for {tun_dev}, gateway {gateway}")

            # Get IP address from interface
            ip_addr, prefix = self._get_tun_ipv4_config(tun_dev)
            log.info(f"Detected IP: {ip_addr}/{prefix}")
            if not ip_addr:
                log.warning(f"Refusing to emit connected state for {tun_dev}: no IPv4 address")
                try:
                    if self.vpn_process and self.vpn_process.poll() is None:
                        self._stop_vpn_process(preserve_session=True, force=True)
                except Exception:
                    pass
                self._cleanup_dns()
                self._set_state(NM_VPN_SERVICE_STATE_STARTING)
                return False

            # Use pre-resolved gateway IP (resolved before VPN connected, when external DNS was available)
            gateway_ip = getattr(self, 'current_gateway_ip', None)
            if gateway_ip:
                log.info(f"Using pre-resolved gateway IP: {gateway_ip}")
            else:
                log.warning(f"No pre-resolved gateway IP available, gateway uint will be 0")

            # NetworkManager VPN config uses host-order uint32 for IPv4 values.
            gateway_uint = 0
            if gateway_ip:
                try:
                    gateway_uint = self._ipv4_to_nm_uint32(gateway_ip)
                    log.info(f"Gateway host-order uint32: {gateway_uint} (0x{gateway_uint:08x})")
                except Exception as e:
                    log.info(f"Warning: Could not convert gateway IP '{gateway_ip}': {e}")

            if gateway_uint == 0:
                log.info(f"ERROR: Gateway is 0, NetworkManager will reject this!")

            # Emit Config signal with tunnel device info
            # gateway must be uint32 in NetworkManager host order
            config = dbus.Dictionary({
                'tundev': dbus.String(tun_dev),
                'gateway': dbus.UInt32(gateway_uint),
                'has-ip4': dbus.Boolean(True),
                'has-ip6': dbus.Boolean(False),
            }, signature='sv')
            self.Config(config)
            log.info(f"Emitted Config signal")

            # Emit Ip4Config signal with proper format
            # NetworkManager expects 'addresses' as array of arrays: [[addr, prefix, gateway], ...]
            if ip_addr:
                # Convert IP to uint32 (network byte order)
                ip_parts = [int(x) for x in ip_addr.split('.')]
                ip_uint = struct.unpack('!I', bytes(ip_parts))[0]

                # Get DNS servers - try multiple methods
                dns_server_ips = []

                # Method 1: Try resolvectl for systemd-resolved systems
                try:
                    result = subprocess.run(
                        ['resolvectl', 'dns', tun_dev],
                        capture_output=True, text=True, timeout=5
                    )
                    if result.returncode == 0:
                        # Parse output like "Link 123 (tun0): 10.0.0.1 10.0.0.2"
                        for line in result.stdout.split('\n'):
                            if tun_dev in line:
                                parts = line.split(':')
                                if len(parts) >= 2:
                                    dns_part = parts[1].strip()
                                    for ns in dns_part.split():
                                        try:
                                            ns_parts = [int(x) for x in ns.split('.')]
                                            if len(ns_parts) == 4:
                                                # Convert IP to uint32 in host byte order (little-endian on x86)
                                                # IP a.b.c.d becomes: a + b*256 + c*65536 + d*16777216
                                                ns_uint = ns_parts[0] | (ns_parts[1] << 8) | (ns_parts[2] << 16) | (ns_parts[3] << 24)
                                                dns_server_ips.append(ns)
                                                log.info(f"Found DNS from resolvectl: {ns} -> {ns_uint}")
                                        except:
                                            pass
                except Exception as e:
                    log.info(f"resolvectl failed: {e}")

                # Method 2: If no DNS yet, check stored DNS from OpenConnect output
                if not dns_server_ips and hasattr(self, 'vpn_dns_servers') and self.vpn_dns_servers:
                    for ns in self.vpn_dns_servers:
                        try:
                            ns_parts = [int(x) for x in ns.split('.')]
                            if len(ns_parts) == 4:
                                # Convert IP to uint32 in host byte order (little-endian on x86)
                                ns_uint = ns_parts[0] | (ns_parts[1] << 8) | (ns_parts[2] << 16) | (ns_parts[3] << 24)
                                dns_server_ips.append(ns)
                                log.info(f"Using stored VPN DNS: {ns} -> {ns_uint}")
                        except:
                            pass

                # Method 3: Fall back to resolv.conf
                if not dns_server_ips:
                    try:
                        result = subprocess.run(['cat', '/etc/resolv.conf'], capture_output=True, text=True)
                        for line in result.stdout.split('\n'):
                            if line.startswith('nameserver '):
                                ns = line.split()[1]
                                try:
                                    ns_parts = [int(x) for x in ns.split('.')]
                                    if len(ns_parts) == 4:
                                        # Convert IP to uint32 in host byte order (little-endian on x86)
                                        ns_uint = ns_parts[0] | (ns_parts[1] << 8) | (ns_parts[2] << 16) | (ns_parts[3] << 24)
                                        dns_server_ips.append(ns)
                                        log.info(f"Found DNS from resolv.conf: {ns} -> {ns_uint}")
                                except:
                                    pass  # Skip non-IPv4 nameservers
                    except:
                        pass

                dns_server_ips = self._normalize_dns_servers(dns_server_ips)
                dns_domains = self._normalize_vpn_domains()
                if dns_domains:
                    log.info(f"VPN DNS domains for NetworkManager: {dns_domains}")
                if self.current_protocol == 'anyconnect' and not self.vpn_tunnel_all_dns:
                    if self._anyconnect_preserve_default_route():
                        log.info(
                            "AnyConnect split-exclude/full-tunnel routing active; "
                            "keeping VPN DNS available for global lookups"
                        )
                    else:
                        log.info("AnyConnect split-DNS mode active; avoiding VPN as global DNS/default route")
                dns_servers = []
                for ns in dns_server_ips:
                    ns_parts = [int(x) for x in ns.split('.')]
                    ns_uint = ns_parts[0] | (ns_parts[1] << 8) | (ns_parts[2] << 16) | (ns_parts[3] << 24)
                    dns_servers.append(dbus.UInt32(ns_uint))
                log.info(f"Total DNS servers found: {len(dns_servers)}")

                # Build addresses array: each address is [addr, prefix, gateway]
                # For point-to-point VPN, gateway in address is typically 0
                addr_array = dbus.Array([
                    dbus.Array([dbus.UInt32(ip_uint), dbus.UInt32(prefix), dbus.UInt32(0)], signature='u')
                ], signature='au')

                # Build routes array: empty since OpenConnect handles routes via vpnc-script
                routes_array = dbus.Array([], signature='au')

                ip4_config = dbus.Dictionary({
                    'addresses': addr_array,
                    'routes': routes_array,
                    'dns': dbus.Array(dns_servers, signature='u') if dns_servers else dbus.Array([], signature='u'),
                    'domains': dbus.Array(dns_domains, signature='s'),
                }, signature='sv')
                if self.current_protocol == 'anyconnect' and not self._anyconnect_preserve_default_route():
                    ip4_config['never-default'] = dbus.Boolean(True)
                self.Ip4Config(ip4_config)
                log.info(
                    f"Emitted Ip4Config signal: addr={ip_addr}/{prefix}, "
                    f"dns={len(dns_servers)} servers, domains={dns_domains}"
                )
                if self.current_protocol == 'anyconnect' and not self.vpn_tunnel_all_dns:
                    GLib.timeout_add_seconds(1, self._apply_split_dns_resolved, tun_dev, dns_domains)
                    GLib.timeout_add_seconds(3, self._apply_split_dns_resolved, tun_dev, dns_domains)

            self._apply_ipv6_leak_protection()

            # Now set state to started
            self._set_state(NM_VPN_SERVICE_STATE_STARTED)
        except Exception as e:
            log.info(f"Error emitting config: {e}")
            import traceback
            traceback.print_exc()
            self._set_state(NM_VPN_SERVICE_STATE_STARTED)

        return False

    def _emit_disconnected(self):
        """Emit disconnected state (called from main thread)."""
        self._cleanup_dns()
        self._set_state(NM_VPN_SERVICE_STATE_STOPPED)
        return False

    def _emit_failure(self, message):
        """Emit failure (called from main thread)."""
        self._cleanup_dns()
        self.Failure(NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED)
        self._set_state(NM_VPN_SERVICE_STATE_STOPPED)
        return False

    def _cleanup_leaked_vpn_dns_links(self):
        """Remove VPN DNS accidentally attached to non-tunnel links."""
        if not shutil.which("resolvectl"):
            return

        vpn_dns = set(self._normalize_dns_servers(getattr(self, "vpn_dns_servers", [])))
        vpn_domains = set(self._normalize_vpn_domains())
        if not vpn_dns and not vpn_domains:
            return

        try:
            result = subprocess.run(
                ["resolvectl", "status"],
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )
        except Exception as e:
            log.info(f"Could not inspect resolved links for DNS cleanup: {e}")
            return

        current_name = None
        current_lines = []

        def flush_current():
            if not current_name or current_name.startswith(("tun", "tap")):
                return
            body = "\n".join(current_lines)
            has_vpn_dns = any(server in body for server in vpn_dns)
            has_vpn_domain = any(domain in body for domain in vpn_domains)
            if not has_vpn_dns and not has_vpn_domain:
                return
            try:
                subprocess.run(
                    ["resolvectl", "revert", current_name],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=5,
                )
                log.info(f"Reverted leaked VPN DNS settings from {current_name}")
            except Exception as e:
                log.info(f"Leaked DNS cleanup failed for {current_name}: {e}")

        for line in result.stdout.splitlines():
            match = re.match(r"\s*Link\s+\d+\s+\(([^)]+)\)", line)
            if match:
                flush_current()
                current_name = match.group(1)
                current_lines = [line]
            elif current_name:
                current_lines.append(line)
        flush_current()

    def _cleanup_dns(self):
        """Attempt to clear DNS settings left behind on disconnect/failure."""
        self._remove_ipv6_leak_protection()
        self._cleanup_leaked_vpn_dns_links()
        self._cleanup_anyconnect_physical_routes()

        tun_devs = set()
        if self.current_tun_device:
            tun_devs.add(self.current_tun_device)
        tun_devs.update(self.owned_tun_devices)

        # Best effort: add currently present tunnel interfaces so DNS gets
        # reverted even when we missed current_tun_device tracking.
        if not tun_devs:
            tun_devs.update(self._list_tun_devices())

        # Fallback when we can't enumerate: try tun0 at minimum.
        if not tun_devs:
            tun_devs.add("tun0")

        owned_cleanup_devs = set()
        if self.current_tun_device:
            owned_cleanup_devs.add(self.current_tun_device)
        owned_cleanup_devs.update(self.owned_tun_devices)

        for tun_dev in sorted(tun_devs):
            cleaned = False
            if shutil.which("resolvectl"):
                try:
                    subprocess.run(
                        ["resolvectl", "revert", tun_dev],
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    log.info(f"Reverted DNS settings for {tun_dev}")
                    cleaned = True
                except Exception as e:
                    log.info(f"resolvectl revert failed for {tun_dev}: {e}")
            # Fallback: try resolvconf if present
            if not cleaned and shutil.which("resolvconf"):
                try:
                    subprocess.run(
                        ["resolvconf", "-d", tun_dev],
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    log.info(f"Removed resolvconf entry for {tun_dev}")
                except Exception as e:
                    log.info(f"resolvconf cleanup failed for {tun_dev}: {e}")

            if tun_dev not in owned_cleanup_devs:
                continue

            try:
                subprocess.run(
                    ["ip", "route", "flush", "dev", tun_dev],
                    capture_output=True,
                    text=True,
                    check=False,
                )
            except Exception as e:
                log.info(f"Route cleanup failed for {tun_dev}: {e}")

            try:
                subprocess.run(
                    ["ip", "link", "delete", "dev", tun_dev],
                    capture_output=True,
                    text=True,
                    check=False,
                )
            except Exception as e:
                log.info(f"Link cleanup failed for {tun_dev}: {e}")

        # Always clear in-memory DNS/tunnel state, even when no tun device was found.
        self.vpn_dns_servers = []
        self.vpn_domains = []
        self.vpn_tunnel_all_dns = None
        self.vpn_split_excludes = []
        self.vpn_split_includes = []
        self.current_tun_device = None
        self.owned_tun_devices.clear()

    # D-Bus methods
    @dbus.service.method(NM_VPN_DBUS_PLUGIN_INTERFACE,
                         in_signature='a{sa{sv}}', out_signature='')
    def Connect(self, connection):
        """Start VPN connection."""
        log.info("Connect called")
        self._reset_inactivity_timeout()

        # Supersede any previous in-flight connect worker.
        self.cancel_requested = True
        self._connect_generation += 1
        connect_generation = self._connect_generation
        if self.connection_thread and self.connection_thread.is_alive():
            log.warning("Connect called while previous connect thread is still running; superseding old request")

        self._set_state(NM_VPN_SERVICE_STATE_STARTING)

        # Convert D-Bus types to Python
        settings = {str(k): {str(k2): v2 for k2, v2 in v.items()} for k, v in connection.items()}

        # Start connection in background thread
        self.connection_thread = threading.Thread(
            target=self._connect_thread,
            args=(settings, connect_generation),
        )
        self.connection_thread.daemon = True
        self.connection_thread.start()

    @dbus.service.method(NM_VPN_DBUS_PLUGIN_INTERFACE,
                         in_signature='a{sa{sv}}a{sv}', out_signature='')
    def ConnectInteractive(self, connection, details):
        """Start interactive VPN connection."""
        log.info("ConnectInteractive called")
        self.Connect(connection)

    @dbus.service.method(NM_VPN_DBUS_PLUGIN_INTERFACE,
                         in_signature='', out_signature='')
    def Disconnect(self):
        """Disconnect VPN."""
        log.info("Disconnect called")
        self._reset_inactivity_timeout()
        self.cancel_requested = True
        self._connect_generation += 1

        self._set_state(NM_VPN_SERVICE_STATE_STOPPING)

        # Use SIGHUP so openconnect preserves the session cookie but still runs
        # vpnc-script cleanup for routes and DNS.
        if self.vpn_process and self.vpn_process.poll() is None:
            log.info("Stopping openconnect with SIGHUP to preserve session cookie")
            self._stop_vpn_process(preserve_session=True, force=True)

        # Ensure DNS cleanup even if openconnect/vpnc-script left residue behind.
        self._cleanup_dns()

        self._set_state(NM_VPN_SERVICE_STATE_STOPPED)

    @dbus.service.method(NM_VPN_DBUS_PLUGIN_INTERFACE,
                         in_signature='a{sa{sv}}', out_signature='s')
    def NeedSecrets(self, settings):
        """Check if secrets are needed."""
        log.info("NeedSecrets called")
        self._reset_inactivity_timeout()

        # Check if we have secrets
        vpn_settings = settings.get('vpn', {})
        vpn_secrets = vpn_settings.get('secrets', {})

        if not vpn_secrets.get('password'):
            return 'vpn'

        return ''

    @dbus.service.method(NM_VPN_DBUS_PLUGIN_INTERFACE,
                         in_signature='a{sa{sv}}', out_signature='')
    def NewSecrets(self, connection):
        """New secrets provided."""
        log.info("NewSecrets called")
        self._reset_inactivity_timeout()

    @dbus.service.method(NM_VPN_DBUS_PLUGIN_INTERFACE,
                         in_signature='a{sv}', out_signature='')
    def SetConfig(self, config):
        """Set VPN configuration."""
        log.info("SetConfig called")

    @dbus.service.method(NM_VPN_DBUS_PLUGIN_INTERFACE,
                         in_signature='a{sv}', out_signature='')
    def SetIp4Config(self, config):
        """Set IPv4 configuration."""
        log.info("SetIp4Config called")

    @dbus.service.method(NM_VPN_DBUS_PLUGIN_INTERFACE,
                         in_signature='a{sv}', out_signature='')
    def SetIp6Config(self, config):
        """Set IPv6 configuration."""
        log.info("SetIp6Config called")

    @dbus.service.method(NM_VPN_DBUS_PLUGIN_INTERFACE,
                         in_signature='s', out_signature='')
    def SetFailure(self, reason):
        """Set failure reason."""
        log.info(f"SetFailure called: {reason}")

    # D-Bus signals
    @dbus.service.signal(NM_VPN_DBUS_PLUGIN_INTERFACE, signature='u')
    def StateChanged(self, state):
        """Emit state change signal."""
        log.info(f"State changed to {state}")

    @dbus.service.signal(NM_VPN_DBUS_PLUGIN_INTERFACE, signature='a{sv}')
    def Config(self, config):
        """Emit configuration signal."""
        pass

    @dbus.service.signal(NM_VPN_DBUS_PLUGIN_INTERFACE, signature='a{sv}')
    def Ip4Config(self, config):
        """Emit IPv4 configuration signal."""
        pass

    @dbus.service.signal(NM_VPN_DBUS_PLUGIN_INTERFACE, signature='a{sv}')
    def Ip6Config(self, config):
        """Emit IPv6 configuration signal."""
        pass

    @dbus.service.signal(NM_VPN_DBUS_PLUGIN_INTERFACE, signature='u')
    def Failure(self, reason):
        """Emit failure signal."""
        log.info(f"Failure: {reason}")

    @dbus.service.signal(NM_VPN_DBUS_PLUGIN_INTERFACE, signature='s')
    def SecretsRequired(self, message):
        """Emit secrets required signal."""
        pass

    # D-Bus Properties interface implementation
    @dbus.service.method(dbus.PROPERTIES_IFACE, in_signature='ss', out_signature='v')
    def Get(self, interface, prop):
        """Get a property value."""
        if interface == NM_VPN_DBUS_PLUGIN_INTERFACE:
            if prop == 'State':
                return dbus.UInt32(self.state)
        raise dbus.exceptions.DBusException(
            f"org.freedesktop.DBus.Error.UnknownProperty: Property '{prop}' not found")

    @dbus.service.method(dbus.PROPERTIES_IFACE, in_signature='s', out_signature='a{sv}')
    def GetAll(self, interface):
        """Get all properties."""
        if interface == NM_VPN_DBUS_PLUGIN_INTERFACE:
            return {'State': dbus.UInt32(self.state)}
        return {}

    @dbus.service.method(dbus.PROPERTIES_IFACE, in_signature='ssv', out_signature='')
    def Set(self, interface, prop, value):
        """Set a property value."""
        # All properties are read-only
        raise dbus.exceptions.DBusException(
            f"org.freedesktop.DBus.Error.PropertyReadOnly: Property '{prop}' is read-only")

    def run(self, mainloop):
        """Run the service main loop."""
        self.mainloop = mainloop
        # Plugin starts in INIT state (already set in __init__)
        # NetworkManager will call Connect() or NeedSecrets() when ready
        mainloop.run()


def main():
    """Main entry point."""
    log.info("Starting VPN plugin service")

    # Set up D-Bus main loop
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)

    # Get system bus
    try:
        bus = dbus.SystemBus()
    except dbus.exceptions.DBusException as e:
        log.info(f"Failed to connect to system bus: {e}")
        sys.exit(1)

    # Create and run service
    service = VPNPluginService(bus)

    # Set up signal handlers
    mainloop = GLib.MainLoop()

    def signal_handler(signum, frame):
        log.info(f"Received signal {signum}, shutting down")
        service.Disconnect()
        mainloop.quit()

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    try:
        service.run(mainloop)
    except KeyboardInterrupt:
        pass

    log.info("Service stopped")


if __name__ == '__main__':
    main()
