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

import fcntl
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
    SamlUiStalledError,
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

# A completed VPN activation must be torn down by NetworkManager before the
# plugin repairs or validates the base network.  In particular, trying to move
# an activation from STARTED back to STARTING leaves NetworkManager's DNS state
# pointing at the old tunnel ifindex after OpenConnect has removed it.
NETWORK_RECOVERY_INITIAL_DELAY_MS = 750
NETWORK_RECOVERY_TIMEOUT_SECONDS = 15
GP_GATEWAY_ROUTE_STABILIZATION_DELAYS = (0.0, 0.2, 0.5, 1.0, 1.5)
ANYCONNECT_STRUCTURAL_READY_GRACE_SECONDS = 1.0
IPV6_LEAK_ROUTE_METRIC = "42760"
IPV6_LEAK_ROUTE_PROTOCOL = "186"
IPV6_LEAK_ROUTE_MARKER = Path(
    "/run/network-manager-ms-sso/ipv6-leak-route"
)
OPENCONNECT_STATE_FILE = Path(
    "/run/network-manager-ms-sso/openconnect.state"
)
PHYSICAL_UPLINK_TYPES = {
    "ethernet",
    "wifi",
    "gsm",
    "cdma",
    "bridge",
    "bond",
    "team",
    "vlan",
    "infiniband",
}


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
        self.current_connection_uuid = None
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
        self.owned_tun_ifindices = {}
        self.preexisting_tun_devices = set()
        self.ipv6_leak_protection_enabled = False
        # NetworkManager-owned uplinks captured before the VPN changes routing
        # or DNS.  They are reapplied only when post-disconnect health checks
        # show that the base network did not recover on its own.
        self.pre_vpn_uplinks = {}
        self.pre_vpn_dns_default_uplinks = set()
        self.pre_vpn_dns_state_captured = False
        self._uplinks_needing_reapply = set()
        self._network_recovery_token = 0
        self._network_recovery_deadline = 0.0
        self._network_recovery_reload_attempted = False
        self._network_recovery_thread = None
        self._cleanup_lock = threading.RLock()
        # Track GP connection timing so we can delay initial Config/UI state.
        self.gp_connect_start_time = None
        self.auth_in_progress = False
        self.auth_generation = None
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

        # If an older service instance was killed, its child can outlive the
        # D-Bus owner.  Recover the exact persisted PID/start-time ownership
        # before accepting another VPN activation.
        self._recover_orphaned_openconnect()

        # A previous service crash must not leave this host-wide route behind.
        # New activations use a unique metric/protocol plus an ownership marker;
        # the exact legacy metric-50 route is removed once during upgrade/start.
        self._remove_stale_ipv6_leak_protection()

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
        log.info(f"VPN data keys: {list(vpn_data.keys())}")
        log.info(f"VPN secrets keys: {list(vpn_secrets.keys())}")

        # Extract data fields
        secrets['gateway'] = vpn_data.get('gateway', '')
        secrets['protocol'] = vpn_data.get('protocol', 'anyconnect')
        secrets['username'] = vpn_data.get('username', '')
        secrets['gp_os_version'] = vpn_data.get('gp-os-version', '')
        secrets['gp_auth_interface'] = vpn_data.get('gp-auth-interface', '')
        secrets['disable_cookie_cache'] = vpn_data.get('disable-cookie-cache', '')
        secrets['disable_browser_session_cache'] = vpn_data.get('disable-browser-session-cache', '')
        secrets['enable_browser_session_cache'] = vpn_data.get('enable-browser-session-cache', '')
        secrets['skip_gp_cookie_cache'] = vpn_data.get('skip-gp-cookie-cache', '')
        secrets['auto_reconnect'] = vpn_data.get('auto-reconnect', '')
        secrets['reconnect_delay_seconds'] = vpn_data.get('reconnect-delay-seconds', '')
        secrets['reconnect_max_delay_seconds'] = vpn_data.get('reconnect-max-delay-seconds', '')
        secrets['reconnect_max_attempts'] = vpn_data.get('reconnect-max-attempts', '')
        secrets['dns_server_limit'] = vpn_data.get('dns-server-limit', '')
        secrets['mfa_preference'] = vpn_data.get('mfa-preference', '')
        secrets['debug_auth'] = vpn_data.get('debug-auth', '')

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

    def _do_saml_auth_with_ui_stall_fallback(self, **auth_kwargs):
        """Retry one AnyConnect cached-browser stall in an ephemeral session."""
        try:
            return do_saml_auth(**auth_kwargs)
        except SamlUiStalledError:
            # The fast profile-repair policy is specific to AnyConnect/FHNW.
            # GlobalProtect has its own prelogin/callback flow and must not be
            # restarted under a clean browser profile by this wrapper.
            if auth_kwargs.get('protocol', 'anyconnect') != 'anyconnect':
                raise

            # An already-ephemeral attempt has no safer browser state to fall
            # back to. Propagate it without starting another MFA flow.
            if auth_kwargs.get('disable_browser_session_cache'):
                raise

            cancel_callback = auth_kwargs.get('cancel_callback')
            if cancel_callback and cancel_callback():
                raise

            log.warning(
                "Cached SAML browser session stalled; retrying once with an "
                "ephemeral browser session"
            )
            retry_kwargs = dict(auth_kwargs)
            retry_kwargs['disable_browser_session_cache'] = True
            return do_saml_auth(**retry_kwargs)

    @staticmethod
    def _is_cookie_rejection(error_msg) -> bool:
        """Return True when OpenConnect explicitly rejected a session cookie."""
        text = str(error_msg or '').lower()
        return 'cookie' in text and any(token in text for token in ('reject', 'invalid', 'fail'))

    @staticmethod
    def _write_gp_cookie_and_close(process, cookie: str) -> None:
        """Send one GP cookie line and EOF so OpenConnect cannot wait on stdin."""
        stream = getattr(process, "stdin", None)
        if stream is None:
            raise RuntimeError("OpenConnect stdin is unavailable")
        try:
            stream.write(f"{cookie}\n".encode())
            stream.flush()
        finally:
            stream.close()

    @staticmethod
    def _select_gp_cookie(cookies, auth_interface: str = 'portal'):
        """Return (value, usergroup, stdin) for the strongest GP auth artifact."""
        auth_interface = str(auth_interface or 'portal').strip().lower()
        if auth_interface not in {'portal', 'gateway'}:
            auth_interface = 'portal'
        if auth_interface == 'gateway':
            # A portal-userauthcookie is a portal handoff artifact. Passing it
            # as gateway:portal-userauthcookie makes OpenConnect submit it to
            # the wrong GP form. Direct gateway SAML must use the gateway's
            # prelogin cookie, including when both artifacts were captured.
            if cookies.get('prelogin-cookie'):
                return (
                    cookies['prelogin-cookie'],
                    'gateway:prelogin-cookie',
                    True,
                )
            raise RuntimeError(
                "GlobalProtect gateway authentication returned no gateway prelogin cookie"
            )
        if cookies.get('portal-userauthcookie'):
            return (
                cookies['portal-userauthcookie'],
                'portal:portal-userauthcookie',
                True,
            )
        if cookies.get('prelogin-cookie'):
            return (
                cookies['prelogin-cookie'],
                'portal:prelogin-cookie',
                True,
            )
        raise RuntimeError("GlobalProtect authentication returned no usable cookie")

    @staticmethod
    def _has_reusable_gp_cookie(cookies, auth_interface: str = 'portal') -> bool:
        """Return whether the artifact selected for this GP interface is reusable."""
        auth_interface = str(auth_interface or 'portal').strip().lower()
        if auth_interface == 'gateway':
            # Direct gateway auth always selects the single-use prelogin cookie,
            # even if the callback also exposed a reusable portal handoff.
            return False
        return bool(cookies and cookies.get('portal-userauthcookie'))

    @staticmethod
    def _build_gp_openconnect_command(
            openconnect_bin: str,
            proto_flag: str,
            gateway: str,
            usergroup: str,
            username: Optional[str] = None,
            resolve_arg: Optional[str] = None,
            hip_wrapper: Optional[str] = None,
            interface_name: Optional[str] = None,
    ) -> list[str]:
        """Build a GP command with the same identity flags for every cookie type."""
        cmd = [openconnect_bin, "--verbose", f"--protocol={proto_flag}"]
        if resolve_arg:
            cmd.append(resolve_arg)
        if interface_name:
            cmd.append(f"--interface={interface_name}")
        # GlobalProtect's native dead-peer cadence is ten seconds. Keep it so
        # an interrupted ESP/HTTPS path is detected promptly instead of
        # extending a blackholed session to the AnyConnect interval.
        cmd.extend(["--reconnect-timeout=300", "--force-dpd=10"])
        cmd.append("--non-inter")
        # GP SAML artifacts are authentication-form secrets, not final VPN
        # session cookies. Keep them out of argv and close stdin after one line.
        cmd.append("--passwd-on-stdin")
        cmd.extend([
            "--useragent=PAN GlobalProtect",
            f"--usergroup={usergroup}",
            "--os=linux-64",
        ])
        if username:
            cmd.append(f"--user={username}")
        if hip_wrapper:
            cmd.append(f"--csd-wrapper={hip_wrapper}")
        cmd.append(gateway)
        return cmd

    @staticmethod
    def _build_anyconnect_cookie_header(cookies) -> str:
        """Return only browser cookies that OpenConnect can consume.

        The named entries below are capture metadata, not HTTP cookies.  In
        particular, a SAML assertion must not be sent back as a Cisco cookie.
        Preserve all unknown cookie names for gateway compatibility.
        """
        metadata_keys = {
            "samlresponse",
            "saml-username",
            "_gateway_ip",
        }
        cookie_parts = []
        for raw_name, raw_value in (cookies or {}).items():
            name = str(raw_name).strip()
            value = str(raw_value)
            if (
                not name
                or name.casefold() in metadata_keys
                or any(character in name or character in value for character in "\r\n")
            ):
                continue
            cookie_parts.append(f"{name}={value}")
        return "; ".join(cookie_parts)

    @staticmethod
    def _build_anyconnect_cookie_config(cookie_header: str) -> bytes:
        """Encode one OpenConnect config containing the complete Cisco cookie."""
        cookie_header = str(cookie_header or "")
        if not cookie_header:
            raise ValueError("AnyConnect cookie header is empty")
        if "\r" in cookie_header or "\n" in cookie_header:
            raise ValueError("AnyConnect cookie header contains a line break")
        return f"cookie={cookie_header}\n".encode("utf-8")

    @staticmethod
    def _create_anyconnect_cookie_config_fd(cookie_header: str) -> int:
        """Store an unlimited cookie config in an anonymous, inherited memfd."""
        memfd_create = getattr(os, "memfd_create", None)
        if memfd_create is None:
            raise RuntimeError(
                "Anonymous in-memory files are unavailable on this Linux runtime"
            )

        payload = VPNPluginService._build_anyconnect_cookie_config(cookie_header)
        raw_config_fd = memfd_create(
            "nm-ms-sso-anyconnect-cookie",
            getattr(os, "MFD_CLOEXEC", 0),
        )
        try:
            # stdin may be closed when NetworkManager launches the service, in
            # which case memfd_create() can return fd 0.  Popen's DEVNULL stdin
            # setup would replace that descriptor before OpenConnect reads it.
            config_fd = fcntl.fcntl(
                raw_config_fd,
                fcntl.F_DUPFD_CLOEXEC,
                3,
            )
        finally:
            os.close(raw_config_fd)
        try:
            os.fchmod(config_fd, stat.S_IRUSR | stat.S_IWUSR)
            remaining = memoryview(payload)
            while remaining:
                try:
                    written = os.write(config_fd, remaining)
                except InterruptedError:
                    continue
                if written <= 0:
                    raise OSError("Could not write AnyConnect cookie config")
                remaining = remaining[written:]
            os.lseek(config_fd, 0, os.SEEK_SET)
            return config_fd
        except Exception:
            os.close(config_fd)
            raise

    @staticmethod
    def _build_anyconnect_openconnect_command(
            openconnect_bin: str,
            proto_flag: str,
            gateway: str,
            cookie_config_fd: int,
            resolve_arg: Optional[str] = None,
            interface_name: Optional[str] = None,
    ) -> list[str]:
        """Build a non-interactive command referencing an inherited secret fd."""
        cookie_config_fd = int(cookie_config_fd)
        if cookie_config_fd < 0:
            raise ValueError("AnyConnect cookie config fd must be non-negative")
        cmd = [openconnect_bin, "--verbose", f"--protocol={proto_flag}"]
        if resolve_arg:
            cmd.append(resolve_arg)
        if interface_name:
            cmd.append(f"--interface={interface_name}")
        cmd.extend([
            "--reconnect-timeout=300",
            "--force-dpd=30",
            "--non-inter",
            f"--config=/proc/self/fd/{cookie_config_fd}",
            gateway,
        ])
        return cmd

    @staticmethod
    def _build_anyconnect_popen_kwargs(cookie_config_fd: int) -> dict:
        """Keep only the anonymous config fd open in the OpenConnect child."""
        cookie_config_fd = int(cookie_config_fd)
        if cookie_config_fd < 0:
            raise ValueError("AnyConnect cookie config fd must be non-negative")
        return {
            "stdin": subprocess.DEVNULL,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.STDOUT,
            "pass_fds": (cookie_config_fd,),
        }

    @staticmethod
    def _advance_anyconnect_structural_readiness(
            candidate_ifindex: Optional[int],
            ip_addr: Optional[str],
            stable_ifindex: Optional[int],
            stable_since: Optional[float],
            now: float,
            grace_seconds: float = ANYCONNECT_STRUCTURAL_READY_GRACE_SECONDS,
    ) -> tuple[bool, Optional[int], Optional[float]]:
        """Track a stable, exact AnyConnect link independently of log wording."""
        if candidate_ifindex is None or not ip_addr:
            return False, None, None
        if stable_ifindex != candidate_ifindex or stable_since is None:
            return False, candidate_ifindex, now
        ready = now - stable_since >= max(0.0, grace_seconds)
        return ready, stable_ifindex, stable_since

    @staticmethod
    def _classify_openconnect_timeout(output: str) -> str:
        """Return a fixed, secret-free diagnostic for a stalled OpenConnect handoff."""
        text = str(output or '').lower()
        if not text.strip():
            return "no OpenConnect output"
        if any(marker in text for marker in (
            "fgets (stdin)",
            "please enter",
            "password:",
            "passwd:",
        )):
            return "waiting for additional credential input"
        if "hip" in text or "host integrity" in text:
            return "waiting during HIP negotiation"
        if "certificate" in text:
            return "stalled during certificate validation"
        if "ssl" in text or "https" in text or "connected to" in text:
            return "TLS connected but no tunnel was created"
        return "handshake produced output but no tunnel"

    def _gp_early_started_enabled(self) -> bool:
        """Whether GP should optimistically report STARTED during auth."""
        value = self._parse_bool(os.environ.get("MS_SSO_NM_GP_EARLY_STARTED"))
        if value is None:
            # GP profiles use a 300-second NetworkManager timeout. Reporting
            # STARTED before a tunnel exists produces a false "connected" UI.
            return False
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

    @staticmethod
    def _tunnel_name_for_generation(connect_generation: Optional[int]) -> str:
        """Return a short plugin-specific interface name for one activation."""
        generation = max(0, int(connect_generation or 0)) % 100
        return f"tun-ms-sso{generation}"

    @staticmethod
    def _link_ifindex(device: str) -> Optional[int]:
        """Return a live link ifindex; names alone are not stable ownership."""
        try:
            return socket.if_nametoindex(str(device))
        except (OSError, ValueError):
            return None

    def _list_connected_uplinks(self) -> dict[str, str]:
        """Return connected NetworkManager physical uplinks as device -> UUID."""
        uplinks = {}
        if not shutil.which("nmcli"):
            return uplinks
        try:
            result = subprocess.run(
                [
                    "nmcli",
                    "--terse",
                    "--fields",
                    "DEVICE,TYPE,STATE,CON-UUID",
                    "device",
                    "status",
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )
        except Exception as e:
            log.info(f"Could not enumerate NetworkManager uplinks: {e}")
            return uplinks

        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()
            log.info(f"Could not enumerate NetworkManager uplinks: {detail}")
            return uplinks

        for line in result.stdout.splitlines():
            parts = line.split(":", 3)
            if len(parts) < 3:
                continue
            device, device_type, state = parts[:3]
            connection_uuid = parts[3] if len(parts) > 3 else ""
            if (
                device
                and device_type in PHYSICAL_UPLINK_TYPES
                and state.startswith("connected")
            ):
                uplinks[device] = connection_uuid
        return uplinks

    def _capture_base_network_state(self) -> None:
        """Remember pre-VPN tunnel and uplink ownership for safe teardown."""
        self.preexisting_tun_devices = self._list_tun_devices()
        current_uplinks = self._list_connected_uplinks()
        if current_uplinks:
            self.pre_vpn_uplinks = current_uplinks
        if shutil.which("resolvectl"):
            self.pre_vpn_dns_state_captured = True
            self.pre_vpn_dns_default_uplinks = (
                self._dns_default_route_uplinks(set(current_uplinks))
            )
        log.info(
            "Captured base network state: "
            f"uplinks={sorted(self.pre_vpn_uplinks)}, "
            f"dns-default-uplinks={sorted(self.pre_vpn_dns_default_uplinks)}, "
            f"preexisting-tunnels={sorted(self.preexisting_tun_devices)}"
        )

    def _dns_default_route_uplinks(self, devices: set[str]) -> set[str]:
        """Return physical links systemd-resolved currently uses by default."""
        resolvectl = shutil.which("resolvectl")
        if not resolvectl:
            return set()
        default_uplinks = set()
        for device in sorted(devices):
            try:
                result = subprocess.run(
                    [resolvectl, "status", device],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=5,
                )
            except Exception:
                continue
            if result.returncode != 0:
                continue
            body = result.stdout.lower()
            if (
                re.search(r"current scopes:\s*[^\n]*\bdns\b", body)
                and re.search(r"default route:\s*yes\b", body)
            ):
                default_uplinks.add(device)
        return default_uplinks

    def _physical_dns_route_restored(self) -> bool:
        """Compare resolved's post-VPN default DNS links with the baseline."""
        if not self.pre_vpn_dns_state_captured:
            return True
        if not self.pre_vpn_dns_default_uplinks:
            return True
        current_uplinks = set(self._list_connected_uplinks())
        current_defaults = self._dns_default_route_uplinks(current_uplinks)
        required_defaults = self.pre_vpn_dns_default_uplinks & current_uplinks
        contaminated = self._uplinks_needing_reapply & current_uplinks
        return required_defaults.issubset(current_defaults) and not contaminated

    def _route_to_base_network_uses_uplink(self) -> bool:
        """Return True when public traffic is routed over a physical uplink."""
        uplinks = set(self.pre_vpn_uplinks)
        uplinks.update(self._list_connected_uplinks())
        targets = ["1.1.1.1"]
        gateway_ip = getattr(self, "current_gateway_ip", None)
        if gateway_ip and gateway_ip not in targets:
            targets.append(gateway_ip)

        for target in targets:
            try:
                result = subprocess.run(
                    ["ip", "-4", "route", "get", target],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=5,
                )
            except Exception as e:
                log.info(f"Base route validation failed: {e}")
                return False
            if result.returncode != 0:
                return False

            route_line = next(
                (line.strip() for line in result.stdout.splitlines() if line.strip()),
                "",
            )
            match = re.search(r"(?:^|\s)dev\s+(\S+)", route_line)
            if not match:
                return False
            route_device = match.group(1)
            if uplinks:
                if route_device not in uplinks:
                    return False
            elif route_device.startswith(("tun", "tap", "ppp")):
                return False
        return True

    def _base_dns_operational(self) -> bool:
        """Probe host DNS independently of either institution's VPN record."""
        host = str(
            os.environ.get("MS_SSO_NM_NETWORK_DNS_PROBE_HOST")
            or "example.com"
        ).strip()
        if not host:
            return True
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            pass

        getent = shutil.which("getent")
        if getent:
            try:
                result = subprocess.run(
                    [getent, "ahostsv4", host],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=5,
                )
                return result.returncode == 0 and bool(result.stdout.strip())
            except Exception:
                return False

        resolvectl = shutil.which("resolvectl")
        if resolvectl:
            try:
                result = subprocess.run(
                    [resolvectl, "query", "--legend=no", "--type=A", host],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=5,
                )
                return result.returncode == 0
            except Exception:
                return False
        return False

    def _base_network_ready(self) -> bool:
        """Return True only when both physical routing and DNS are usable."""
        route_ready = self._route_to_base_network_uses_uplink()
        dns_ready = self._base_dns_operational()
        dns_route_ready = self._physical_dns_route_restored()
        gateway_route_ready = not (
            getattr(self, "current_protocol", None) == "gp"
            and self._gp_gateway_route_mismatch(
                getattr(self, "current_gateway_ip", None)
            )
        )
        log.debug(
            "Base network health: "
            f"route={'ready' if route_ready else 'not-ready'}, "
            f"dns={'ready' if dns_ready else 'not-ready'}, "
            f"dns-route={'ready' if dns_route_ready else 'not-ready'}, "
            "gp-gateway-route="
            f"{'ready' if gateway_route_ready else 'not-ready'}"
        )
        return (
            route_ready
            and dns_ready
            and dns_route_ready
            and gateway_route_ready
        )

    @staticmethod
    def _run_recovery_command(command: list[str]) -> bool:
        """Run one bounded recovery command and report its real exit status."""
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
                timeout=8,
            )
        except Exception as e:
            log.info(f"Network recovery command failed ({command[0]}): {e}")
            return False
        if result.returncode == 0:
            return True
        detail = (result.stderr or result.stdout).strip()
        log.info(
            "Network recovery command returned "
            f"{result.returncode} ({command[0]}): {detail}"
        )
        return False

    def _reload_networkmanager_dns(self) -> None:
        """Ask NetworkManager/resolved to discard stale VPN DNS link state."""
        if shutil.which("nmcli"):
            if not self._run_recovery_command(
                ["nmcli", "general", "reload", "dns-full"]
            ):
                self._run_recovery_command(["nmcli", "general", "reload"])
        if shutil.which("resolvectl"):
            self._run_recovery_command(["resolvectl", "flush-caches"])

    def _primary_uplink_device(self, uplinks: dict[str, str]) -> Optional[str]:
        """Return the first NM uplink used by the kernel's default routes."""
        try:
            result = subprocess.run(
                ["ip", "-4", "route", "show", "default"],
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    match = re.search(r"(?:^|\s)dev\s+(\S+)", line)
                    if match and match.group(1) in uplinks:
                        return match.group(1)
        except Exception:
            pass
        return sorted(uplinks)[0] if uplinks else None

    def _gp_gateway_route_mismatch(self, gateway_ip: Optional[str]) -> bool:
        """Detect a GP gateway uplink that NetworkManager would later replace."""
        if not gateway_ip:
            return False
        current_uplinks = self._list_connected_uplinks()
        uplinks = dict(
            current_uplinks
            or getattr(self, "pre_vpn_uplinks", {})
            or {}
        )
        if not uplinks:
            return False
        try:
            defaults_result = subprocess.run(
                ["ip", "-4", "route", "show", "default"],
                capture_output=True,
                text=True,
                check=False,
                timeout=3,
            )
        except Exception as e:
            log.info(f"Could not inspect physical default routes: {e}")
            return False
        if defaults_result.returncode != 0:
            return False
        try:
            gateway_result = subprocess.run(
                ["ip", "-4", "route", "get", gateway_ip],
                capture_output=True,
                text=True,
                check=False,
                timeout=3,
            )
        except Exception as e:
            log.info(f"Could not inspect GlobalProtect gateway route: {e}")
            return False
        if gateway_result.returncode != 0:
            return False
        default_candidates = []
        for line in defaults_result.stdout.splitlines():
            device_match = re.search(r"(?:^|\s)dev\s+(\S+)", line)
            if not device_match or device_match.group(1) not in uplinks:
                continue
            metric_match = re.search(r"(?:^|\s)metric\s+(\d+)", line)
            metric = int(metric_match.group(1)) if metric_match else 0
            default_candidates.append((metric, device_match.group(1)))
        if not default_candidates:
            return False
        best_metric = min(metric for metric, _device in default_candidates)
        primary_devices = {
            device
            for metric, device in default_candidates
            if metric == best_metric
        }
        match = re.search(
            r"(?:^|\s)dev\s+(\S+)",
            gateway_result.stdout,
        )
        gateway_device = match.group(1) if match else None
        mismatch = bool(
            gateway_device
            and gateway_device not in primary_devices
        )
        if mismatch:
            log.warning(
                "GlobalProtect gateway route uses "
                f"{gateway_device} while the lowest-metric physical default "
                f"uses {','.join(sorted(primary_devices))}; "
                "NetworkManager reapply is required"
            )
        return mismatch

    def _stabilize_gp_gateway_route(self, gateway_ip: Optional[str]) -> bool:
        """Withdraw leaked VPN uplink routes before consuming GP credentials."""
        if not self._gp_gateway_route_mismatch(gateway_ip):
            return True
        self._uplinks_needing_reapply.update(
            self._list_connected_uplinks()
        )
        self._reapply_connected_uplinks()
        stable_samples = 0
        for delay in GP_GATEWAY_ROUTE_STABILIZATION_DELAYS:
            if delay:
                time.sleep(delay)
            if self._gp_gateway_route_mismatch(gateway_ip):
                stable_samples = 0
                continue
            stable_samples += 1
            if stable_samples >= 2:
                log.info(
                    "GlobalProtect gateway route stabilized before authentication"
                )
                return True
        return False

    def _reapply_connected_uplinks(self, reactivate: bool = False) -> None:
        """Reapply, and as a last resort reactivate, still-connected uplinks."""
        current_uplinks = self._list_connected_uplinks()
        devices = set(current_uplinks)
        devices.update(
            device
            for device in self.pre_vpn_uplinks
            if device in current_uplinks
        )
        devices.update(
            device
            for device in self._uplinks_needing_reapply
            if device in current_uplinks
        )

        for device in sorted(devices):
            reapplied = self._run_recovery_command(
                ["nmcli", "device", "reapply", device]
            )
            if reapplied:
                self._uplinks_needing_reapply.discard(device)
            if not reapplied:
                log.info(f"NetworkManager could not reapply uplink {device}")

        if reactivate and not self._base_network_ready():
            device = self._primary_uplink_device(current_uplinks)
            connection_uuid = (
                current_uplinks.get(device or "")
                or self.pre_vpn_uplinks.get(device or "")
            )
            if device and connection_uuid:
                log.warning(
                    "Base network is still unavailable; reactivating primary "
                    f"NetworkManager uplink {device}"
                )
                reactivated = self._run_recovery_command([
                    "nmcli",
                    "connection",
                    "up",
                    "uuid",
                    connection_uuid,
                    "ifname",
                    device,
                ])
                if reactivated:
                    self._uplinks_needing_reapply.discard(device)

    def _recover_base_network_once(self, reactivate: bool = False) -> bool:
        """Perform one health-driven base-network recovery pass."""
        if self._uplinks_needing_reapply:
            log.info(
                "Reapplying physical uplinks to withdraw transient VPN routes and DNS"
            )
            self._reapply_connected_uplinks()
        if self._base_network_ready():
            return True
        if not self._network_recovery_reload_attempted:
            log.warning(
                "Base route or DNS did not recover after VPN teardown; "
                "reloading NetworkManager DNS state"
            )
            self._reload_networkmanager_dns()
            self._network_recovery_reload_attempted = True
        self._reapply_connected_uplinks(reactivate=reactivate)
        return self._base_network_ready()

    def _post_disconnect_recovery_worker(self, token: int) -> None:
        """Run bounded recovery without blocking the GLib/D-Bus main thread."""
        try:
            while True:
                if token != self._network_recovery_token:
                    return
                if self.state in (
                    NM_VPN_SERVICE_STATE_STARTING,
                    NM_VPN_SERVICE_STATE_STARTED,
                ):
                    log.info(
                        "Skipping stale post-disconnect recovery during a new activation"
                    )
                    return

                if not self._cleanup_dns(recovery_token=token):
                    return
                if token != self._network_recovery_token:
                    return
                remaining = self._network_recovery_deadline - time.monotonic()
                if self._recover_base_network_once(reactivate=remaining <= 7.0):
                    log.info(
                        "Base network route and DNS are operational after VPN teardown"
                    )
                    self._uplinks_needing_reapply.clear()
                    return
                if remaining <= 0:
                    log.error(
                        "Base network did not recover within the bounded post-VPN window"
                    )
                    return
                time.sleep(min(1.0, remaining))
        finally:
            if token == self._network_recovery_token:
                self._network_recovery_thread = None

    def _post_disconnect_recovery_tick(self, token: int) -> bool:
        """Launch one guarded recovery worker from the GLib main loop."""
        if token != self._network_recovery_token:
            return False
        if self.state in (NM_VPN_SERVICE_STATE_STARTING, NM_VPN_SERVICE_STATE_STARTED):
            log.info("Skipping stale post-disconnect recovery during a new activation")
            return False
        recovery_thread = getattr(self, "_network_recovery_thread", None)
        if recovery_thread and recovery_thread.is_alive():
            # A prior token's worker may still be unwinding a bounded command.
            # Keep this GLib timeout alive so the newest recovery token gets a
            # worker as soon as that stale thread exits.
            return True
        recovery_thread = threading.Thread(
            target=self._post_disconnect_recovery_worker,
            args=(token,),
            name="nm-ms-sso-network-recovery",
            daemon=True,
        )
        self._network_recovery_thread = recovery_thread
        recovery_thread.start()
        return False

    def _schedule_post_disconnect_recovery(self) -> None:
        """Run cleanup after NetworkManager has withdrawn the VPN activation."""
        self._network_recovery_token += 1
        token = self._network_recovery_token
        current_uplinks = self._list_connected_uplinks()
        self._uplinks_needing_reapply.update(
            set(current_uplinks)
            or set(getattr(self, "pre_vpn_uplinks", {}))
        )
        self._network_recovery_deadline = (
            time.monotonic() + NETWORK_RECOVERY_TIMEOUT_SECONDS
        )
        self._network_recovery_reload_attempted = False
        GLib.timeout_add(
            NETWORK_RECOVERY_INITIAL_DELAY_MS,
            self._post_disconnect_recovery_tick,
            token,
        )

    def _wait_for_base_network_before_connect(
            self,
            connect_generation: Optional[int],
            timeout_seconds: int = 12,
    ) -> bool:
        """Repair a prior teardown before starting a new browser/auth flow."""
        if self._base_network_ready():
            return True
        log.warning("Waiting for base network recovery before VPN authentication")
        deadline = time.monotonic() + max(1, timeout_seconds)
        self._network_recovery_reload_attempted = False
        while time.monotonic() < deadline:
            if self._is_connect_cancelled(connect_generation):
                return False
            remaining = deadline - time.monotonic()
            if self._recover_base_network_once(reactivate=remaining <= 5.0):
                return True
            time.sleep(min(1.0, max(0.0, remaining)))
        return self._base_network_ready()

    def _connect_after_recovery(
            self,
            recovery_thread,
            settings,
            connect_generation: int,
    ) -> None:
        """Serialize a fresh connect behind an already-running recovery pass."""
        recovery_thread.join(timeout=NETWORK_RECOVERY_TIMEOUT_SECONDS + 10)
        if recovery_thread.is_alive():
            GLib.idle_add(
                self._emit_failure,
                "Prior VPN network recovery did not finish",
                connect_generation,
            )
            return
        if self._is_connect_cancelled(connect_generation):
            return
        self._connect_thread(settings, connect_generation)

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
                    output = (result.stderr or result.stdout).strip()
                    log.warning(f"modprobe tun failed: {output}")
                    if "Module tun not found in directory" in output:
                        log.error(
                            "Kernel module mismatch detected: running kernel "
                            f"{os.uname().release} has no tun module installed. "
                            "Reboot into the installed kernel or install matching kernel modules."
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

    def _tun_unavailable_message(self) -> str:
        """Return a user-actionable TUN prerequisite error."""
        return (
            "TUN device unavailable: could not open /dev/net/tun. "
            f"Running kernel is {os.uname().release}; reboot into the installed kernel "
            "or install matching kernel modules so modprobe tun succeeds."
        )

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
                partial = getattr(self, "_vpn_stdout_partial", "")
                if partial:
                    openconnect_reported_up = self._process_vpn_output_line(
                        partial,
                        openconnect_reported_up,
                    )
                    self._vpn_stdout_partial = ""
                break

            text = chunk.decode('utf-8', errors='replace')
            output_buffer += text
            if len(output_buffer) > 65536:
                output_buffer = output_buffer[-65536:]

            pending = getattr(self, "_vpn_stdout_partial", "") + text
            self._vpn_stdout_partial = ""
            for line in pending.splitlines(keepends=True):
                if not line.endswith(('\n', '\r')):
                    self._vpn_stdout_partial = line
                    continue
                openconnect_reported_up = self._process_vpn_output_line(
                    line.rstrip('\r\n'),
                    openconnect_reported_up,
                )

        return output_buffer, openconnect_reported_up

    def _process_vpn_output_line(self, line: str, openconnect_reported_up: bool) -> bool:
        """Parse one complete OpenConnect output line."""
        stripped = line.strip()
        if not stripped:
            return openconnect_reported_up

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
                log.info("OpenConnect reported tunnel session up")
            return True
        return openconnect_reported_up

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

    @staticmethod
    def _process_start_ticks(pid: int) -> Optional[str]:
        """Return Linux /proc start ticks so a persisted PID cannot be reused."""
        try:
            stat_text = Path(f"/proc/{int(pid)}/stat").read_text(encoding="utf-8")
            _prefix, separator, suffix = stat_text.rpartition(") ")
            if not separator:
                return None
            fields = suffix.split()
            # suffix starts at field 3 (state); starttime is field 22.
            return fields[19] if len(fields) > 19 else None
        except Exception:
            return None

    def _write_openconnect_state(
            self,
            process,
            tun_device: str = "",
            tun_ifindex: Optional[int] = None,
    ) -> None:
        """Persist only non-secret child ownership for crash recovery."""
        if not process or not getattr(process, "pid", None):
            return
        start_ticks = self._process_start_ticks(process.pid)
        if not start_ticks:
            return
        try:
            OPENCONNECT_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
            temporary = OPENCONNECT_STATE_FILE.with_name(
                f".{OPENCONNECT_STATE_FILE.name}.{process.pid}.tmp"
            )
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                0o600,
            )
            with os.fdopen(descriptor, "w", encoding="utf-8") as state_file:
                state_file.write(f"pid={int(process.pid)}\n")
                state_file.write(f"start_ticks={start_ticks}\n")
                if self.current_connection_uuid:
                    state_file.write(
                        f"connection_uuid={self.current_connection_uuid}\n"
                    )
                if tun_device:
                    state_file.write(f"tun={tun_device}\n")
                if tun_ifindex is not None:
                    state_file.write(f"tun_ifindex={int(tun_ifindex)}\n")
            os.replace(temporary, OPENCONNECT_STATE_FILE)
        except Exception as e:
            log.info(f"Could not persist OpenConnect recovery state: {e}")

    def _clear_openconnect_state(self, process=None) -> None:
        """Remove persisted ownership only when it still names this child."""
        if not OPENCONNECT_STATE_FILE.exists():
            return
        if process is not None and getattr(process, "pid", None):
            try:
                state = dict(
                    line.split("=", 1)
                    for line in OPENCONNECT_STATE_FILE.read_text(
                        encoding="utf-8"
                    ).splitlines()
                    if "=" in line
                )
                if state.get("pid") != str(int(process.pid)):
                    return
            except Exception:
                return
        try:
            OPENCONNECT_STATE_FILE.unlink(missing_ok=True)
        except Exception as e:
            log.info(f"Could not clear OpenConnect recovery state: {e}")

    def _recover_orphaned_openconnect(self) -> None:
        """Stop an exact persisted orphan and clean its exact tunnel ifindex."""
        if not OPENCONNECT_STATE_FILE.exists():
            return
        try:
            state = dict(
                line.split("=", 1)
                for line in OPENCONNECT_STATE_FILE.read_text(
                    encoding="utf-8"
                ).splitlines()
                if "=" in line
            )
            pid = int(state.get("pid", "0"))
            expected_start = state.get("start_ticks")
        except Exception as e:
            log.info(f"Ignoring invalid OpenConnect recovery state: {e}")
            self._clear_openconnect_state()
            return

        def owned_process_alive() -> bool:
            if pid <= 0 or self._process_start_ticks(pid) != expected_start:
                return False
            try:
                comm = Path(f"/proc/{pid}/comm").read_text(
                    encoding="utf-8"
                ).strip().lower()
            except Exception:
                return False
            return "openconnect" in comm

        if owned_process_alive():
            log.warning(f"Recovering orphaned OpenConnect process {pid}")
            try:
                os.kill(pid, signal.SIGHUP)
            except ProcessLookupError:
                pass
            except Exception as e:
                log.info(f"Could not signal orphaned OpenConnect process: {e}")
            deadline = time.monotonic() + 10.0
            while owned_process_alive() and time.monotonic() < deadline:
                time.sleep(0.25)
            if owned_process_alive():
                try:
                    os.kill(pid, signal.SIGTERM)
                    time.sleep(1.0)
                except Exception:
                    pass
            if owned_process_alive():
                try:
                    os.kill(pid, signal.SIGKILL)
                except Exception:
                    pass

        tun_device = state.get("tun", "")
        try:
            expected_ifindex = int(state.get("tun_ifindex", "0"))
        except ValueError:
            expected_ifindex = 0
        live_ifindex = self._link_ifindex(tun_device) if tun_device else None
        if (
            tun_device.startswith("tun")
            and expected_ifindex > 0
            and live_ifindex in (None, expected_ifindex)
        ):
            self.current_tun_device = tun_device
            self.owned_tun_devices.add(tun_device)
            self.owned_tun_ifindices[tun_device] = expected_ifindex

        if self.owned_tun_devices:
            self._cleanup_dns()
        else:
            self._clear_openconnect_state()

    def _stop_vpn_process(
            self,
            preserve_session: bool = True,
            force: bool = False,
            process=None,
            connect_generation: Optional[int] = None,
    ) -> None:
        """Stop OpenConnect while letting vpnc-script clean up when possible."""
        process = process or self.vpn_process
        if not process:
            return
        if process.poll() is not None:
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
            # Give OpenConnect/vpnc-script enough time to restore the saved
            # default route and resolver state before considering SIGKILL.
            process.wait(timeout=10)
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

    def _apply_split_dns_resolved(
            self,
            tun_dev: str,
            domains,
            connect_generation: Optional[int] = None,
    ):
        """Force route-only DNS after NetworkManager has processed Ip4Config."""
        expected_ifindex = getattr(self, "owned_tun_ifindices", {}).get(tun_dev)
        if (
            (connect_generation is not None and self._is_connect_cancelled(connect_generation))
            or tun_dev != self.current_tun_device
            or tun_dev not in self.owned_tun_devices
            or expected_ifindex is None
            or self._link_ifindex(tun_dev) != expected_ifindex
        ):
            log.info(
                f"Skipping stale split-DNS callback for {tun_dev} "
                f"(generation {connect_generation})"
            )
            return False
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
            connection_settings = settings.get('connection', {})
            self.current_connection_uuid = str(
                connection_settings.get('uuid') or ''
            ).strip() or None
            gateway = secrets['gateway']
            protocol = secrets['protocol']
            username = secrets['username']
            password = secrets['password']
            totp_secret = secrets['totp_secret']
            gp_os_version = (secrets.get('gp_os_version') or '').strip()
            gp_auth_interface = str(
                secrets.get('gp_auth_interface')
                or os.environ.get('MS_SSO_GP_AUTH_INTERFACE')
                or 'portal'
            ).strip().lower()
            if gp_auth_interface not in {'portal', 'gateway'}:
                log.warning(
                    "Ignoring invalid GlobalProtect auth interface: "
                    f"{gp_auth_interface!r}"
                )
                gp_auth_interface = 'portal'
            mfa_preference = str(
                secrets.get('mfa_preference')
                or os.environ.get("MS_SSO_MFA_PREFERENCE")
                or "auto"
            ).strip().lower()
            if mfa_preference not in {'auto', 'totp', 'push'}:
                log.warning(f"Ignoring invalid MFA preference: {mfa_preference!r}")
                mfa_preference = 'auto'
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
            )
            if force_enable_browser_session_cache:
                disable_browser_session_cache = False
            log.info(
                "Browser session cache: "
                f"{'disabled' if disable_browser_session_cache else 'enabled'}"
            )
            log.info(f"MFA preference: {mfa_preference}")
            debug_auth = (
                self._is_truthy(secrets.get('debug_auth'))
                or self._is_truthy(os.environ.get("MS_SSO_NM_DEBUG_AUTH"))
            )
            if debug_auth:
                log.info("Privacy-safe SAML browser diagnostics enabled")
            if protocol in {'gp', 'anyconnect'} and disable_browser_session_cache and not force_enable_browser_session_cache:
                log.info(
                    f"{protocol} uses a fresh browser session by configuration; "
                    "remove disable-browser-session-cache=1 to reuse SSO browser state"
                )

            if not gateway:
                raise Exception("No gateway specified")

            if not username:
                raise Exception("No username specified")

            log.info(f"Connecting to {gateway} via {protocol}")
            log.info(f"Username: {username}")
            if protocol == 'gp':
                log.info(f"GlobalProtect OS version: {gp_os_version or get_gp_os_version()}")
                log.info(f"GlobalProtect auth interface: {gp_auth_interface}")
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
            self._capture_base_network_state()
            if not self._wait_for_base_network_before_connect(connect_generation):
                raise Exception(
                    "Base network route or DNS is not operational after the previous VPN teardown"
                )
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
            if (
                protocol == 'gp'
                and not self._stabilize_gp_gateway_route(
                    self.current_gateway_ip
                )
            ):
                raise Exception(
                    "GlobalProtect gateway route remained inconsistent after "
                    "NetworkManager reapply"
                )

            if protocol in {'anyconnect', 'gp'} and not self._ensure_tun_available():
                raise Exception(self._tun_unavailable_message())

            # Only GP gets pre-tunnel Config keepalives. For AnyConnect this can
            # make NetworkManager show "connected" even though SAML produced no
            # cookie and no tun device exists yet.
            if protocol == 'gp':
                # Delay GP's first Config emission as well; keep UI in "connecting".
                self.gp_connect_start_time = time.monotonic()
                if os.environ.get("MS_SSO_NM_GP_EARLY_CONFIG", "").lower() in {"1", "true", "yes"}:
                    GLib.idle_add(self._emit_initial_config, connect_generation)
            # GP profiles use a 300-second NetworkManager timeout, so keep the
            # connection in STARTING until a real tunnel is usable. A legacy
            # optimistic STARTED state remains available as an explicit opt-in.
            if protocol == 'gp':
                if self._gp_early_started_enabled():
                    GLib.idle_add(self._emit_started_for_auth, connect_generation)

            # Connection name for cookie cache
            connection_name = f"nm-{gateway}"
            log.debug(f"Cookie cache connection name: {connection_name}")
            # Pre-tunnel transport retry configuration.  A tunnel that was
            # already STARTED always ends this NM activation instead.
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
            reconnect_default_max_attempts = 5
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
            watchdog_interval_seconds = self._parse_positive_int(os.environ.get("MS_SSO_NM_WATCHDOG_INTERVAL_SECONDS"), 5)
            watchdog_missing_tun_limit = self._parse_positive_int(os.environ.get("MS_SSO_NM_WATCHDOG_TUN_MISS_LIMIT"), 3)
            anyconnect_wait_existing_auth_seconds = 0
            anyconnect_fresh_retries = 0
            anyconnect_retry_delay_seconds = 0
            anyconnect_unstable_session_seconds = 0
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
            log.info(
                "Pre-tunnel transport retry: "
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
                    f"threshold={anyconnect_unstable_session_seconds}s; "
                    "post-tunnel retries use a fresh NetworkManager activation"
                )

            reconnect_attempt = 0
            saml_keepalive_seconds = self._parse_positive_int(
                os.environ.get("MS_SSO_NM_AUTH_KEEPALIVE_SECONDS"),
                self._parse_positive_int(
                    os.environ.get("MS_SSO_NM_GP_AUTH_KEEPALIVE_SECONDS") if protocol == 'gp' else None,
                    10,
                ),
            )

            while not _connect_cancelled():
                if not self._wait_for_base_network_before_connect(
                    connect_generation
                ):
                    raise Exception(
                        "Base network route or DNS did not recover before VPN retry"
                    )
                # Try connection with retry on cookie rejection.
                max_attempts = 2 + anyconnect_fresh_retries
                connection_ended = False
                connection_uptime_seconds = 0
                final_error = None
                session_used_cache = False
                fresh_auth_attempts = 0
                terminal_auth_failure = False

                for attempt in range(max_attempts):
                    log.info(f"Connection attempt {attempt + 1}/{max_attempts}")
                    if _connect_cancelled():
                        log.info("Connect cancelled before authentication; aborting")
                        return

                    # Try cached cookies first (unless explicitly disabled).
                    cookies = None
                    used_cache = False

                    if attempt == 0 and skip_gp_cookie_cache:
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
                        else:
                            log.info("No valid cached cookies found")

                    # If no cached cookies or this is a retry, authenticate
                    if not cookies:
                        if (
                            protocol == 'anyconnect'
                            and anyconnect_wait_existing_auth_seconds > 0
                            and self.auth_in_progress
                        ):
                            auth_generation = self.auth_generation
                            if auth_generation is not None and auth_generation != connect_generation:
                                log.warning(
                                    "Ignoring stale AnyConnect authentication from superseded "
                                    f"generation {auth_generation}; starting a fresh auth flow"
                                )
                            else:
                                log.info(
                                    "AnyConnect authentication already in progress in this worker; "
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
                                    if not self.auth_in_progress or self.auth_generation != connect_generation:
                                        break
                                    if not self._interruptible_sleep(2, connect_generation):
                                        return

                    if not cookies:
                        log.info("Performing SAML authentication...")
                        fresh_auth_attempts += 1
                        self.auth_in_progress = True
                        self.auth_generation = connect_generation
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
                                    GLib.idle_add(self._emit_initial_config, connect_generation)
                                # Keep NetworkManager from thinking the connection stalled.
                                if self._should_emit_started_keepalive(protocol):
                                    GLib.idle_add(self._emit_started_keepalive, connect_generation)
                                else:
                                    GLib.idle_add(self._emit_starting_keepalive, connect_generation)

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
                            cookies = self._do_saml_auth_with_ui_stall_fallback(
                                vpn_server=gateway,
                                vpn_server_ip=self.current_gateway_ip,
                                username=username,
                                password=password,
                                totp_secret=totp_secret,
                                auto_totp=True,
                                headless=True,
                                debug=debug_auth,
                                protocol=protocol,  # Pass protocol for correct SAML URL
                                disable_browser_session_cache=disable_browser_session_cache,
                                gp_os_version=gp_os_version or None,
                                gp_auth_interface=gp_auth_interface,
                                cancel_callback=_connect_cancelled,
                                progress_callback=lambda event: log.info(
                                    f"SAML flow: {event}"
                                ),
                                mfa_preference=mfa_preference,
                                notification_helper_path=os.path.join(
                                    os.path.dirname(os.path.abspath(__file__)),
                                    "nm-ms-sso-notify",
                                ),
                            )
                            log.info(f"SAML auth returned cookies: {list(cookies.keys()) if cookies else 'none'}")
                            if protocol == 'anyconnect' and cookies and not self._has_usable_anyconnect_cookies(cookies):
                                log.warning(
                                    "Ignoring incomplete AnyConnect SAML cookies "
                                    f"(keys: {list(cookies.keys())})"
                                )
                                cookies = None
                        except Exception as auth_err:
                            log.error(f"SAML auth error: {auth_err}")
                            import traceback
                            traceback.print_exc()
                            final_error = f"SAML authentication error: {auth_err}"
                            auth_failed = True
                        finally:
                            if self.auth_generation == connect_generation:
                                self.auth_in_progress = False
                                self.auth_generation = None
                                self.saml_start_time = None
                                self._auth_started_guard_triggered = False
                            stop_keepalive.set()

                        if auth_failed:
                            terminal_auth_failure = True
                            break
                        if not cookies:
                            final_error = "SAML authentication returned no cookies"
                            terminal_auth_failure = True
                            break

                        cache_usergroup = 'portal:prelogin-cookie'
                        if protocol == 'gp':
                            try:
                                _cookie_value, cache_usergroup, _cookie_uses_stdin = (
                                    self._select_gp_cookie(
                                        cookies,
                                        auth_interface=gp_auth_interface,
                                    )
                                )
                            except RuntimeError as gp_cookie_error:
                                final_error = str(gp_cookie_error)
                                terminal_auth_failure = True
                                break

                        # Store fresh cookies unless cache is explicitly disabled.
                        # Store before cancellation check so NM-triggered reconnects can
                        # reuse fresh auth result and skip duplicate browser auth flows.
                        if not disable_cookie_cache and not skip_gp_cookie_cache and not used_cache:
                            store_nm_cookies(
                                connection_name,
                                cookies,
                                usergroup=cache_usergroup,
                            )

                        if _connect_cancelled():
                            log.info("Connect cancelled during authentication; fresh cookies preserved for retry")
                            return

                    # Try to connect with these cookies
                    if _connect_cancelled():
                        log.info("Connect cancelled before starting OpenConnect; aborting")
                        return
                    if protocol == 'gp' and not self._has_reusable_gp_cookie(
                        cookies,
                        gp_auth_interface,
                    ):
                        # A prelogin cookie is endpoint-scoped and commonly
                        # single-use. It may be cached briefly across an NM
                        # cancellation before handoff, but never replay it after
                        # OpenConnect starts consuming it.
                        clear_nm_cookies(connection_name)
                    success, error_msg, uptime_seconds = self._attempt_vpn_connection(
                        gateway,
                        protocol,
                        cookies,
                        username,
                        used_cache=used_cache,
                        gp_os_version=gp_os_version,
                        gp_auth_interface=gp_auth_interface,
                        connect_generation=connect_generation,
                        watchdog_interval_seconds=watchdog_interval_seconds,
                        watchdog_missing_tun_limit=watchdog_missing_tun_limit,
                    )

                    if _connect_cancelled():
                        log.info("Connect cancelled after OpenConnect attempt; preserving cookie cache")
                        return

                    cookie_rejected = self._is_cookie_rejection(error_msg)
                    if success:
                        connection_ended = True
                        connection_uptime_seconds = uptime_seconds
                        session_used_cache = used_cache
                        log.info("VPN connection established and later ended")
                        break
                    elif used_cache and attempt < max_attempts - 1:
                        if cookie_rejected:
                            log.warning("Cached cookie rejected, clearing cache and re-authenticating...")
                            clear_nm_cookies(connection_name)
                            continue
                        if protocol == 'gp' and not self._has_reusable_gp_cookie(
                            cookies,
                            gp_auth_interface,
                        ):
                            log.warning(
                                "Cached one-time GlobalProtect prelogin cookie did not "
                                "establish a tunnel; clearing it before one fresh SAML attempt"
                            )
                            clear_nm_cookies(connection_name)
                            continue
                        protocol_label = "GlobalProtect" if protocol == 'gp' else "AnyConnect"
                        log.warning(
                            f"Cached {protocol_label} cookie did not establish a usable tunnel; "
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
                        if not used_cache and cookie_rejected:
                            terminal_auth_failure = True
                        if not used_cache:
                            if protocol == 'gp':
                                if self._has_reusable_gp_cookie(
                                    cookies,
                                    gp_auth_interface,
                                ) and not cookie_rejected:
                                    log.info(
                                        "Preserving reusable GlobalProtect portal cookie after "
                                        "transport failure"
                                    )
                                else:
                                    clear_nm_cookies(connection_name)
                                    terminal_auth_failure = True
                                    if not cookie_rejected:
                                        final_error = (
                                            (error_msg or "GlobalProtect tunnel handoff failed")
                                            + "; not repeating SAML/TOTP after a one-time "
                                            "prelogin cookie was consumed"
                                        )
                            elif not (
                                protocol == 'anyconnect'
                                and error_msg
                                and 'dns' in str(error_msg).lower()
                            ):
                                clear_nm_cookies(connection_name)
                        if not final_error:
                            final_error = error_msg or "VPN connection failed"
                        break

                if _connect_cancelled():
                    return

                if not connection_ended:
                    if terminal_auth_failure:
                        # Credential/MFA failures are not transport failures. A
                        # watchdog retry would only launch another browser/MFA
                        # flow inside the same NetworkManager activation.
                        raise Exception(final_error or "SAML authentication failed")
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
                        GLib.idle_add(self._emit_started_keepalive, connect_generation)
                    else:
                        GLib.idle_add(self._emit_starting_keepalive, connect_generation)
                    if protocol == 'gp' and self._gp_initial_config_allowed():
                        GLib.idle_add(self._emit_initial_config, connect_generation)
                    if not self._interruptible_sleep(delay_seconds, connect_generation):
                        return
                    continue

                # Once Config/Ip4Config has been emitted, NetworkManager owns an
                # activation that references this exact tunnel ifindex.  Reusing
                # that activation after OpenConnect removed the device leaves NM
                # and systemd-resolved pointing at a dead link.  OpenConnect has
                # already exhausted its own bounded reconnect window, so finish
                # this activation and let a later NM request start from a healthy
                # physical network.
                if (
                    protocol == 'anyconnect'
                    and session_used_cache
                    and anyconnect_unstable_session_seconds > 0
                    and 0 < connection_uptime_seconds < anyconnect_unstable_session_seconds
                ):
                    clear_nm_cookies(connection_name)
                raise Exception(
                    "VPN tunnel ended unexpectedly after "
                    f"{connection_uptime_seconds}s; ending this activation to restore "
                    "the base network"
                )

        except Exception as e:
            error_msg = str(e)
            log.error(f"Connection error: {error_msg}")
            import traceback
            traceback.print_exc()
            GLib.idle_add(self._emit_failure, error_msg, connect_generation)

    def _attempt_vpn_connection(
            self,
            gateway,
            protocol,
            cookies,
            username=None,
            used_cache=False,
            gp_os_version=None,
            gp_auth_interface='portal',
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
            tunnel_was_established = False
            # Log cookie info for debugging
            log.debug(f"Cookie keys: {list(cookies.keys())}")

            # Connect to VPN
            # We use subprocess so we can monitor and return control
            proto_flag = PROTOCOLS.get(protocol, {}).get('flag', 'anyconnect')
            openconnect_bin = get_openconnect_binary(protocol)
            resolve_arg = self._get_openconnect_resolve_arg()
            # Capture existing tunnel devices before OpenConnect can create its
            # interface; a fast process must not make the new tun look stale.
            baseline_tun_devs = self._list_tun_devices()
            requested_tun_device = self._tunnel_name_for_generation(
                connect_generation
            )
            if requested_tun_device in baseline_tun_devs:
                return (
                    False,
                    f"Reserved VPN interface {requested_tun_device} already exists",
                    0,
                )

            if not self._ensure_tun_available():
                return (
                    False,
                    self._tun_unavailable_message(),
                    0,
                )

            if protocol == 'gp':
                cookie_str, gp_usergroup, gp_cookie_uses_stdin = (
                    self._select_gp_cookie(
                        cookies,
                        auth_interface=gp_auth_interface,
                    )
                )
                gp_env = os.environ.copy()
                if gp_os_version:
                    gp_env["MS_SSO_GP_OS_VERSION"] = gp_os_version
                else:
                    gp_env.setdefault("MS_SSO_GP_OS_VERSION", get_gp_os_version())
                gp_hip_wrapper = get_gp_hip_report_wrapper()
                gp_username = cookies.get('saml-username') or username
                log.debug(
                    "Using GlobalProtect authentication artifact "
                    f"(group={gp_usergroup}, len={len(cookie_str)})"
                )
                cmd = self._build_gp_openconnect_command(
                    openconnect_bin=openconnect_bin,
                    proto_flag=proto_flag,
                    gateway=gateway,
                    usergroup=gp_usergroup,
                    username=gp_username,
                    resolve_arg=resolve_arg,
                    hip_wrapper=gp_hip_wrapper,
                    interface_name=requested_tun_device,
                )
                if gp_hip_wrapper:
                    log.info(
                        "Using GlobalProtect HIP wrapper: "
                        f"{gp_hip_wrapper} (OS={gp_env.get('MS_SSO_GP_OS_VERSION')})"
                    )
                popen_kwargs = {
                    "stdout": subprocess.PIPE,
                    "stderr": subprocess.STDOUT,
                    "env": gp_env,
                }
                if gp_cookie_uses_stdin:
                    popen_kwargs["stdin"] = subprocess.PIPE
                self.vpn_process = subprocess.Popen(cmd, **popen_kwargs)
                vpn_process = self.vpn_process
                self.vpn_process_generation = connect_generation
                self._write_openconnect_state(
                    vpn_process,
                    requested_tun_device,
                )
                if gp_cookie_uses_stdin:
                    self._write_gp_cookie_and_close(vpn_process, cookie_str)
            else:
                cookie_str = self._build_anyconnect_cookie_header(cookies)
                if not cookie_str:
                    return (
                        False,
                        "AnyConnect authentication returned no usable HTTP cookies",
                        0,
                    )
                log.debug(f"Using AnyConnect cookie (len={len(cookie_str)})")
                cookie_config_fd = self._create_anyconnect_cookie_config_fd(
                    cookie_str
                )
                try:
                    cmd = self._build_anyconnect_openconnect_command(
                        openconnect_bin=openconnect_bin,
                        proto_flag=proto_flag,
                        gateway=gateway,
                        cookie_config_fd=cookie_config_fd,
                        resolve_arg=resolve_arg,
                        interface_name=requested_tun_device,
                    )
                    log.debug(
                        f"OpenConnect command: {openconnect_bin} --verbose "
                        f"--protocol={proto_flag} --config=/proc/self/fd/[redacted] "
                        f"{gateway}"
                    )
                    self.vpn_process = subprocess.Popen(
                        cmd,
                        **self._build_anyconnect_popen_kwargs(cookie_config_fd),
                    )
                finally:
                    os.close(cookie_config_fd)
                vpn_process = self.vpn_process
                self.vpn_process_generation = connect_generation
                self._write_openconnect_state(
                    vpn_process,
                    requested_tun_device,
                )

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
            self._vpn_stdout_partial = ""

            # Monitor for interface up and parse output for DNS
            # Wait for tun interface to come up
            timeout = self._get_tunnel_connect_timeout_seconds(protocol)
            log.info(f"Waiting up to {timeout}s for tunnel interface")
            start_time = time.monotonic()
            connected = False
            output_buffer = ""
            openconnect_reported_up = False
            structural_ready_ifindex = None
            structural_ready_since = None

            # Set stdout to non-blocking so we can read while checking interface
            import os as os_module
            fd = vpn_process.stdout.fileno()
            fl = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, fl | os_module.O_NONBLOCK)

            while time.monotonic() - start_time < timeout:
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
                if (
                    requested_tun_device in tun_devs_now
                    and requested_tun_device not in baseline_tun_devs
                ):
                    candidate_tun = requested_tun_device

                if candidate_tun:
                    self.current_tun_device = candidate_tun
                    self.owned_tun_devices.add(candidate_tun)
                    candidate_ifindex = self._link_ifindex(candidate_tun)
                    if candidate_ifindex is not None:
                        self.owned_tun_ifindices[candidate_tun] = candidate_ifindex
                    self._write_openconnect_state(
                        vpn_process,
                        candidate_tun,
                        candidate_ifindex,
                    )
                    if protocol != 'anyconnect':
                        log.info(f"Found tun device: {self.current_tun_device}")
                        connected = True
                        break
                    if openconnect_reported_up and candidate_ifindex is not None:
                        log.info(f"Found tun device: {self.current_tun_device}")
                        connected = True
                        break

                    # The requested name did not exist before this child was
                    # launched, and its exact ifindex is persisted as owned
                    # state.  Some OpenConnect versions change their English
                    # success wording, so a live link with stable IPv4 is a
                    # stronger readiness signal than stdout text.  The short
                    # grace also drains the remaining pushed DNS/route lines.
                    candidate_ip, _candidate_prefix = (
                        self._get_tun_ipv4_config(candidate_tun)
                    )
                    (
                        structurally_ready,
                        structural_ready_ifindex,
                        structural_ready_since,
                    ) = self._advance_anyconnect_structural_readiness(
                        candidate_ifindex,
                        candidate_ip,
                        structural_ready_ifindex,
                        structural_ready_since,
                        time.monotonic(),
                    )
                    if structurally_ready and vpn_process.poll() is None:
                        output_buffer, openconnect_reported_up = (
                            self._consume_vpn_stdout(
                                output_buffer,
                                openconnect_reported_up,
                                process=vpn_process,
                            )
                        )
                        log.info(
                            "Found structurally ready AnyConnect tunnel: "
                            f"{self.current_tun_device} ifindex={candidate_ifindex}"
                        )
                        connected = True
                        break
                else:
                    structural_ready_ifindex = None
                    structural_ready_since = None

                time.sleep(0.5)

            if not connected:
                log.warning(
                    "OpenConnect tunnel timeout diagnostic: "
                    f"{self._classify_openconnect_timeout(output_buffer)} "
                    f"(captured-bytes={len(output_buffer)})"
                )
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
            tunnel_was_established = True

            log.info(f"VPN DNS servers captured: {self.vpn_dns_servers}")

            # Emit full IP config now that interface is up
            GLib.idle_add(
                self._emit_connected,
                connect_generation,
                vpn_process,
                self.current_tun_device,
            )
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
                if not self._interruptible_sleep(
                    watch_interval,
                    connect_generation,
                ):
                    break

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
            if locals().get("tunnel_was_established", False):
                connected_at_value = locals().get("connected_at")
                uptime_seconds = 0
                if connected_at_value is not None:
                    uptime_seconds = int(
                        max(0, time.monotonic() - connected_at_value)
                    )
                # Config may already be queued/emitted.  Route this through the
                # post-STARTED terminal path so NM withdraws the activation
                # before any cleanup or retry.
                return (True, error_msg, uptime_seconds)
            # Check if it's a cookie rejection error
            if 'cookie' in error_msg.lower() and ('reject' in error_msg.lower() or 'invalid' in error_msg.lower()):
                return (False, "Cookie rejected by server", 0)
            return (False, error_msg, 0)

    def _emit_initial_config(self, connect_generation: Optional[int] = None):
        """Emit initial Config signal before interface is created (called from main thread).

        Note: We DON'T include tundev here because NetworkManager will try to look it up
        immediately and fail if it doesn't exist yet.
        """
        if connect_generation is not None and self._is_connect_cancelled(connect_generation):
            log.info(f"Skipping stale initial config for generation {connect_generation}")
            return False
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
        # Default off: a gateway-only Config makes NetworkManager advertise an
        # active VPN even though OpenConnect has not created a tunnel. Profiles
        # saved by the editor already have a 300-second activation timeout.
        if not os.environ.get("MS_SSO_NM_GP_CONFIG_DELAY", "").strip():
            return False
        return self._initial_config_delay_elapsed("GP", "MS_SSO_NM_GP_CONFIG_DELAY", 20)

    def _anyconnect_initial_config_allowed(self) -> bool:
        """Return True if AnyConnect gateway-only Config may be emitted during slow auth."""
        allow_early = os.environ.get("MS_SSO_NM_ANYCONNECT_EARLY_CONFIG", "").lower() in {"1", "true", "yes"}
        if allow_early:
            return True
        # Default off: NetworkManager can treat gateway-only Config/STARTED as a
        # half-connected VPN. That was worse for FHNW than a clean auth retry.
        if not os.environ.get("MS_SSO_NM_ANYCONNECT_CONFIG_DELAY", "").strip():
            return False
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
            # AnyConnect defaults to no pre-tunnel STARTED; this value only
            # matters when MS_SSO_NM_ANYCONNECT_EARLY_STARTED is explicitly set.
            return 45
        return 45

    def _should_emit_started_keepalive(self, protocol: str) -> bool:
        """Return True when we should send STARTED keepalive to avoid NM timeout."""
        if protocol == 'gp' and self._gp_early_started_enabled():
            return True
        if protocol == 'anyconnect':
            return self._is_truthy(os.environ.get("MS_SSO_NM_ANYCONNECT_EARLY_STARTED"))

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
        # Host-wide unmanaged routes are not crash-safe, so this is now opt-in.
        if not self._is_truthy(os.environ.get("MS_SSO_NM_BLOCK_IPV6", "0")):
            return

        try:
            # Persist ownership before creating the host-wide route.  If the
            # service is killed at any later instruction, either the service
            # startup recovery or the NM dispatcher can safely remove it.
            IPV6_LEAK_ROUTE_MARKER.parent.mkdir(parents=True, exist_ok=True)
            temporary = IPV6_LEAK_ROUTE_MARKER.with_name(
                f".{IPV6_LEAK_ROUTE_MARKER.name}.{os.getpid()}.tmp"
            )
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                0o600,
            )
            with os.fdopen(descriptor, "w", encoding="utf-8") as marker_file:
                marker_file.write(
                    "connection_uuid="
                    f"{self.current_connection_uuid or ''}\n"
                )
            os.replace(temporary, IPV6_LEAK_ROUTE_MARKER)

            result = subprocess.run(
                [
                    "ip",
                    "-6",
                    "route",
                    "add",
                    "unreachable",
                    "::/0",
                    "metric",
                    IPV6_LEAK_ROUTE_METRIC,
                    "proto",
                    IPV6_LEAK_ROUTE_PROTOCOL,
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )
            if result.returncode == 0:
                self.ipv6_leak_protection_enabled = True
                log.info(
                    "Enabled opt-in IPv6 leak protection with an owned route"
                )
            else:
                log.warning(
                    "Failed to enable IPv6 leak protection: "
                    f"{(result.stderr or result.stdout).strip()}"
                )
                # A failed add normally means no route was created.  Keep the
                # marker if the exact route exists or its absence cannot be
                # verified; recovery can then retry without losing ownership.
                if self._ipv6_leak_route_present() is False:
                    IPV6_LEAK_ROUTE_MARKER.unlink(missing_ok=True)
        except Exception as e:
            log.warning(f"Failed to enable IPv6 leak protection: {e}")

    @staticmethod
    def _ipv6_leak_route_present() -> Optional[bool]:
        """Return exact owned-route presence, or None when it cannot be read."""
        try:
            result = subprocess.run(
                [
                    "ip",
                    "-6",
                    "route",
                    "show",
                    "table",
                    "all",
                    "type",
                    "unreachable",
                    "::/0",
                    "metric",
                    IPV6_LEAK_ROUTE_METRIC,
                    "proto",
                    IPV6_LEAK_ROUTE_PROTOCOL,
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )
        except Exception as e:
            log.info(f"Could not inspect owned IPv6 leak route: {e}")
            return None
        if result.returncode != 0:
            log.info(
                "Could not inspect owned IPv6 leak route: "
                f"{(result.stderr or result.stdout).strip()}"
            )
            return None
        return bool(result.stdout.strip())

    def _clear_ipv6_leak_marker_if_route_absent(self) -> bool:
        """Clear ownership only after confirming the owned route is absent."""
        route_present = self._ipv6_leak_route_present()
        if route_present is not False:
            if route_present:
                log.warning("Owned IPv6 leak route still exists; preserving marker")
            else:
                log.warning(
                    "Could not verify IPv6 leak route removal; preserving marker"
                )
            return False
        self.ipv6_leak_protection_enabled = False
        try:
            IPV6_LEAK_ROUTE_MARKER.unlink(missing_ok=True)
        except Exception as e:
            log.info(f"Could not remove IPv6 leak-route marker: {e}")
            return False
        return True

    def _remove_stale_ipv6_leak_protection(self) -> None:
        """Remove only routes attributable to this plugin, including v2.0.3."""
        marker_exists = IPV6_LEAK_ROUTE_MARKER.exists()
        if marker_exists:
            self._run_recovery_command([
                "ip",
                "-6",
                "route",
                "del",
                "unreachable",
                "::/0",
                "metric",
                IPV6_LEAK_ROUTE_METRIC,
                "proto",
                IPV6_LEAK_ROUTE_PROTOCOL,
            ])
            self._clear_ipv6_leak_marker_if_route_absent()

        # Versions through 2.0.3 created this exact global route by default but
        # had no ownership marker.  Removing the exact signature once prevents
        # an earlier SIGKILL from requiring a reboot.
        try:
            result = subprocess.run(
                [
                    "ip",
                    "-6",
                    "route",
                    "del",
                    "unreachable",
                    "::/0",
                    "metric",
                    "50",
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )
            if result.returncode == 0:
                log.info("Removed legacy v2.0.3 IPv6 leak-protection route")
        except Exception as e:
            log.info(f"Could not remove legacy IPv6 leak route: {e}")

    def _remove_ipv6_leak_protection(self) -> None:
        """Remove the temporary IPv6 block route added for VPN leak protection."""
        if (
            not self.ipv6_leak_protection_enabled
            and not IPV6_LEAK_ROUTE_MARKER.exists()
        ):
            return
        self._run_recovery_command([
            "ip",
            "-6",
            "route",
            "del",
            "unreachable",
            "::/0",
            "metric",
            IPV6_LEAK_ROUTE_METRIC,
            "proto",
            IPV6_LEAK_ROUTE_PROTOCOL,
        ])
        self._clear_ipv6_leak_marker_if_route_absent()

    def _emit_starting_keepalive(self, connect_generation: Optional[int] = None):
        """Emit a keepalive STARTING state to reduce NM connect timeouts."""
        if connect_generation is not None and self._is_connect_cancelled(connect_generation):
            return False
        try:
            if self.state == NM_VPN_SERVICE_STATE_STARTED:
                log.warning(
                    "Refusing unsafe STARTED-to-STARTING transition in one activation"
                )
                return False
            if self.state != NM_VPN_SERVICE_STATE_STARTING:
                self._set_state(NM_VPN_SERVICE_STATE_STARTING)
            else:
                self.StateChanged(NM_VPN_SERVICE_STATE_STARTING)
        except Exception:
            pass
        return False

    def _emit_started_for_auth(self, connect_generation: Optional[int] = None):
        """Enter STARTED while authentication is still in progress.

        NetworkManager may cancel VPN connections that stay in STARTING too long.
        This is common for GlobalProtect SAML flows with MFA. We later emit the
        full Config/Ip4Config once the tunnel device exists.
        """
        if connect_generation is not None and self._is_connect_cancelled(connect_generation):
            return False
        try:
            self._set_state(NM_VPN_SERVICE_STATE_STARTED)
        except Exception:
            pass
        return False

    def _emit_started_keepalive(self, connect_generation: Optional[int] = None):
        """Emit a keepalive STARTED state."""
        if connect_generation is not None and self._is_connect_cancelled(connect_generation):
            return False
        try:
            # Keep local property state consistent with emitted signal.
            if self.state != NM_VPN_SERVICE_STATE_STARTED:
                self._set_state(NM_VPN_SERVICE_STATE_STARTED)
            else:
                self.StateChanged(NM_VPN_SERVICE_STATE_STARTED)
        except Exception:
            pass
        return False

    def _emit_connected(
            self,
            connect_generation: Optional[int] = None,
            vpn_process=None,
            tun_device: Optional[str] = None,
    ):
        """Emit IP config after interface is up (called from main thread)."""
        if (
            (connect_generation is not None and self._is_connect_cancelled(connect_generation))
            or (vpn_process is not None and vpn_process is not self.vpn_process)
        ):
            log.info(f"Skipping stale connected callback for generation {connect_generation}")
            return False

        try:
            # Get IP configuration from tun device
            tun_dev = tun_device or self.current_tun_device or 'tun0'
            gateway = self.current_gateway or ''

            log.info(f"Emitting config for {tun_dev}, gateway {gateway}")

            # Get IP address from interface
            ip_addr, prefix = self._get_tun_ipv4_config(tun_dev)
            log.info(f"Detected IP: {ip_addr}/{prefix}")
            if not ip_addr:
                log.warning(f"Refusing to emit connected state for {tun_dev}: no IPv4 address")
                try:
                    process = vpn_process or self.vpn_process
                    if process and process.poll() is None:
                        self._stop_vpn_process(
                            preserve_session=True,
                            force=True,
                            process=process,
                            connect_generation=connect_generation,
                        )
                except Exception:
                    pass
                self._emit_failure(
                    f"Tunnel {tun_dev} lost IPv4 before NetworkManager config",
                    connect_generation,
                )
                self.cancel_requested = True
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

            # Emit Ip4Config using NetworkManager's singular IPv4 keys.
            if ip_addr:
                # NetworkManager represents IPv4 values as a uint32 containing
                # the address in network byte order.
                ip_uint = self._ipv4_to_nm_uint32(ip_addr)

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

                # Do not copy the host's /etc/resolv.conf into VPN Ip4Config.
                # On systemd-resolved systems that is usually 127.0.0.53 and
                # feeding the local stub back as link DNS creates a resolver
                # loop.  If the VPN pushed no DNS, emit no VPN DNS and retain
                # NetworkManager's physical-link resolvers.

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

                ip4_config = dbus.Dictionary({
                    'address': dbus.UInt32(ip_uint),
                    'prefix': dbus.UInt32(prefix),
                    # OpenConnect's vpnc-script already owns the live kernel
                    # address and routes. Retain NetworkManager's prior route
                    # metadata and suppress its otherwise automatic second
                    # default route for the same tunnel.
                    'preserve-routes': dbus.Boolean(True),
                    'never-default': dbus.Boolean(True),
                    'dns': dbus.Array(dns_servers, signature='u') if dns_servers else dbus.Array([], signature='u'),
                    'domains': dbus.Array(dns_domains, signature='s'),
                }, signature='sv')
                self.Ip4Config(ip4_config)
                log.info(
                    f"Emitted Ip4Config signal: addr={ip_addr}/{prefix}, "
                    f"dns={len(dns_servers)} servers, domains={dns_domains}"
                )
                if self.current_protocol == 'anyconnect' and not self.vpn_tunnel_all_dns:
                    GLib.timeout_add_seconds(
                        1,
                        self._apply_split_dns_resolved,
                        tun_dev,
                        dns_domains,
                        connect_generation,
                    )
                    GLib.timeout_add_seconds(
                        3,
                        self._apply_split_dns_resolved,
                        tun_dev,
                        dns_domains,
                        connect_generation,
                    )

            self._apply_ipv6_leak_protection()

            # Now set state to started
            self._set_state(NM_VPN_SERVICE_STATE_STARTED)
        except Exception as e:
            log.error(f"Error emitting config: {e}")
            import traceback
            traceback.print_exc()
            self.cancel_requested = True
            try:
                process = vpn_process or self.vpn_process
                if process and process.poll() is None:
                    self._stop_vpn_process(
                        preserve_session=True,
                        force=True,
                        process=process,
                        connect_generation=connect_generation,
                    )
            except Exception:
                pass
            self._emit_failure(str(e))

        return False

    def _emit_disconnected(self, connect_generation: Optional[int] = None):
        """Emit disconnected state (called from main thread)."""
        if connect_generation is not None and self._is_connect_cancelled(connect_generation):
            return False
        self._set_state(NM_VPN_SERVICE_STATE_STOPPED)
        self._schedule_post_disconnect_recovery()
        return False

    def _emit_failure(self, message, connect_generation: Optional[int] = None):
        """Emit failure (called from main thread)."""
        if connect_generation is not None and self._is_connect_cancelled(connect_generation):
            log.info(f"Skipping stale failure callback for generation {connect_generation}")
            return False
        self.Failure(NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED)
        self._set_state(NM_VPN_SERVICE_STATE_STOPPED)
        self._schedule_post_disconnect_recovery()
        return False

    def _cleanup_leaked_vpn_dns_links(self):
        """Detect physical links that NetworkManager must reapply after teardown."""
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
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()
            log.info(f"Could not inspect resolved links for DNS cleanup: {detail}")
            return

        physical_uplinks = set(self.pre_vpn_uplinks)
        physical_uplinks.update(self._list_connected_uplinks())

        current_name = None
        current_lines = []

        def flush_current():
            if not current_name or current_name not in physical_uplinks:
                return
            body = "\n".join(current_lines)
            has_vpn_dns = any(server in body for server in vpn_dns)
            has_vpn_domain = any(domain in body for domain in vpn_domains)
            if not has_vpn_dns and not has_vpn_domain:
                return
            # `resolvectl revert` would also erase the DHCP-provided DNS for a
            # physical link.  Let NetworkManager reapply the connection instead.
            self._uplinks_needing_reapply.add(current_name)
            log.warning(
                "Detected VPN DNS state on physical uplink "
                f"{current_name}; scheduling NetworkManager reapply"
            )

        for line in result.stdout.splitlines():
            match = re.match(r"\s*Link\s+\d+\s+\(([^)]+)\)", line)
            if match:
                flush_current()
                current_name = match.group(1)
                current_lines = [line]
            elif current_name:
                current_lines.append(line)
        flush_current()

    def _cleanup_dns(self, recovery_token: Optional[int] = None) -> bool:
        """Serialize idempotent cleanup across D-Bus and worker callbacks."""
        cleanup_lock = getattr(self, "_cleanup_lock", None)
        if cleanup_lock is None:
            cleanup_lock = threading.RLock()
            self._cleanup_lock = cleanup_lock
        with cleanup_lock:
            if recovery_token is not None and (
                recovery_token != self._network_recovery_token
                or self.state in (
                    NM_VPN_SERVICE_STATE_STARTING,
                    NM_VPN_SERVICE_STATE_STARTED,
                )
            ):
                return False
            self._cleanup_owned_network_state()
            return True

    def _cleanup_owned_network_state(self):
        """Clear only DNS/routes/interfaces owned by this VPN activation."""
        self._remove_ipv6_leak_protection()
        self._cleanup_leaked_vpn_dns_links()

        owned_cleanup_devs = set(self.owned_tun_devices)
        had_owned_state = bool(owned_cleanup_devs)
        owned_ifindices = getattr(self, "owned_tun_ifindices", {})
        remaining_owned_ifindices = {}

        for tun_dev in sorted(owned_cleanup_devs):
            expected_ifindex = owned_ifindices.get(tun_dev)
            live_ifindex = self._link_ifindex(tun_dev)
            if (
                expected_ifindex is None
                or (
                    live_ifindex is not None
                    and live_ifindex != expected_ifindex
                )
            ):
                log.info(
                    "Skipping cleanup for tunnel name without matching ownership: "
                    f"{tun_dev} expected-ifindex={expected_ifindex} "
                    f"live-ifindex={live_ifindex}"
                )
                continue
            if shutil.which("resolvectl"):
                resolved_cleaned = self._run_recovery_command(
                    ["resolvectl", "revert", tun_dev]
                )
                if resolved_cleaned:
                    log.info(f"Reverted DNS settings for {tun_dev}")
            # Try openresolv independently.  NixOS can expose both commands,
            # and a successful resolvectl call does not remove resolvconf data.
            if shutil.which("resolvconf"):
                resolvconf_cleaned = self._run_recovery_command(
                    ["resolvconf", "-d", tun_dev]
                )
                if resolvconf_cleaned:
                    log.info(f"Removed resolvconf entry for {tun_dev}")

            # A vanished owned link still needs its name-keyed resolver entry
            # removed, but has no live routes/link to mutate.
            if live_ifindex is None:
                continue

            self._run_recovery_command(
                ["ip", "-4", "route", "flush", "dev", tun_dev]
            )
            self._run_recovery_command(
                ["ip", "-6", "route", "flush", "dev", tun_dev]
            )
            self._run_recovery_command(
                ["ip", "link", "delete", "dev", tun_dev]
            )
            remaining_ifindex = self._link_ifindex(tun_dev)
            if remaining_ifindex == expected_ifindex:
                remaining_owned_ifindices[tun_dev] = expected_ifindex
                log.warning(
                    "Owned tunnel still exists after cleanup; preserving "
                    f"recovery ownership for {tun_dev} ifindex={expected_ifindex}"
                )

        # Clear captured VPN metadata, but retain exact ownership when deletion
        # failed so a later recovery pass/dispatcher can retry safely.
        self.vpn_dns_servers = []
        self.vpn_domains = []
        self.vpn_tunnel_all_dns = None
        self.vpn_split_excludes = []
        self.vpn_split_includes = []
        self.owned_tun_ifindices = remaining_owned_ifindices
        self.owned_tun_devices = set(remaining_owned_ifindices)
        self.current_tun_device = next(
            iter(sorted(self.owned_tun_devices)),
            None,
        )
        try:
            if self.vpn_process and self.vpn_process.poll() is not None:
                if not self.owned_tun_devices:
                    self._clear_openconnect_state(self.vpn_process)
                self.vpn_process = None
                self.vpn_process_generation = None
            elif (
                not self.vpn_process
                and had_owned_state
                and not self.owned_tun_devices
            ):
                self._clear_openconnect_state()
        except Exception:
            pass

    # D-Bus methods
    @dbus.service.method(NM_VPN_DBUS_PLUGIN_INTERFACE,
                         in_signature='a{sa{sv}}', out_signature='')
    def Connect(self, connection):
        """Start VPN connection."""
        log.info("Connect called")
        self._reset_inactivity_timeout()

        recovery_thread = self._network_recovery_thread

        # Never overlap two activations that share process/tunnel/DNS state.
        # Failing the second request cleanly is safer than letting an old worker
        # delete or reapply resources under a new tunnel.
        cleanup_lock = getattr(self, "_cleanup_lock", None) or threading.RLock()
        self._cleanup_lock = cleanup_lock
        with cleanup_lock:
            previous_thread_alive = bool(
                self.connection_thread and self.connection_thread.is_alive()
            )
            previous_process_alive = bool(
                self.vpn_process and self.vpn_process.poll() is None
            )
            self.cancel_requested = True
            self._connect_generation += 1
            self._network_recovery_token += 1
            connect_generation = self._connect_generation

        if previous_thread_alive or previous_process_alive:
            log.error(
                "Rejecting overlapping Connect request; ending the existing "
                "activation before NetworkManager retries"
            )
            if previous_process_alive:
                self._stop_vpn_process(preserve_session=True, force=True)
            self._emit_failure("Overlapping VPN activation rejected")
            return

        self._set_state(NM_VPN_SERVICE_STATE_STARTING)

        # Convert D-Bus types to Python
        settings = {str(k): {str(k2): v2 for k2, v2 in v.items()} for k, v in connection.items()}

        # Start connection in the background.  If a prior recovery command is
        # already in flight, the coordinator waits for it off the D-Bus thread
        # before starting browser authentication or OpenConnect.
        if recovery_thread and recovery_thread.is_alive():
            thread_target = self._connect_after_recovery
            thread_args = (recovery_thread, settings, connect_generation)
        else:
            thread_target = self._connect_thread
            thread_args = (settings, connect_generation)
        self.connection_thread = threading.Thread(
            target=thread_target,
            args=thread_args,
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

        if self.state in (
            NM_VPN_SERVICE_STATE_STOPPED,
            NM_VPN_SERVICE_STATE_SHUTDOWN,
        ):
            log.info("Disconnect is already complete")
            if self.state == NM_VPN_SERVICE_STATE_STOPPED:
                self._schedule_post_disconnect_recovery()
            return

        self._set_state(NM_VPN_SERVICE_STATE_STOPPING)

        # Use SIGHUP so openconnect preserves the session cookie but still runs
        # vpnc-script cleanup for routes and DNS.
        if self.vpn_process and self.vpn_process.poll() is None:
            log.info("Stopping openconnect with SIGHUP to preserve session cookie")
            self._stop_vpn_process(preserve_session=True, force=True)

        worker = self.connection_thread
        if worker and worker.is_alive() and worker is not threading.current_thread():
            worker.join(timeout=3)
            if worker.is_alive():
                log.warning(
                    "Connection worker is still unwinding after cancellation; "
                    "its generation is invalidated"
                )

        self._set_state(NM_VPN_SERVICE_STATE_STOPPED)
        # NetworkManager must first withdraw Config/Ip4Config for the old
        # tunnel.  The delayed pass then removes only generation-owned residue,
        # verifies physical routing/DNS, and repairs NM state if necessary.
        self._schedule_post_disconnect_recovery()

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
        try:
            mainloop.run()
        finally:
            # GLib timers do not run after quit.  Keep process-exit cleanup
            # synchronous so SIGTERM/service replacement cannot strand an
            # owned tunnel, DNS link, or opt-in IPv6 block route.
            self.cancel_requested = True
            self._connect_generation += 1
            try:
                if self.vpn_process and self.vpn_process.poll() is None:
                    self._stop_vpn_process(
                        preserve_session=True,
                        force=True,
                        process=self.vpn_process,
                    )
            except Exception:
                pass
            self._cleanup_dns()
            self._network_recovery_reload_attempted = False
            if not self._recover_base_network_once(reactivate=True):
                log.error("Base network was not yet healthy when the service exited")


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
