"""SAML authentication via headless Playwright with heuristic form handling."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import ssl
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
import unicodedata
import xml.etree.ElementTree as ET
from typing import Callable, Optional

from playwright.sync_api import sync_playwright

from .platform_info import get_gp_client_os, get_gp_os_version
from .totp import generate_totp, seconds_until_totp_rotation


MICROSOFT_TOTP_DIRECT_SELECTORS = (
    "#idA_SAASTO_TOTP",
    "[data-value='PhoneAppOTP']",
    "[data-value='SoftwareOath']",
)

MICROSOFT_MFA_TRANSITION_TIMEOUT_SECONDS = 25.0
MICROSOFT_METHOD_PICKER_SETTLE_SECONDS = 1.5
MICROSOFT_PASSWORD_STABILITY_SECONDS = 0.5
MICROSOFT_TOTP_MAX_SUBMISSIONS = 2
SAML_UI_STALL_WINDOW_SECONDS = 8.0
SAML_UI_POST_SUBMIT_GRACE_SECONDS = 20.0
SAML_UI_PROCESSING_EXTENSION_SECONDS = 10.0
SAML_UI_MAX_PROCESSING_EXTENSIONS = 6
SAML_UI_MAX_SUBMIT_WAIT_SECONDS = 180.0
SAML_UI_MAX_RECOVERIES = 1

MICROSOFT_TOTP_METHOD_LABELS = (
    "Use a verification code",
    "Enter a verification code",
    "Use a code from my authenticator app",
    "Use a code from your authenticator app",
    "Use a verification code from my mobile app",
    "Code aus meiner Microsoft Authenticator-App verwenden",
    "Prüfcode aus meiner mobilen App verwenden",
    "Prüfcode verwenden",
    "Bestätigungscode verwenden",
    "Einen Prüfcode verwenden",
    "Code aus der Authenticator-App verwenden",
)

MICROSOFT_ALTERNATE_MFA_LABELS = (
    "I can't use my Microsoft Authenticator app right now",
    "Sign in another way",
    "Other ways to sign in",
    "Sign-in options",
    "Use a different verification option",
    "Use another verification method",
    "Use a different method",
    "Ich kann meine Microsoft Authenticator-App im Moment nicht verwenden",
    "Auf andere Weise anmelden",
    "Andere Anmeldemöglichkeiten",
    "Anmeldeoptionen",
    "Andere Möglichkeit zur Anmeldung",
    "Andere Überprüfungsoption verwenden",
    "Andere Methode verwenden",
    "Weitere Anmeldemethoden",
)

MICROSOFT_ALTERNATE_MFA_SELECTORS = (
    "#idA_SAASTO_Proofs",
    "#idA_SAOTCS_SwitchProof",
    "#idA_SAASTO_SwitchProof",
    "#idA_PWD_SwitchToCredPicker",
)

MICROSOFT_PUSH_DIRECT_SELECTORS = (
    "[data-value='PhoneAppNotification']",
    "[data-value='PhoneAppNotificationWithCode']",
)

MICROSOFT_PUSH_METHOD_LABELS = (
    "Approve a request on my Microsoft Authenticator app",
    "Send a notification to my Microsoft Authenticator app",
    "Microsoft Authenticator notification",
    "Anforderung in meiner Microsoft Authenticator-App genehmigen",
    "Benachrichtigung an meine Microsoft Authenticator-App senden",
    "Microsoft Authenticator-Benachrichtigung",
    "Eine Anforderung in meiner Microsoft Authenticator-App bestätigen",
)

MICROSOFT_PASSWORD_METHOD_LABELS = (
    "Use my password",
    "Use your password instead",
    "Use password instead",
    "Sign in with your password",
    "Stattdessen Kennwort verwenden",
    "Mit Kennwort anmelden",
    "Mit Ihrem Kennwort anmelden",
    "Mein Kennwort verwenden",
    "Stattdessen Ihr Kennwort verwenden",
)

MICROSOFT_PASSWORD_DIRECT_SELECTORS = (
    "#idA_PWD_SwitchToPassword",
)

MICROSOFT_PASSKEY_MARKERS = (
    "Use your passkey",
    "Sign in with a passkey",
    "Face, fingerprint, PIN, or security key",
    "Passkey verwenden",
    "Mit einem Passkey anmelden",
    "Gesichtserkennung, Fingerabdruck, PIN oder Sicherheitsschlüssel",
    "Mit Ihrem Passkey anmelden",
    "Mit einem Hauptschlüssel anmelden",
    "Anmeldung mit einem Hauptschlüssel",
    "Gesicht, Fingerabdruck, PIN oder Sicherheitsschlüssel",
)

MICROSOFT_CREDENTIAL_ERROR_MARKERS = (
    "Your account or password is incorrect",
    "Your password is incorrect",
    "The user name or password is incorrect",
    "Enter a valid password",
    "Incorrect user ID or password",
    "Ihr Konto oder Kennwort ist falsch",
    "Das Kennwort ist falsch",
    "Benutzername oder Kennwort ist falsch",
    "Geben Sie ein gültiges Kennwort ein",
)

MICROSOFT_NUMBER_MATCH_MARKERS = (
    "Enter the number shown to sign in",
    "Geben Sie die Nummer ein",
    "Geben Sie die angezeigte Zahl ein",
)

MICROSOFT_AUTHENTICATOR_PUSH_MARKERS = (
    "Approve sign in request",
    "Approve a sign-in request",
    "Anmeldeanforderung bestätigen",
    "Anmeldeanforderung genehmigen",
)

MICROSOFT_NUMBER_MATCH_SELECTORS = (
    "#idRichContext_DisplaySign",
    "[data-testid='displaySign']",
    "[data-test-id='displaySign']",
    ".displaySign",
)

MICROSOFT_PASSKEY_REGISTRATION_MARKERS = (
    "Set up a passkey",
    "Create a passkey",
    "Passkey einrichten",
    "Passkey erstellen",
)

MICROSOFT_SKIP_OPTIONAL_LABELS = (
    "Skip for now",
    "Not now",
    "Maybe later",
    "Vorerst überspringen",
    "Jetzt nicht",
    "Später",
)

MICROSOFT_KMSI_MARKERS = (
    "Stay signed in",
    "Angemeldet bleiben",
    "Rester connecté",
    "Rimanere connesso",
    "Mantener la sesión iniciada",
)

MICROSOFT_KMSI_ACCEPT_LABELS = (
    "Yes",
    "Ja",
    "Oui",
    "Sì",
    "Sí",
)


class SamlUiStalledError(RuntimeError):
    """Raised when the browser login UI remains unchanged after recovery."""


def _normalize_session_identity(value: Optional[str]) -> str:
    """Normalize a cache identity component without exposing it in a path."""
    return unicodedata.normalize("NFKC", str(value or "")).strip().casefold()


def _normalize_gateway_identity(gateway: Optional[str]) -> str:
    """Return a stable host/port identity for a VPN gateway."""
    text = unicodedata.normalize("NFKC", str(gateway or "")).strip()
    try:
        parsed = urllib.parse.urlsplit(text if "://" in text else f"//{text}")
        host = (parsed.hostname or text).strip().rstrip(".").casefold()
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            pass
        try:
            port = parsed.port
        except ValueError:
            port = None
        if port and port != 443:
            return f"{host}:{port}"
        return host
    except Exception:
        return text.rstrip(".").casefold()


def _browser_session_cache_key(
    protocol: Optional[str],
    gateway: Optional[str],
    username: Optional[str],
) -> str:
    """Return an opaque deterministic key for one VPN/account browser profile."""
    identity = json.dumps(
        [
            _normalize_session_identity(protocol),
            _normalize_gateway_identity(gateway),
            _normalize_session_identity(username),
        ],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    # Bump the opaque namespace when browser-profile semantics change so an
    # upgrade cannot inherit a pre-fix Microsoft page that was mid-transition.
    return f"v2-{hashlib.sha256(identity.encode('utf-8')).hexdigest()}"


def _is_actionable_control(
    tag_name: Optional[str],
    role: Optional[str] = None,
    input_type: Optional[str] = None,
    disabled: bool = False,
    has_href: bool = False,
    has_click_handler: bool = False,
    has_data_value: bool = False,
    tab_index: Optional[int] = None,
    pointer_cursor: bool = False,
) -> bool:
    """Classify semantic and non-semantic controls that are genuinely interactive."""
    if disabled:
        return False
    tag = str(tag_name or "").strip().casefold()
    normalized_role = str(role or "").strip().casefold()
    normalized_type = str(input_type or "").strip().casefold()
    return (
        normalized_role in {"button", "link"}
        or tag == "button"
        or (tag == "a" and has_href)
        or (tag == "input" and normalized_type in {"button", "submit"})
        or has_click_handler
        or has_data_value
        or (tab_index is not None and tab_index >= 0)
        or pointer_cursor
    )


def _exact_action_pattern(label: str) -> re.Pattern:
    """Match one complete control label, ignoring case and edge whitespace."""
    return re.compile(rf"^\s*{re.escape(str(label or '').strip())}\s*$", re.IGNORECASE)


def _allows_partial_action_label(label: str) -> bool:
    """Allow partial matching only for long labels specific enough to be safe."""
    return len(str(label or "").strip()) >= 12


def _action_patterns(labels) -> list[re.Pattern]:
    """Prefer exact labels, then permit specific long-label variants."""
    patterns = [_exact_action_pattern(label) for label in labels]
    patterns.extend(
        re.compile(re.escape(str(label).strip()), re.IGNORECASE)
        for label in labels
        if _allows_partial_action_label(label)
    )
    return patterns


def _stale_ui_recovery_action(
    last_substantive_progress: float,
    now: float,
    recovery_attempts: int,
    grace_until: float = 0.0,
    stall_window: float = SAML_UI_STALL_WINDOW_SECONDS,
    max_recoveries: int = SAML_UI_MAX_RECOVERIES,
) -> str:
    """Choose a bounded recovery action based only on substantive UI progress."""
    if now < grace_until or now - last_substantive_progress < max(0.0, stall_window):
        return "wait"
    return "recover" if recovery_attempts < max(0, max_recoveries) else "fail"


def _extend_processing_grace(
    now: float,
    grace_until: float,
    processing_visible: bool,
    extensions_used: int,
    extension_seconds: float = SAML_UI_PROCESSING_EXTENSION_SECONDS,
    max_extensions: int = SAML_UI_MAX_PROCESSING_EXTENSIONS,
    hard_deadline: Optional[float] = None,
) -> tuple[float, int]:
    """Progressively extend an expired grace while submitted UI is unresolved."""
    if (
        not processing_visible
        or now < grace_until
        or (hard_deadline is not None and now >= hard_deadline)
        or extensions_used >= max(0, max_extensions)
    ):
        return grace_until, extensions_used
    # Back off from the fast initial check without imposing the longest wait on
    # ordinary logins: 10s, 20s, 30s, 40s, 50s, then 60s as needed.
    next_extension = max(0.0, extension_seconds) * (extensions_used + 1)
    next_deadline = now + next_extension
    if hard_deadline is not None:
        next_deadline = min(next_deadline, hard_deadline)
    return next_deadline, extensions_used + 1


def _submission_hard_deadline(
    submitted_at: float,
    auth_deadline: float,
    max_wait_seconds: float = SAML_UI_MAX_SUBMIT_WAIT_SECONDS,
) -> float:
    """Clamp one submitted form to both its own cap and the auth deadline."""
    return min(auth_deadline, submitted_at + max(0.0, max_wait_seconds))


def _remaining_timeout_ms(deadline: float, now: Optional[float] = None) -> int:
    """Return the non-negative milliseconds remaining before a monotonic deadline."""
    current_time = time.monotonic() if now is None else now
    return max(0, int((deadline - current_time) * 1000))


def _standalone_two_digit_numbers(text: Optional[str]) -> set[str]:
    """Return unique standalone two-digit lines from rendered prompt text."""
    numbers = set()
    for line in (text or "").splitlines():
        match = re.fullmatch(r"\s*([0-9]{2})\s*", line)
        if match:
            numbers.add(match.group(1))
    return numbers


def _prefer_totp_for_number_match(
    mfa_preference: str,
    totp_available: bool,
    totp_disabled: bool,
) -> bool:
    """Prefer a stored TOTP unless phone approval was explicitly requested."""
    return mfa_preference != "push" and totp_available and not totp_disabled


def _should_notify_number_match(
    mfa_preference: str,
    totp_available: bool,
) -> bool:
    """Use phone approval only explicitly, or when adaptive mode has no TOTP."""
    return mfa_preference == "push" or (
        mfa_preference == "auto" and not totp_available
    )


def _has_number_match_evidence(
    marker_visible: bool,
    selector_visible: bool,
) -> bool:
    """Recognize number matching from either wording or Microsoft's stable control."""
    return marker_visible or selector_visible


def _adaptive_mfa_action(
    prefer_totp: bool,
    otp_input_visible: bool,
    authenticator_challenge_visible: bool,
    totp_choice_visible: bool,
    picker_transition_pending: bool,
) -> str:
    """Choose the next adaptive action without ever preferring phone over TOTP."""
    if prefer_totp and otp_input_visible:
        return "submit-totp"
    if not authenticator_challenge_visible:
        return "select-totp" if prefer_totp and totp_choice_visible else "none"
    if not prefer_totp:
        return "phone"
    if totp_choice_visible:
        return "select-totp"
    if picker_transition_pending:
        return "wait-for-picker"
    return "open-alternate-methods"


def _should_submit_totp_counter(
    last_submitted_counter: Optional[int],
    current_counter: int,
) -> bool:
    """Submit once per TOTP window and allow a fresh window to recover a stall."""
    return (
        last_submitted_counter is None
        or last_submitted_counter != current_counter
    )


def _merge_saml_artifacts(
    cookies: dict[str, str],
    saml_result: dict,
    protocol: str,
    gp_prelogin_cookie: Optional[str] = None,
    gp_gateway_ip: Optional[str] = None,
) -> dict[str, str]:
    """Merge captured SAML/GP headers without dropping their paired username."""
    merged = dict(cookies)
    if saml_result.get("saml_response"):
        merged["SAMLResponse"] = saml_result["saml_response"]
    if saml_result.get("prelogin_cookie"):
        merged["prelogin-cookie"] = saml_result["prelogin_cookie"]
    if protocol == "gp":
        if saml_result.get("portal_userauthcookie"):
            merged["portal-userauthcookie"] = saml_result["portal_userauthcookie"]
        if saml_result.get("saml_username"):
            merged["saml-username"] = saml_result["saml_username"]
        if gp_prelogin_cookie and "prelogin-cookie" not in merged:
            merged["prelogin-cookie"] = gp_prelogin_cookie
        if gp_gateway_ip:
            merged["_gateway_ip"] = gp_gateway_ip
    return merged


def _parse_saml_timeout(protocol: str, value: Optional[str] = None) -> int:
    """Return a safe SAML timeout for the selected protocol."""
    default_timeout = 180 if protocol == "gp" else 120
    raw_value = os.environ.get("MS_SSO_SAML_TIMEOUT", "") if value is None else value
    try:
        timeout = int(str(raw_value).strip()) if str(raw_value).strip() else default_timeout
    except (TypeError, ValueError):
        timeout = default_timeout
    if timeout <= 0:
        timeout = default_timeout
    return max(timeout, 180) if protocol == "gp" else timeout


def _detect_desktop_user() -> Optional[str]:
    """Return the unique active, local graphical user reported by logind."""
    try:
        result = subprocess.run(
            ["loginctl", "list-sessions", "--no-legend"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode != 0:
            return None

        candidates = set()
        for line in result.stdout.splitlines():
            parts = line.split()
            if not parts:
                continue
            session_id = parts[0]
            details = subprocess.run(
                [
                    "loginctl",
                    "show-session",
                    session_id,
                    "-p", "Active",
                    "-p", "Remote",
                    "-p", "Type",
                    "-p", "Class",
                    "-p", "User",
                    "-p", "Name",
                    "--no-pager",
                ],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if details.returncode != 0:
                continue
            properties = {}
            for property_line in details.stdout.splitlines():
                key, separator, value = property_line.partition("=")
                if separator:
                    properties[key] = value
            try:
                uid = int(properties.get("User", "-1"))
            except ValueError:
                continue
            if (
                properties.get("Active") == "yes"
                and properties.get("Remote") == "no"
                and properties.get("Type") in {"wayland", "x11"}
                and properties.get("Class") == "user"
                and uid >= 1000
                and properties.get("Name")
            ):
                candidates.add(properties["Name"])
        return next(iter(candidates)) if len(candidates) == 1 else None
    except Exception:
        return None


def _get_gp_prelogin(
    server: str,
    debug: bool = False,
    gp_os_version: Optional[str] = None,
    gp_auth_interface: str = "portal",
) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """Get prelogin-cookie and SAML request for GlobalProtect."""
    gp_auth_interface = str(gp_auth_interface or "portal").strip().lower()
    if gp_auth_interface not in {"portal", "gateway"}:
        gp_auth_interface = "portal"
    prelogin_path = (
        "ssl-vpn/prelogin.esp"
        if gp_auth_interface == "gateway"
        else "global-protect/prelogin.esp"
    )
    url = f"https://{server}/{prelogin_path}"
    retry_env = os.environ.get("MS_SSO_GP_PRELOGIN_RETRIES", "3").strip()
    delay_env = os.environ.get("MS_SSO_GP_PRELOGIN_DELAY", "2").strip()
    client_os = get_gp_client_os()
    os_version = gp_os_version or get_gp_os_version()
    host_id = socket.gethostname() or "localhost"
    request_params = {
        "tmp": "tmp",
        "clientVer": "4100",
        "clientos": client_os,
        "os-version": os_version,
        "host-id": host_id,
        "ipv6-support": "yes",
        "default-browser": "1",
        "cas-support": "yes",
    }
    request_body = urllib.parse.urlencode(request_params).encode("utf-8")
    try:
        retries = max(1, int(retry_env))
    except Exception:
        retries = 3
    try:
        retry_delay = max(0.0, float(delay_env))
    except Exception:
        retry_delay = 2.0

    last_err = None
    for attempt in range(1, retries + 1):
        try:
            ctx = ssl.create_default_context()
            req = urllib.request.Request(url, data=request_body, method="POST")
            req.add_header("User-Agent", "PAN GlobalProtect")
            req.add_header("Content-Type", "application/x-www-form-urlencoded")
            with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
                if resp.status != 200:
                    raise Exception(f"prelogin.esp returned HTTP {resp.status}")
                content = resp.read().decode("utf-8")
                root = ET.fromstring(content)
                prelogin_cookie = None
                saml_request = None
                gateway_ip = None
                for elem in root.iter():
                    if elem.tag == "prelogin-cookie":
                        prelogin_cookie = elem.text
                    elif elem.tag == "saml-request":
                        saml_request = elem.text
                    elif elem.tag == "server-ip":
                        gateway_ip = elem.text
                return prelogin_cookie, saml_request, gateway_ip
        except Exception as e:
            last_err = e
            if debug:
                print(f"[DEBUG] prelogin.esp error (attempt {attempt}/{retries}): {e}")
            if attempt < retries:
                time.sleep(retry_delay)

    # Some portals are stricter and still expect the legacy GET prelogin call.
    fallback_url = f"{url}?{urllib.parse.urlencode(request_params)}"
    try:
        ctx = ssl.create_default_context()
        req = urllib.request.Request(fallback_url)
        req.add_header("User-Agent", "PAN GlobalProtect")
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            if resp.status != 200:
                raise Exception(f"legacy prelogin.esp returned HTTP {resp.status}")
            content = resp.read().decode("utf-8")
            root = ET.fromstring(content)
            prelogin_cookie = None
            saml_request = None
            gateway_ip = None
            for elem in root.iter():
                if elem.tag == "prelogin-cookie":
                    prelogin_cookie = elem.text
                elif elem.tag == "saml-request":
                    saml_request = elem.text
                elif elem.tag == "server-ip":
                    gateway_ip = elem.text
            if debug:
                print(
                    "[DEBUG] Falling back to legacy GP prelogin request "
                    f"(clientos={client_os}, os-version={os_version}, host-id={host_id})"
                )
            return prelogin_cookie, saml_request, gateway_ip
    except Exception as fallback_err:
        last_err = fallback_err

    if debug and last_err is not None:
        print(f"[DEBUG] prelogin.esp failed after {retries} attempts: {last_err}")
    return None, None, None


def do_saml_auth(
    vpn_server: str,
    username: str,
    password: str,
    totp_secret: Optional[str] = None,
    protocol: str = "anyconnect",
    auto_totp: bool = True,
    headless: bool = True,
    debug: bool = False,
    vpn_server_ip: Optional[str] = None,
    disable_browser_session_cache: bool = False,
    gp_os_version: Optional[str] = None,
    gp_auth_interface: str = "portal",
    cancel_callback: Optional[Callable[[], bool]] = None,
    progress_callback: Optional[Callable[[str], None]] = None,
    mfa_preference: Optional[str] = None,
    notification_helper_path: Optional[str] = None,
):
    """Complete Microsoft SAML authentication and return cookies."""
    last_reported_progress = None
    vpn_server_raw = vpn_server
    try:
        parsed_server = urllib.parse.urlparse(vpn_server_raw if "://" in vpn_server_raw else f"//{vpn_server_raw}")
        vpn_server_host = parsed_server.hostname or vpn_server_raw
        vpn_server_netloc = parsed_server.netloc or vpn_server_raw
    except Exception:
        vpn_server_host = vpn_server_raw
        vpn_server_netloc = vpn_server_raw

    vpn_url = f"https://{vpn_server_netloc}"
    mfa_preference = str(
        mfa_preference or os.environ.get("MS_SSO_MFA_PREFERENCE") or "auto"
    ).strip().lower()
    if mfa_preference not in {"auto", "totp", "push"}:
        mfa_preference = "auto"

    def _cancelled() -> bool:
        if not cancel_callback:
            return False
        try:
            return bool(cancel_callback())
        except Exception:
            return False

    def _raise_if_cancelled() -> None:
        if _cancelled():
            raise RuntimeError("SAML authentication cancelled")

    def _report_progress(event: str) -> None:
        """Report privacy-safe flow state without credentials, codes, or URLs."""
        nonlocal last_reported_progress
        if not progress_callback:
            return
        if event == last_reported_progress:
            return
        try:
            progress_callback(event)
            last_reported_progress = event
        except Exception:
            pass

    gp_prelogin_cookie, gp_saml_request, gp_gateway_ip = None, None, None
    if protocol == "gp":
        print("  [1/6] Getting GlobalProtect prelogin info...")
        gp_prelogin_cookie, gp_saml_request, gp_gateway_ip = _get_gp_prelogin(
            vpn_server,
            debug,
            gp_os_version=gp_os_version,
            gp_auth_interface=gp_auth_interface,
        )
        if debug:
            print(f"    [DEBUG] prelogin-cookie present: {bool(gp_prelogin_cookie)}")
            print(f"    [DEBUG] gateway_ip: {gp_gateway_ip}")
    else:
        print("  [1/6] Using AnyConnect SAML URL...")

    real_user = os.environ.get("SUDO_USER", os.environ.get("USER", "root"))
    home = os.path.expanduser("~")

    def _is_truthy(value) -> bool:
        if isinstance(value, bool):
            return value
        if value is None:
            return False
        return str(value).strip().lower() in {"1", "true", "yes", "on"}

    def _ensure_writable_dir(path: str) -> bool:
        try:
            os.makedirs(path, exist_ok=True)
            probe = os.path.join(path, ".write-test")
            with open(probe, "w", encoding="utf-8") as f:
                f.write("ok")
            os.remove(probe)
            return True
        except OSError:
            return False

    def _looks_like_playwright_browser_dir(path: str) -> bool:
        try:
            return any(
                entry.startswith(("chromium-", "chromium_headless_shell-", "firefox-", "webkit-"))
                for entry in os.listdir(path)
            )
        except OSError:
            return False

    def _install_playwright_chromium(browser_path: str) -> bool:
        if _is_truthy(os.environ.get("MS_SSO_DISABLE_PLAYWRIGHT_AUTO_INSTALL")):
            return False

        env = os.environ.copy()
        env["PLAYWRIGHT_BROWSERS_PATH"] = browser_path
        commands = []
        playwright_bin = shutil.which("playwright")
        if playwright_bin:
            commands.append([playwright_bin, "install", "chromium"])
        commands.append([sys.executable, "-m", "playwright", "install", "chromium"])

        os.makedirs(browser_path, exist_ok=True)
        for command in commands:
            try:
                if debug:
                    print(f"    [DEBUG] Installing Playwright Chromium into {browser_path}: {' '.join(command)}")
                result = subprocess.run(
                    command,
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=300,
                    check=False,
                )
                if result.returncode == 0:
                    return True
                if debug:
                    output = (result.stderr or result.stdout or "").strip()
                    print(f"    [DEBUG] Playwright install failed ({result.returncode}): {output}")
            except Exception as e:
                if debug:
                    print(f"    [DEBUG] Playwright install command failed: {e}")
        return False

    force_ephemeral_browser_session = (
        _is_truthy(disable_browser_session_cache)
        or _is_truthy(os.environ.get("MS_SSO_DISABLE_BROWSER_SESSION_CACHE"))
    )

    if real_user == "root":
        detected_user = _detect_desktop_user()
        if detected_user:
            real_user = detected_user
            if debug:
                print(f"    [DEBUG] Detected desktop user: {real_user}")
    if real_user != "root":
        try:
            import pwd
            home = pwd.getpwnam(real_user).pw_dir
        except Exception:
            pass

    number_match_notification_id = 0

    def _notification_request(request: dict) -> Optional[int]:
        """Run the unprivileged notification helper with data on stdin only."""
        helper_path = (
            os.environ.get("MS_SSO_NOTIFICATION_HELPER", "").strip()
            or (notification_helper_path or "").strip()
        )
        if not helper_path or not os.path.isfile(helper_path):
            return None
        try:
            import pwd

            account = pwd.getpwnam(real_user)
            runtime_dir = f"/run/user/{account.pw_uid}"
            user_bus = os.path.join(runtime_dir, "bus")
            if not os.path.exists(user_bus):
                return None
            safe_path = os.environ.get(
                "PATH",
                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            )
            notification_env = {
                "PATH": safe_path,
                "HOME": account.pw_dir,
                "USER": account.pw_name,
                "LOGNAME": account.pw_name,
                "XDG_RUNTIME_DIR": runtime_dir,
                "DBUS_SESSION_BUS_ADDRESS": f"unix:path={user_bus}",
                "LANG": os.environ.get("LANG", "C.UTF-8"),
            }

            if os.geteuid() == 0 and account.pw_uid != 0:
                runuser = shutil.which("runuser")
                env_bin = shutil.which("env")
                if not runuser or not env_bin:
                    return None
                command = [
                    runuser,
                    "-u",
                    account.pw_name,
                    "--",
                    env_bin,
                    "-i",
                    f"PATH={safe_path}",
                    f"HOME={account.pw_dir}",
                    f"USER={account.pw_name}",
                    f"LOGNAME={account.pw_name}",
                    f"XDG_RUNTIME_DIR={runtime_dir}",
                    f"DBUS_SESSION_BUS_ADDRESS=unix:path={user_bus}",
                    f"LANG={notification_env['LANG']}",
                    helper_path,
                ]
            else:
                command = [helper_path]

            result = subprocess.run(
                command,
                input=json.dumps(request),
                env=notification_env,
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if result.returncode != 0:
                return None
            notification_id = int(result.stdout.strip())
            return notification_id if 0 <= notification_id <= 0xFFFFFFFF else None
        except Exception:
            return None

    def _notify_number_match(number: str) -> bool:
        nonlocal number_match_notification_id
        if not re.fullmatch(r"[0-9]{2}", number or ""):
            return False
        notification_id = _notification_request({
            "action": "show",
            "code": number,
            "replaces_id": number_match_notification_id,
        })
        if notification_id is None:
            return False
        number_match_notification_id = notification_id
        return True

    def _close_number_match_notification() -> None:
        nonlocal number_match_notification_id
        if not number_match_notification_id:
            return
        _notification_request({
            "action": "close",
            "id": number_match_notification_id,
        })
        number_match_notification_id = 0

    browser_path_candidates = []
    existing_env_browser_path = os.environ.get("PLAYWRIGHT_BROWSERS_PATH")
    if existing_env_browser_path:
        browser_path_candidates.append(existing_env_browser_path)
    if home:
        browser_path_candidates.append(os.path.join(home, ".cache", "ms-playwright"))
    browser_path_candidates.extend([
        "/var/cache/ms-playwright",
        "/opt/ms-playwright",
        "/usr/share/ms-playwright",
    ])

    for browser_path in browser_path_candidates:
        if _looks_like_playwright_browser_dir(browser_path):
            os.environ["PLAYWRIGHT_BROWSERS_PATH"] = browser_path
            if debug:
                print(f"    [DEBUG] Using Playwright browsers from: {browser_path}")
            break

    with sync_playwright() as p:
        _raise_if_cancelled()
        session_tmp_dir = None
        if force_ephemeral_browser_session:
            session_tmp_dir = tempfile.mkdtemp(prefix="ms-sso-openconnect-auth-")
            cache_dir = session_tmp_dir
            if debug:
                print(f"    [DEBUG] Using ephemeral browser session dir: {cache_dir}")
        else:
            cache_dir = None
            cache_roots = []
            if real_user != "root":
                cache_roots.append(
                    os.path.join(home, ".cache", "ms-sso-openconnect", "browser-session")
                )
            cache_roots.extend([
                "/var/cache/ms-sso-openconnect/browser-session",
                "/tmp/ms-sso-openconnect/browser-session",
            ])
            cache_key = _browser_session_cache_key(
                protocol,
                vpn_server_netloc,
                username,
            )

            for root in cache_roots:
                candidate = os.path.join(root, cache_key)
                if _ensure_writable_dir(candidate):
                    cache_dir = candidate
                    if debug:
                        print(f"    [DEBUG] Using browser session dir: {cache_dir}")
                    break

            if not cache_dir:
                session_tmp_dir = tempfile.mkdtemp(prefix="ms-sso-openconnect-auth-")
                cache_dir = os.path.join(session_tmp_dir, "browser-session")
                os.makedirs(cache_dir, exist_ok=True)
                if debug:
                    print(f"    [DEBUG] Falling back to temporary browser session dir: {cache_dir}")

        def _chromium_executable_path() -> Optional[str]:
            configured = os.environ.get("MS_SSO_PLAYWRIGHT_EXECUTABLE", "").strip()
            if configured:
                return configured
            try:
                executable = p.chromium.executable_path
                if executable and os.path.exists(executable):
                    return executable
            except Exception:
                pass
            return None

        def _launch_context():
            executable_path = _chromium_executable_path()
            if debug and executable_path:
                print(f"    [DEBUG] Using Chromium executable: {executable_path}")
            return p.chromium.launch_persistent_context(
                cache_dir,
                headless=headless,
                executable_path=executable_path,
                args=[
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-blink-features=AutomationControlled",
                    "--window-size=1280,720",
                ],
                viewport={"width": 1280, "height": 720},
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/122.0.0.0 Safari/537.36"
                ),
                locale="de-CH",
            )

        try:
            context = _launch_context()
        except Exception as e:
            message = str(e)
            browser_path = os.environ.get("PLAYWRIGHT_BROWSERS_PATH") or "/var/cache/ms-playwright"
            if "Executable doesn't exist" not in message or not _install_playwright_chromium(browser_path):
                raise
            if debug:
                print("    [DEBUG] Retrying Playwright launch after Chromium runtime install")
            context = _launch_context()
        try:
            context.add_init_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined});")
        except Exception:
            pass
        page = context.pages[0] if context.pages else context.new_page()
        page.set_default_timeout(5000)
        page.set_default_navigation_timeout(20000)

        def _page_host() -> str:
            try:
                return urllib.parse.urlparse(page.url).hostname or "unknown"
            except Exception:
                return "unknown"

        def _secure_screenshot(path: str) -> None:
            page.screenshot(path=path)
            os.chmod(path, 0o600)
            os.chmod(path, 0o600)

        def _close_context() -> None:
            try:
                _close_number_match_notification()
                context.close()
            finally:
                if session_tmp_dir:
                    shutil.rmtree(session_tmp_dir, ignore_errors=True)

        saml_result = {
            "prelogin_cookie": None,
            "saml_username": None,
            "saml_response": None,
            "portal_userauthcookie": None,
        }

        allowed_hosts = {vpn_server_host}
        if gp_gateway_ip:
            allowed_hosts.add(gp_gateway_ip)
        if vpn_server_ip:
            allowed_hosts.add(vpn_server_ip)

        def _is_vpn_url(url: str) -> bool:
            try:
                host = urllib.parse.urlparse(url).hostname or ""
            except Exception:
                host = ""
            return host in allowed_hosts

        def _cookie_domain_matches(domain: str) -> bool:
            domain_no_dot = domain.lstrip(".")
            if domain_no_dot == vpn_server_host:
                return True
            if vpn_server_host.endswith(f".{domain_no_dot}"):
                return True
            if vpn_server_ip and domain_no_dot == vpn_server_ip:
                return True
            return False

        def _collect_vpn_cookies() -> dict[str, str]:
            vpn_cookies = {}
            for c in context.cookies():
                if c.get("value") and _cookie_domain_matches(c.get("domain", "")):
                    vpn_cookies[c["name"]] = c["value"]
            return vpn_cookies

        def _has_usable_auth_artifact(cookies: Optional[dict[str, str]] = None) -> bool:
            cookies = cookies or {}
            if protocol == "anyconnect":
                # OpenConnect's --cookie path cannot use a bare SAMLResponse. It
                # needs the final Cisco WebVPN session cookies; otherwise the
                # gateway rejects the cookie immediately.
                return bool(
                    cookies.get("webvpn")
                    and (cookies.get("webvpnc") or cookies.get("webvpnaac") or cookies.get("SVPNCOOKIE"))
                )
            return bool(
                saml_result.get("prelogin_cookie")
                or saml_result.get("portal_userauthcookie")
                or cookies.get("prelogin-cookie")
                or cookies.get("portal-userauthcookie")
                or cookies.get("SVPNCOOKIE")
            )

        def _auth_capture_complete() -> bool:
            if protocol == "anyconnect":
                return _has_usable_auth_artifact(_collect_vpn_cookies())
            return bool(
                saml_result.get("prelogin_cookie")
                or saml_result.get("portal_userauthcookie")
            )

        vpn_request_event = threading.Event()
        ui_change_event = threading.Event()
        microsoft_credential_lookup_pending = 0
        microsoft_credential_lookup_settle_until = 0.0
        microsoft_credential_lookup_generation = 0

        def _wait_for_vpn_callback(timeout_ms: int = 60000) -> None:
            _raise_if_cancelled()
            if _is_vpn_url(page.url) and protocol != "anyconnect":
                return
            if _auth_capture_complete():
                return
            deadline = time.time() + (timeout_ms / 1000.0)
            while time.time() < deadline:
                _raise_if_cancelled()
                if _auth_capture_complete():
                    return
                if _is_vpn_url(page.url) and protocol != "anyconnect":
                    return
                if vpn_request_event.wait(timeout=0.05):
                    if protocol != "anyconnect" or _auth_capture_complete():
                        return
                    vpn_request_event.clear()

        def handle_request(request):
            nonlocal microsoft_credential_lookup_pending
            nonlocal microsoft_credential_lookup_generation
            if debug:
                parsed_request = urllib.parse.urlsplit(request.url)
                if (
                    parsed_request.hostname == "login.microsoftonline.com"
                    and request.method.upper() != "GET"
                ):
                    print(
                        "    [DEBUG] Microsoft request: "
                        f"path={parsed_request.path or '/'} method={request.method}"
                    )
            parsed_request = urllib.parse.urlsplit(request.url)
            if (
                parsed_request.hostname == "login.microsoftonline.com"
                and parsed_request.path.casefold().endswith("/getcredentialtype")
            ):
                microsoft_credential_lookup_pending += 1
                microsoft_credential_lookup_generation += 1
            if _is_vpn_url(request.url):
                vpn_request_event.set()
                ui_change_event.set()
                if debug:
                    parsed_request = urllib.parse.urlsplit(request.url)
                    print(
                        "    [DEBUG] Request to VPN: "
                        f"host={parsed_request.hostname or 'unknown'} "
                        f"path={parsed_request.path or '/'}"
                    )
                    print(f"    [DEBUG] Request method: {request.method}")
                if request.post_data:
                    try:
                        params = urllib.parse.parse_qs(request.post_data)
                        if debug:
                            print(f"    [DEBUG] POST params: {list(params.keys())}")
                        if "SAMLResponse" in params:
                            saml_result["saml_response"] = params["SAMLResponse"][0]
                            if debug:
                                print(f"    [DEBUG] Captured SAMLResponse ({len(saml_result['saml_response'])} chars)")
                        if "prelogin-cookie" in params:
                            saml_result["prelogin_cookie"] = params["prelogin-cookie"][0]
                            if debug:
                                print(f"    [DEBUG] Captured prelogin-cookie from POST")
                    except Exception as e:
                        if debug:
                            print(f"    [DEBUG] Error parsing POST: {e}")

        def handle_response(response):
            nonlocal microsoft_credential_lookup_pending
            nonlocal microsoft_credential_lookup_settle_until
            parsed_response = urllib.parse.urlsplit(response.url)
            if (
                parsed_response.hostname == "login.microsoftonline.com"
                and parsed_response.path.casefold().endswith("/getcredentialtype")
            ):
                microsoft_credential_lookup_pending = max(
                    0,
                    microsoft_credential_lookup_pending - 1,
                )
                microsoft_credential_lookup_settle_until = (
                    time.monotonic() + 0.5
                )
                ui_change_event.set()
            if not _is_vpn_url(response.url):
                if debug:
                    if (
                        parsed_response.hostname == "login.microsoftonline.com"
                        and response.request.method.upper() != "GET"
                    ):
                        print(
                            "    [DEBUG] Microsoft response: "
                            f"path={parsed_response.path or '/'} "
                            f"status={response.status}"
                        )
                return
            ui_change_event.set()
            try:
                headers = response.headers
                if debug:
                    parsed_response = urllib.parse.urlsplit(response.url)
                    print(
                        "    [DEBUG] Response from VPN: "
                        f"host={parsed_response.hostname or 'unknown'} "
                        f"path={parsed_response.path or '/'} status={response.status}"
                    )
                    auth_header_names = [
                        h for h in [
                            "prelogin-cookie",
                            "saml-username",
                            "portal-userauthcookie",
                            "set-cookie",
                            "location",
                        ]
                        if h in headers
                    ]
                    if auth_header_names:
                        print(
                            "    [DEBUG] Auth response headers present: "
                            f"{auth_header_names}"
                        )
                if "prelogin-cookie" in headers:
                    saml_result["prelogin_cookie"] = headers["prelogin-cookie"]
                if "saml-username" in headers:
                    saml_result["saml_username"] = headers["saml-username"]
                if "portal-userauthcookie" in headers:
                    saml_result["portal_userauthcookie"] = headers["portal-userauthcookie"]
            except Exception:
                pass

        def handle_request_failed(request):
            nonlocal microsoft_credential_lookup_pending
            nonlocal microsoft_credential_lookup_settle_until
            parsed_request = urllib.parse.urlsplit(request.url)
            if (
                parsed_request.hostname == "login.microsoftonline.com"
                and parsed_request.path.casefold().endswith("/getcredentialtype")
            ):
                microsoft_credential_lookup_pending = max(
                    0,
                    microsoft_credential_lookup_pending - 1,
                )
                microsoft_credential_lookup_settle_until = (
                    time.monotonic() + 0.5
                )
                ui_change_event.set()

        page.on("request", handle_request)
        page.on("response", handle_response)
        page.on("requestfailed", handle_request_failed)
        page.on("load", lambda *_: ui_change_event.set())
        page.on("domcontentloaded", lambda *_: ui_change_event.set())
        page.on("framenavigated", lambda *_: ui_change_event.set())

        def _first_visible(locator, limit: int = 20):
            try:
                count = min(locator.count(), limit)
            except Exception:
                try:
                    fallback = [
                        password_loc.get_attribute("id") or "",
                        password_loc.get_attribute("name") or "",
                        password_loc.get_attribute("type") or "",
                        password_loc.get_attribute("autocomplete") or "",
                    ]
                    return "fallback:" + hashlib.sha256(
                        json.dumps(fallback, separators=(",", ":")).encode("utf-8")
                    ).hexdigest()
                except Exception:
                    return None
            for index in range(count):
                candidate = locator.nth(index)
                try:
                    if candidate.is_visible():
                        return candidate
                except Exception:
                    continue
            return None

        def _first_usable_input(locator, limit: int = 20):
            """Return a visible, enabled, editable input and ignore stale panels."""
            try:
                count = min(locator.count(), limit)
            except Exception:
                return None
            for index in range(count):
                candidate = locator.nth(index)
                try:
                    if (
                        candidate.is_visible()
                        and candidate.is_enabled()
                        and candidate.is_editable()
                    ):
                        return candidate
                except Exception:
                    continue
            return None

        def _find_visible_in_frames(selectors: list[str]):
            for frame in page.frames:
                for sel in selectors:
                    try:
                        candidate = _first_visible(frame.locator(sel))
                        if candidate is not None:
                            return candidate
                    except Exception:
                        continue
            return None

        def _find_input_by_ids(ids: list[str]):
            for frame in page.frames:
                for element_id in ids:
                    try:
                        candidate = _first_visible(frame.locator(f"#{element_id}"))
                        if candidate is not None:
                            return candidate
                    except Exception:
                        continue
            return None

        def _find_usable_input_by_ids(ids: list[str]):
            for frame in page.frames:
                for element_id in ids:
                    try:
                        candidate = _first_usable_input(frame.locator(f"#{element_id}"))
                        if candidate is not None:
                            return candidate
                    except Exception:
                        continue
            return None

        def _find_input_by_labels(labels: list[str]):
            patterns = [re.compile(re.escape(label), re.IGNORECASE) for label in labels]
            for frame in page.frames:
                for pattern in patterns:
                    try:
                        candidate = _first_visible(frame.get_by_label(pattern))
                        if candidate is not None:
                            return candidate
                    except Exception:
                        continue
            return None

        def _find_usable_input_by_labels(labels: list[str]):
            patterns = [re.compile(re.escape(label), re.IGNORECASE) for label in labels]
            for frame in page.frames:
                for pattern in patterns:
                    try:
                        candidate = _first_usable_input(frame.get_by_label(pattern))
                        if candidate is not None:
                            return candidate
                    except Exception:
                        continue
            return None

        def _normalize_text(value: Optional[str]) -> str:
            return (value or "").strip().lower()

        def _iter_visible_inputs(frame, limit: int = 60):
            try:
                inputs = frame.locator("input")
                count = min(inputs.count(), limit)
            except Exception:
                return
            for idx in range(count):
                loc = inputs.nth(idx)
                try:
                    if not loc.is_visible():
                        continue
                    input_type = _normalize_text(loc.get_attribute("type"))
                    if input_type in {"hidden", "submit", "button", "checkbox", "radio", "file"}:
                        continue
                    yield loc
                except Exception:
                    continue

        def _score_input(attrs: dict[str, str], kind: str) -> int:
            name = _normalize_text(attrs.get("name"))
            input_id = _normalize_text(attrs.get("id"))
            placeholder = _normalize_text(attrs.get("placeholder"))
            aria_label = _normalize_text(attrs.get("aria-label"))
            autocomplete = _normalize_text(attrs.get("autocomplete"))
            input_type = _normalize_text(attrs.get("type"))
            input_mode = _normalize_text(attrs.get("inputmode"))
            data_test = _normalize_text(attrs.get("data-test") or attrs.get("data-testid"))

            haystack = "|".join([name, input_id, placeholder, aria_label, data_test])
            score = 0

            if kind == "username":
                if input_type == "email":
                    score += 6
                if autocomplete in {"username", "email"}:
                    score += 6
                if input_type in {"text", "email"}:
                    score += 1
                for hint in [
                    "user",
                    "login",
                    "email",
                    "username",
                    "account",
                    "loginfmt",
                    "i0116",
                    "identifier",
                    "okta",
                    "adfs",
                ]:
                    if hint in haystack:
                        score += 3
            elif kind == "password":
                if input_type == "password":
                    score += 8
                if autocomplete in {"current-password", "password"}:
                    score += 6
                for hint in [
                    "pass",
                    "password",
                    "passwd",
                    "pwd",
                    "i0118",
                ]:
                    if hint in haystack:
                        score += 3
            elif kind == "otp":
                if autocomplete == "one-time-code":
                    score += 8
                if input_mode == "numeric":
                    score += 1
                if input_type == "tel":
                    score += 1
                for hint in [
                    "otp",
                    "otc",
                    "mfa",
                    "2fa",
                    "totp",
                    "authenticator",
                    "verification",
                    "code",
                    "security code",
                ]:
                    if hint in haystack:
                        score += 3
            return score

        def _find_best_input(kind: str):
            best_score = 0
            best_loc = None
            for frame in page.frames:
                for loc in _iter_visible_inputs(frame):
                    try:
                        if kind == "otp" and not (
                            loc.is_enabled() and loc.is_editable()
                        ):
                            continue
                        attrs = {
                            "type": loc.get_attribute("type") or "",
                            "name": loc.get_attribute("name") or "",
                            "id": loc.get_attribute("id") or "",
                            "placeholder": loc.get_attribute("placeholder") or "",
                            "aria-label": loc.get_attribute("aria-label") or "",
                            "autocomplete": loc.get_attribute("autocomplete") or "",
                            "inputmode": loc.get_attribute("inputmode") or "",
                            "data-test": loc.get_attribute("data-test") or "",
                            "data-testid": loc.get_attribute("data-testid") or "",
                        }
                        score = _score_input(attrs, kind)
                        if score > best_score:
                            best_score = score
                            best_loc = loc
                    except Exception:
                        continue
            # A generic numeric or telephone input is not enough evidence for an
            # OTP field (Microsoft number-matching pages can contain such controls).
            if kind == "otp" and best_score < 3:
                return None
            return best_loc

        def _find_otp_input():
            return (
                _find_usable_input_by_ids(["idTxtBx_SAOTCC_OTC", "idTxtBx_SAOTCC_OTP", "otp", "otc", "code"])
                or _find_usable_input_by_labels([
                    "Verification code",
                    "Security code",
                    "Code",
                    "OTP",
                    "Einmalcode",
                    "Prüfcode",
                    "Bestätigungscode",
                    "Sicherheitscode",
                    "Code eingeben",
                ])
                or _find_best_input("otp")
            )

        def _totp_error_signature(otp_loc) -> Optional[str]:
            stable_selectors = [
                "#idSpan_SAOTCC_Error",
                "#idDiv_SAOTCC_Error",
                "#idTD_Error",
            ]
            form_selectors = [
                "[role='alert']",
                "[aria-live='assertive']",
                "input[aria-invalid='true']",
            ]
            messages = []

            # Microsoft's stable error elements are sometimes siblings of the
            # OTP form rather than descendants. They are specific enough to
            # inspect across frames while generic alerts remain form-scoped.
            for selector in stable_selectors:
                candidate = _find_visible_in_frames([selector])
                if candidate is None:
                    continue
                try:
                    text_value = _normalize_text(candidate.text_content(timeout=500))
                    messages.append(text_value or selector)
                except Exception:
                    continue

            try:
                described_by = otp_loc.get_attribute("aria-describedby") or ""
            except Exception:
                described_by = ""
            for element_id in described_by.split():
                if not re.fullmatch(r"[A-Za-z0-9_.:-]+", element_id):
                    continue
                candidate = _find_visible_in_frames([f"#{element_id}"])
                if candidate is None:
                    continue
                try:
                    text_value = _normalize_text(candidate.text_content(timeout=500))
                    messages.append(text_value or f"#{element_id}")
                except Exception:
                    continue

            try:
                form = _first_visible(otp_loc.locator("xpath=ancestor::form[1]"), limit=1)
            except Exception:
                form = None
            if form is not None:
                for selector in form_selectors:
                    try:
                        candidate = _first_visible(form.locator(selector))
                        if candidate is None:
                            continue
                        text_value = _normalize_text(candidate.text_content(timeout=500))
                        messages.append(text_value or selector)
                    except Exception:
                        continue
            if not messages:
                return None
            return "|".join(sorted(set(messages)))

        def _input_value_empty(loc) -> bool:
            try:
                return not _normalize_text(loc.input_value())
            except Exception:
                return False

        def _locator_is_actionable(loc) -> bool:
            try:
                if not loc.is_visible() or not loc.is_enabled():
                    return False
                traits = loc.evaluate(
                    """element => ({
                        tagName: element.tagName.toLowerCase(),
                        role: element.getAttribute('role') || '',
                        inputType: element.getAttribute('type') || '',
                        disabled: !!element.disabled ||
                            element.getAttribute('aria-disabled') === 'true',
                        hasHref: element.tagName.toLowerCase() === 'a' &&
                            !!element.getAttribute('href'),
                        hasClickHandler: typeof element.onclick === 'function' ||
                            element.hasAttribute('onclick'),
                        hasDataValue: element.hasAttribute('data-value'),
                        tabIndex: Number.isInteger(element.tabIndex) ?
                            element.tabIndex : null,
                        pointerCursor: window.getComputedStyle(element).cursor === 'pointer',
                    })"""
                )
                return _is_actionable_control(
                    traits.get("tagName"),
                    role=traits.get("role"),
                    input_type=traits.get("inputType"),
                    disabled=bool(traits.get("disabled")),
                    has_href=bool(traits.get("hasHref")),
                    has_click_handler=bool(traits.get("hasClickHandler")),
                    has_data_value=bool(traits.get("hasDataValue")),
                    tab_index=traits.get("tabIndex"),
                    pointer_cursor=bool(traits.get("pointerCursor")),
                )
            except Exception:
                return False

        def _find_actionable_text_control(frame, pattern):
            """Return a matching text node's nearest genuinely interactive control."""
            try:
                matches = frame.get_by_text(pattern, exact=False)
                match_count = min(matches.count(), 20)
            except Exception:
                return None
            for match_index in range(match_count):
                text_match = matches.nth(match_index)
                try:
                    if not text_match.is_visible():
                        continue
                    controls = text_match.locator(
                        "xpath=ancestor-or-self::*["
                        "self::button or self::a[@href] or "
                        "@role='button' or @role='link' or "
                        "(self::input and (@type='submit' or @type='button')) or "
                        "@onclick or @data-value or @tabindex]"
                    )
                    for control_index in range(min(controls.count(), 10)):
                        control = controls.nth(control_index)
                        if _locator_is_actionable(control):
                            return control
                except Exception:
                    continue
            return None

        def _click_action(labels: list[str]) -> bool:
            patterns = _action_patterns(labels)
            for frame in page.frames:
                for pattern in patterns:
                    for role in ["button", "link"]:
                        try:
                            candidate = _first_visible(frame.get_by_role(role, name=pattern))
                            if candidate is not None:
                                candidate.click(timeout=1500)
                                return True
                        except Exception:
                            continue
                    try:
                        loc = frame.locator("input[type='submit']")
                        if loc.count() > 0:
                            for idx in range(min(loc.count(), 10)):
                                candidate = loc.nth(idx)
                                try:
                                    value = _normalize_text(candidate.get_attribute("value"))
                                    if value and pattern.search(value) and candidate.is_visible():
                                        candidate.click(timeout=1500)
                                        return True
                                except Exception:
                                    continue
                    except Exception:
                        continue
                    candidate = _find_actionable_text_control(frame, pattern)
                    if candidate is not None:
                        try:
                            candidate.click(timeout=1500)
                            return True
                        except Exception:
                            continue
            return False

        def _action_available(labels: list[str]) -> bool:
            """Find only visible, enabled controls; explanatory text is not an action."""
            patterns = _action_patterns(labels)
            for frame in page.frames:
                for pattern in patterns:
                    for role in ("button", "link"):
                        try:
                            candidate = _first_visible(
                                frame.get_by_role(role, name=pattern)
                            )
                            if (
                                candidate is not None
                                and candidate.is_enabled()
                                and _is_actionable_control("", role=role)
                            ):
                                return True
                        except Exception:
                            continue
                    try:
                        submits = frame.locator(
                            "input[type='submit'], input[type='button'], button[type='submit']"
                        )
                        for index in range(min(submits.count(), 10)):
                            candidate = submits.nth(index)
                            tag_name = candidate.evaluate(
                                "element => element.tagName.toLowerCase()"
                            )
                            input_type = candidate.get_attribute("type")
                            label = _normalize_text(
                                candidate.get_attribute("value")
                                or candidate.text_content(timeout=500)
                            )
                            if (
                                label
                                and pattern.search(label)
                                and candidate.is_visible()
                                and candidate.is_enabled()
                                and _is_actionable_control(
                                    tag_name,
                                    input_type=input_type,
                                )
                            ):
                                return True
                    except Exception:
                        continue
                    if _find_actionable_text_control(frame, pattern) is not None:
                        return True
            return False

        def _click_known_ids(ids: list[str]) -> bool:
            for frame in page.frames:
                for element_id in ids:
                    try:
                        candidate = _first_visible(frame.locator(f"#{element_id}"))
                        if candidate is not None:
                            candidate.click(timeout=1000)
                            return True
                    except Exception:
                        continue
            return False

        def _click_first_selector(selectors) -> bool:
            loc = _find_visible_in_frames(list(selectors))
            if loc is None:
                return False
            try:
                loc.click(timeout=1000)
                return True
            except Exception:
                return False

        def _submit_owned_form(
            input_loc,
            labels: list[str],
            ids: list[str],
            *,
            allow_unlabelled_submit: bool = True,
            allow_known_ids: bool = True,
            allow_enter: bool = True,
        ) -> bool:
            """Submit the form owning an input before trying page-level fallbacks."""
            try:
                form = _first_visible(
                    input_loc.locator("xpath=ancestor::form[1]"),
                    limit=1,
                )
            except Exception:
                form = None
            if form is not None:
                for label in labels:
                    pattern = _exact_action_pattern(label)
                    try:
                        button = _first_visible(form.get_by_role("button", name=pattern))
                        if button is not None:
                            button.click()
                            if debug:
                                print("    [DEBUG] Submitted owning form via exact button")
                            return True
                    except Exception:
                        continue
                if allow_unlabelled_submit:
                    try:
                        submit = _first_visible(form.locator(
                            "input[type='submit'], button[type='submit']"
                        ))
                        if submit is not None:
                            submit.click()
                            if debug:
                                print(
                                    "    [DEBUG] Submitted owning form via submit control"
                                )
                            return True
                    except Exception:
                        pass
            if allow_known_ids and _click_known_ids(ids):
                if debug:
                    print("    [DEBUG] Submitted form via known control id")
                return True
            if not allow_enter:
                return False
            try:
                input_loc.press("Enter")
                if debug:
                    print("    [DEBUG] Submitted form via Enter")
                return True
            except Exception:
                return False

        def _submit_otp(otp_loc) -> bool:
            """Submit only the form that owns the OTP input."""
            return _submit_owned_form(
                otp_loc,
                [
                    "Verify",
                    "Überprüfen",
                    "Bestätigen",
                    "Continue",
                    "Weiter",
                    "Next",
                    "Submit",
                ],
                [
                "idSubmit_SAOTCC_Continue",
                "idSIButton9",
                "submitButton",
                ],
            )

        def _submit_password(password_loc) -> bool:
            """Submit the password form without matching alternate-login links."""
            labels = [
                "Anmelden",
                "Sign in",
                "Connexion",
                "Accedi",
                "Continue",
                "Next",
            ]
            if _submit_owned_form(
                password_loc,
                labels,
                [],
                allow_unlabelled_submit=False,
                allow_known_ids=False,
                allow_enter=False,
            ):
                if debug:
                    print("    [DEBUG] Submitted password via exact owning-form control")
                return True
            if _click_action(labels):
                if debug:
                    print("    [DEBUG] Submitted password via exact page control")
                return True
            return _submit_owned_form(
                password_loc,
                labels,
                ["idSIButton9", "submitButton"],
            )

        def _page_has_text(texts: list[str]) -> bool:
            for frame in page.frames:
                for t in texts:
                    try:
                        if _first_visible(frame.get_by_text(t, exact=False)) is not None:
                            return True
                    except Exception:
                        continue
            try:
                body_text = page.evaluate("() => document.body && document.body.innerText ? document.body.innerText : ''")
                body_lower = (body_text or "").lower()
                for t in texts:
                    if t.lower() in body_lower:
                        return True
            except Exception:
                pass
            return False

        def _find_password_input():
            return (
                _find_input_by_ids([
                    "passwordInput",
                    "password",
                    "i0118",
                    "passwd",
                    "Passwd",
                ])
                or _find_input_by_labels([
                    "Kennwort",
                    "Passwort",
                    "Password",
                    "Mot de passe",
                ])
                or _find_best_input("password")
            )

        def _password_control_identity(password_loc) -> Optional[str]:
            """Return a document-scoped identity that changes with the DOM node."""
            try:
                return str(password_loc.evaluate(
                    """element => {
                        if (!globalThis.__msSsoDocumentIdentity) {
                            globalThis.__msSsoDocumentIdentity =
                                (globalThis.crypto && crypto.randomUUID)
                                    ? crypto.randomUUID()
                                    : `${Date.now()}-${Math.random()}`;
                        }
                        if (!globalThis.__msSsoElementIdentities) {
                            globalThis.__msSsoElementIdentities = new WeakMap();
                            globalThis.__msSsoNextElementIdentity = 1;
                        }
                        if (!globalThis.__msSsoElementIdentities.has(element)) {
                            globalThis.__msSsoElementIdentities.set(
                                element,
                                globalThis.__msSsoNextElementIdentity++,
                            );
                        }
                        return `${globalThis.__msSsoDocumentIdentity}:` +
                            globalThis.__msSsoElementIdentities.get(element);
                    }"""
                ))
            except Exception:
                return None

        def _credential_error_visible() -> bool:
            """Recognize explicit credential rejection without logging its text."""
            return _page_has_text(list(MICROSOFT_CREDENTIAL_ERROR_MARKERS))

        def _open_alternate_methods() -> bool:
            if _click_first_selector(MICROSOFT_ALTERNATE_MFA_SELECTORS):
                return True
            return _click_action(list(MICROSOFT_ALTERNATE_MFA_LABELS))

        def _method_picker_context_visible() -> bool:
            """Require multiple known choices before trusting non-semantic tile text."""
            method_groups = (
                MICROSOFT_PASSKEY_MARKERS,
                MICROSOFT_TOTP_METHOD_LABELS,
                MICROSOFT_PUSH_METHOD_LABELS,
                MICROSOFT_PASSWORD_METHOD_LABELS,
            )
            return sum(
                1 for labels in method_groups if _page_has_text(list(labels))
            ) >= 2

        def _actionable_method_choice_visible() -> bool:
            """Recognize one concrete method control without trusting body text."""
            direct_selectors = (
                MICROSOFT_TOTP_DIRECT_SELECTORS
                + MICROSOFT_PUSH_DIRECT_SELECTORS
                + MICROSOFT_PASSWORD_DIRECT_SELECTORS
            )
            return bool(
                _find_visible_in_frames(list(direct_selectors)) is not None
                or _action_available(list(MICROSOFT_TOTP_METHOD_LABELS))
                or _action_available(list(MICROSOFT_PUSH_METHOD_LABELS))
                or _action_available(list(MICROSOFT_PASSWORD_METHOD_LABELS))
            )

        def _known_method_label_visible(labels: tuple[str, ...]) -> bool:
            """Recognize a vetted label only inside a verified method picker."""
            return (
                _method_picker_context_visible()
                and _page_has_text(list(labels))
            )

        def _click_known_method_label(labels: tuple[str, ...]) -> bool:
            """Click only vetted credential/MFA labels as a non-semantic tile fallback."""
            if not _method_picker_context_visible():
                return False
            patterns = _action_patterns(labels)
            for frame in page.frames:
                for pattern in patterns:
                    try:
                        candidate = _first_visible(
                            frame.get_by_text(pattern, exact=False)
                        )
                        if candidate is not None:
                            candidate.click(timeout=1500)
                            return True
                    except Exception:
                        continue
            return False

        def _totp_method_visible() -> bool:
            if _find_visible_in_frames(list(MICROSOFT_TOTP_DIRECT_SELECTORS)) is not None:
                return True
            return (
                _action_available(list(MICROSOFT_TOTP_METHOD_LABELS))
                or _known_method_label_visible(MICROSOFT_TOTP_METHOD_LABELS)
            )

        def _push_method_visible() -> bool:
            if _find_visible_in_frames(list(MICROSOFT_PUSH_DIRECT_SELECTORS)) is not None:
                return True
            return (
                _action_available(list(MICROSOFT_PUSH_METHOD_LABELS))
                or _known_method_label_visible(MICROSOFT_PUSH_METHOD_LABELS)
            )

        def _password_method_visible() -> bool:
            if _find_visible_in_frames(list(MICROSOFT_PASSWORD_DIRECT_SELECTORS)) is not None:
                return True
            return (
                _action_available(list(MICROSOFT_PASSWORD_METHOD_LABELS))
                or _known_method_label_visible(MICROSOFT_PASSWORD_METHOD_LABELS)
            )

        def _select_totp_method() -> bool:
            if _click_first_selector(MICROSOFT_TOTP_DIRECT_SELECTORS):
                return True
            return (
                _click_action(list(MICROSOFT_TOTP_METHOD_LABELS))
                or _click_known_method_label(MICROSOFT_TOTP_METHOD_LABELS)
            )

        def _select_push_method() -> bool:
            if _click_first_selector(MICROSOFT_PUSH_DIRECT_SELECTORS):
                return True
            return (
                _click_action(list(MICROSOFT_PUSH_METHOD_LABELS))
                or _click_known_method_label(MICROSOFT_PUSH_METHOD_LABELS)
            )

        def _select_password_method() -> bool:
            if _click_first_selector(MICROSOFT_PASSWORD_DIRECT_SELECTORS):
                return True
            return (
                _click_action(list(MICROSOFT_PASSWORD_METHOD_LABELS))
                or _click_known_method_label(MICROSOFT_PASSWORD_METHOD_LABELS)
            )

        def _number_match_state() -> tuple[bool, Optional[str]]:
            marker_visible = _page_has_text(list(MICROSOFT_NUMBER_MATCH_MARKERS))
            selector_visible = False
            candidates = set()
            for frame in page.frames:
                for selector in MICROSOFT_NUMBER_MATCH_SELECTORS:
                    try:
                        candidate = _first_visible(frame.locator(selector))
                        if candidate is None:
                            continue
                        selector_visible = True
                        candidates.update(_standalone_two_digit_numbers(
                            candidate.text_content(timeout=500)
                        ))
                    except Exception:
                        continue

            if not _has_number_match_evidence(marker_visible, selector_visible):
                return False, None

            # Microsoft has changed the display selector across releases. On a
            # confirmed number-match page, a standalone two-digit line is the
            # generated approval number shown to the user.
            if marker_visible and not candidates:
                try:
                    body_text = page.evaluate(
                        "() => document.body && document.body.innerText ? document.body.innerText : ''"
                    )
                    candidates.update(_standalone_two_digit_numbers(body_text))
                except Exception:
                    pass
            number = next(iter(candidates)) if len(candidates) == 1 else None
            return True, number

        def _leave_passkey_prompt() -> Optional[str]:
            if not _page_has_text(list(MICROSOFT_PASSKEY_MARKERS)):
                return None
            try:
                page.keyboard.press("Escape")
            except Exception:
                pass
            if _select_password_method():
                return "passkey-password-fallback-selected"
            if _open_alternate_methods():
                return "passkey-alternate-methods-opened"
            return None

        def _click_account_tile(candidates: list[str]) -> bool:
            """Click a visible, interactive account tile without hitting email headers."""
            patterns = [re.compile(re.escape(candidate), re.IGNORECASE) for candidate in candidates]
            for frame in page.frames:
                for pattern in patterns:
                    for role in ("button", "link"):
                        try:
                            tile = _first_visible(frame.get_by_role(role, name=pattern))
                            if tile is not None:
                                tile.click()
                                return True
                        except Exception:
                            continue
                    for selector in ("[data-test-id='tile']", "[role='listitem']"):
                        try:
                            tile = _first_visible(
                                frame.locator(selector).filter(has_text=pattern)
                            )
                            if tile is not None:
                                tile.click()
                                return True
                        except Exception:
                            continue
            return False

        def _auth_ui_ready() -> bool:
            selectors = [
                "input",
                "button",
                "input[type='submit']",
                "#idSIButton9",
                "#submitButton",
                "#i0116",
                "#i0118",
                "#userNameInput",
                "#passwordInput",
                "#idTxtBx_SAOTCC_OTC",
            ]
            for frame in page.frames:
                for sel in selectors:
                    try:
                        if _first_visible(frame.locator(sel)) is not None:
                            return True
                    except Exception:
                        continue
            return False

        def _auth_ui_fingerprint() -> str:
            """Hash relevant browser state so credentials never enter logs or paths."""
            snapshot = []
            for frame in page.frames:
                try:
                    controls = frame.evaluate(
                        """() => Array.from(document.querySelectorAll(
                            "input, button, a[href], [role='button'], [role='link']"
                        )).filter(element => {
                            const rect = element.getBoundingClientRect();
                            const style = window.getComputedStyle(element);
                            return style.visibility !== 'hidden' &&
                                style.display !== 'none' &&
                                rect.width > 0 && rect.height > 0;
                        }).slice(0, 50).map(element => ({
                            tag: element.tagName.toLowerCase(),
                            id: element.id || '',
                            name: element.getAttribute('name') || '',
                            type: element.getAttribute('type') || '',
                            role: element.getAttribute('role') || '',
                            autocomplete: element.getAttribute('autocomplete') || '',
                            disabled: !!element.disabled ||
                                element.getAttribute('aria-disabled') === 'true',
                            hasValue: 'value' in element ? !!element.value : null,
                            label: (element.getAttribute('aria-label') ||
                                element.getAttribute('value') ||
                                element.innerText || '').replace(/\\s+/g, ' ').trim().slice(0, 120),
                        }))"""
                    )
                    snapshot.append([frame.url, controls])
                except Exception:
                    continue
            if not snapshot:
                snapshot.append([page.url, []])
            encoded = json.dumps(
                snapshot,
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
            return hashlib.sha256(encoded).hexdigest()

        def _auth_ui_processing() -> bool:
            """Detect a visible semantic loading state without reading page secrets."""
            selectors = (
                "[aria-busy='true']",
                "[role='progressbar']",
                "[data-testid*='progress' i]",
                "[data-testid*='spinner' i]",
                "[class*='progress' i]",
                "[class*='spinner' i]",
                "[class*='loading' i]",
                "#idDiv_PWD_Progress",
                "#idDiv_SAOTCS_Progress",
                "#idDiv_SAOTCC_Progress",
            )
            return _find_visible_in_frames(list(selectors)) is not None

        def _usable_auth_page() -> bool:
            """Reject Chromium error UI while preserving a partially loaded IdP form."""
            try:
                if urllib.parse.urlparse(page.url).scheme not in {"http", "https"}:
                    return False
            except Exception:
                return False
            if _is_vpn_url(page.url):
                return True
            known_selectors = [
                "form input",
                "input[type='email']",
                "input[type='password']",
                "input[autocomplete='username']",
                "input[autocomplete='one-time-code']",
                "#idSIButton9",
                "#i0116",
                "#i0118",
                "#userNameInput",
                "#passwordInput",
                "#idTxtBx_SAOTCC_OTC",
                "[data-test-id='tile']",
            ]
            return _find_visible_in_frames(known_selectors) is not None

        def _wait_until_ready(timeout_seconds: float = 1.0) -> None:
            deadline = time.monotonic() + timeout_seconds
            while time.monotonic() < deadline:
                _raise_if_cancelled()
                if (
                    _is_vpn_url(page.url)
                    or saml_result.get("saml_response")
                    or saml_result.get("prelogin_cookie")
                    or saml_result.get("portal_userauthcookie")
                    or _auth_ui_ready()
                ):
                    return
                remaining = max(0.0, deadline - time.monotonic())
                ui_change_event.wait(timeout=min(0.05, remaining))
                ui_change_event.clear()

        def _interruptible_pause(seconds: float) -> None:
            deadline = time.monotonic() + max(0.0, seconds)
            while time.monotonic() < deadline:
                _raise_if_cancelled()
                remaining = deadline - time.monotonic()
                time.sleep(min(0.05, max(0.0, remaining)))

        def _is_adfs_page() -> bool:
            url = page.url.lower()
            if "adfs" in url and "/ls" in url:
                return True
            return _find_visible_in_frames(["#userNameInput", "#passwordInput"]) is not None

        def _goto_with_retries(url: str, deadline: float) -> None:
            errors = []
            for attempt in range(2):
                _raise_if_cancelled()
                remaining_ms = _remaining_timeout_ms(deadline)
                if remaining_ms <= 0:
                    break
                try:
                    page.goto(
                        url,
                        timeout=min(20000, remaining_ms),
                        wait_until="domcontentloaded",
                    )
                    _wait_until_ready(0.5)
                    return
                except Exception as exc:
                    errors.append(exc)
                    if _auth_capture_complete() or _usable_auth_page():
                        return
                    error_text = str(exc)
                    transient = any(token in error_text for token in (
                        "Timeout",
                        "ERR_NETWORK_CHANGED",
                        "ERR_TIMED_OUT",
                        "ERR_CONNECTION_RESET",
                        "ERR_CONNECTION_CLOSED",
                    ))
                    if debug:
                        action = "retrying" if transient and attempt == 0 else "stopping"
                        print(f"    [DEBUG] Page.goto failed; {action} ({attempt + 1}/2)")
                    if not transient:
                        raise
                _wait_until_ready(0.2)
            raise errors[-1] if errors else Exception("Page.goto failed")

        def _click_first_text(texts: list[str]):
            for frame in page.frames:
                for t in texts:
                    try:
                        candidate = _first_visible(frame.get_by_text(t, exact=False))
                        if candidate is not None:
                            candidate.click()
                            return True
                    except Exception:
                        continue
            return False

        timeout_seconds = _parse_saml_timeout(protocol)
        deadline = time.monotonic() + timeout_seconds

        try:
            _raise_if_cancelled()
            if protocol == "gp" and gp_saml_request:
                try:
                    start_url = base64.b64decode(gp_saml_request).decode("utf-8")
                    if not start_url.startswith("http"):
                        start_url = vpn_url
                except Exception:
                    start_url = vpn_url
            elif protocol == "anyconnect":
                start_url = f"https://{vpn_server_netloc}/+CSCOE+/saml/sp/login?tgname=DefaultWEBVPNGroup"
            else:
                start_url = vpn_url

            print("  [1/6] Opening SAML portal...")
            _goto_with_retries(start_url, deadline)
            _report_progress(f"portal-ready host={_page_host()}")

            if debug:
                try:
                    _secure_screenshot("/tmp/vpn-step1-portal.png")
                    print("    [DEBUG] Screenshot: /tmp/vpn-step1-portal.png")
                except Exception:
                    print("    [DEBUG] Portal screenshot unavailable; continuing")

            _wait_until_ready(0.5)
            _raise_if_cancelled()
            if _is_vpn_url(page.url):
                all_cookies = context.cookies()
                session_cookies = {}
                for c in all_cookies:
                    if c.get("value") and _cookie_domain_matches(c.get("domain", "")):
                        session_cookies[c["name"]] = c["value"]

                has_session = (
                    _has_usable_auth_artifact(session_cookies)
                )
                if has_session:
                    print("  -> Already authenticated (SSO session valid)")
                    session_cookies = _merge_saml_artifacts(
                        session_cookies,
                        saml_result,
                        protocol,
                        gp_prelogin_cookie,
                        gp_gateway_ip,
                    )
                    _close_context()
                    return session_cookies

            filled_username = False
            filled_password = False
            last_totp_counter = None
            totp_submission_attempts = 0
            adfs_submit_attempts = 0
            blank_login_reloads = 0
            last_progress_time = time.monotonic()
            last_mfa_switch_time = 0.0
            last_wait_report_time = 0.0
            otp_input_reported = False
            totp_disabled_for_attempt = False
            totp_error_before_submit = None
            last_number_match = None
            otp_alternate_attempts = 0
            method_selection_pending = None
            mfa_picker_pending_until = 0.0
            mfa_picker_settle_until = 0.0
            mfa_method_pending_until = 0.0
            number_match_switch_deadline = 0.0
            number_match_detected_reported = False
            primary_credential_picker_pending_until = 0.0
            password_bridge_pending_until = 0.0
            password_bridge_attempts = 0
            password_input_ready_since = 0.0
            password_input_identity = None
            credential_lookup_submission_attempts = 0
            password_submission_lookup_generation = 0
            password_submission_classify_until = 0.0
            ui_recovery_attempts = 0
            last_ui_fingerprint = _auth_ui_fingerprint()
            last_substantive_progress_time = time.monotonic()
            post_submit_grace_until = 0.0
            processing_extensions_used = 0
            form_submission_fingerprint = None
            form_submission_kind = None
            form_submission_hard_deadline = 0.0
            mfa_started = False

            def _recover_stale_browser_ui(now: float) -> bool:
                """Re-enter the SAML flow once, then surface a bounded stall."""
                nonlocal filled_username
                nonlocal filled_password
                nonlocal adfs_submit_attempts
                nonlocal last_progress_time
                nonlocal last_mfa_switch_time
                nonlocal otp_input_reported
                nonlocal otp_alternate_attempts
                nonlocal method_selection_pending
                nonlocal mfa_picker_pending_until
                nonlocal mfa_picker_settle_until
                nonlocal mfa_method_pending_until
                nonlocal number_match_switch_deadline
                nonlocal number_match_detected_reported
                nonlocal primary_credential_picker_pending_until
                nonlocal password_bridge_pending_until
                nonlocal password_input_ready_since
                nonlocal password_input_identity
                nonlocal credential_lookup_submission_attempts
                nonlocal password_submission_lookup_generation
                nonlocal password_submission_classify_until
                nonlocal last_number_match
                nonlocal ui_recovery_attempts
                nonlocal last_ui_fingerprint
                nonlocal last_substantive_progress_time
                nonlocal post_submit_grace_until
                nonlocal processing_extensions_used
                nonlocal form_submission_fingerprint
                nonlocal form_submission_kind
                nonlocal form_submission_hard_deadline

                recovery_action = _stale_ui_recovery_action(
                    last_substantive_progress_time,
                    now,
                    ui_recovery_attempts,
                    grace_until=post_submit_grace_until,
                )
                if recovery_action == "wait":
                    return False
                if mfa_started:
                    raise RuntimeError(
                        "Microsoft MFA UI did not make substantive progress"
                    )
                if recovery_action == "fail":
                    raise SamlUiStalledError(
                        "SAML login UI did not make substantive progress after recovery"
                    )

                ui_recovery_attempts += 1
                filled_username = False
                filled_password = False
                adfs_submit_attempts = 0
                last_mfa_switch_time = 0.0
                otp_input_reported = False
                otp_alternate_attempts = 0
                method_selection_pending = None
                mfa_picker_pending_until = 0.0
                mfa_picker_settle_until = 0.0
                mfa_method_pending_until = 0.0
                number_match_switch_deadline = 0.0
                number_match_detected_reported = False
                primary_credential_picker_pending_until = 0.0
                password_bridge_pending_until = 0.0
                password_input_ready_since = 0.0
                password_input_identity = None
                credential_lookup_submission_attempts = 0
                password_submission_lookup_generation = 0
                password_submission_classify_until = 0.0
                post_submit_grace_until = 0.0
                processing_extensions_used = 0
                form_submission_fingerprint = None
                form_submission_kind = None
                form_submission_hard_deadline = 0.0
                if last_number_match is not None:
                    _close_number_match_notification()
                    last_number_match = None

                _report_progress("saml-ui-recovery")
                if debug:
                    print(
                        "    [DEBUG] SAML login UI stalled; re-entering the start flow"
                    )
                try:
                    _goto_with_retries(start_url, deadline)
                except Exception as exc:
                    raise SamlUiStalledError(
                        "SAML login UI recovery could not re-enter the start flow"
                    ) from exc
                last_ui_fingerprint = _auth_ui_fingerprint()
                last_substantive_progress_time = time.monotonic()
                last_progress_time = last_substantive_progress_time
                return True

            def _arm_submission_wait(kind: str, submitted_at: float) -> None:
                """Latch one form submit so it is polled but never replayed."""
                nonlocal last_progress_time
                nonlocal last_substantive_progress_time
                nonlocal post_submit_grace_until
                nonlocal processing_extensions_used
                nonlocal form_submission_fingerprint
                nonlocal form_submission_kind
                nonlocal form_submission_hard_deadline

                last_progress_time = submitted_at
                last_substantive_progress_time = submitted_at
                form_submission_hard_deadline = _submission_hard_deadline(
                    submitted_at,
                    deadline,
                )
                post_submit_grace_until = min(
                    submitted_at + SAML_UI_POST_SUBMIT_GRACE_SECONDS,
                    form_submission_hard_deadline,
                )
                processing_extensions_used = 0
                form_submission_kind = kind
                # Preserve the pre-action baseline. Capturing after the click
                # can miss a transition that renders inside the 250 ms pause.
                form_submission_fingerprint = last_ui_fingerprint

            while time.monotonic() < deadline:
                _raise_if_cancelled()
                if _auth_capture_complete():
                    break
                if _is_vpn_url(page.url) and protocol != "anyconnect":
                    break

                progressed = False
                form_submitted = False
                submitted_form_kind = None
                adfs_mode = _is_adfs_page()

                totp_available = bool(totp_secret and auto_totp)
                otp_loc = _find_otp_input()
                # Microsoft's MFA panels can retain the previous controls for
                # several seconds while the next method loads. Do not click or
                # reinterpret that stale panel during the transition.
                now = time.monotonic()
                current_ui_fingerprint = _auth_ui_fingerprint()
                fingerprint_changed = current_ui_fingerprint != last_ui_fingerprint
                if fingerprint_changed:
                    last_ui_fingerprint = current_ui_fingerprint
                    last_substantive_progress_time = now
                    if form_submission_fingerprint is None:
                        processing_extensions_used = 0
                processing_visible = _auth_ui_processing()
                previous_grace_until = post_submit_grace_until
                post_submit_grace_until, processing_extensions_used = (
                    _extend_processing_grace(
                        now,
                        post_submit_grace_until,
                        form_submission_fingerprint is not None,
                        processing_extensions_used,
                        hard_deadline=(
                            form_submission_hard_deadline or None
                        ),
                    )
                )
                if post_submit_grace_until > previous_grace_until:
                    _report_progress(
                        "saml-ui-processing-extended"
                        if processing_visible
                        else "saml-ui-submit-wait-extended"
                    )
                if form_submission_fingerprint is None:
                    post_submit_grace_until = 0.0
                    processing_extensions_used = 0
                can_switch_mfa = (
                    now - last_mfa_switch_time
                    >= MICROSOFT_MFA_TRANSITION_TIMEOUT_SECONDS
                )
                actual_number_match_detected, number_match = _number_match_state()
                authenticator_push_detected = (
                    actual_number_match_detected
                    or _page_has_text(list(MICROSOFT_AUTHENTICATOR_PUSH_MARKERS))
                )
                number_match_detected = authenticator_push_detected
                mfa_started = mfa_started or bool(otp_loc or number_match_detected)

                if (
                    form_submission_fingerprint is not None
                    and form_submission_kind == "password-unknown"
                ):
                    if (
                        microsoft_credential_lookup_generation
                        > password_submission_lookup_generation
                        or microsoft_credential_lookup_pending > 0
                    ):
                        credential_lookup_submission_attempts += 1
                        if credential_lookup_submission_attempts > 2:
                            raise RuntimeError(
                                "Microsoft repeated credential discovery without "
                                "accepting the password form"
                            )
                        form_submission_kind = "credential-lookup"
                        filled_password = False
                        password_input_ready_since = 0.0
                        password_input_identity = None
                        password_submission_classify_until = 0.0
                        _report_progress("credential-lookup-submitted")
                    elif now >= password_submission_classify_until:
                        form_submission_kind = "password"
                        password_submission_classify_until = 0.0
                        _report_progress("password-submitted")

                credential_error_visible = _credential_error_visible()
                if (
                    form_submission_fingerprint is not None
                    and credential_error_visible
                ):
                    raise RuntimeError(
                        "The identity provider rejected the submitted credentials or code"
                    )

                password_field_visible = bool(
                    form_submission_kind in {"username", "credential-lookup"}
                    and _find_password_input() is not None
                )

                account_state_visible = _page_has_text([
                    "Pick an account",
                    "issue looking up your account",
                    "Use another account",
                    "Anderes Konto verwenden",
                ])
                password_submission_pending = form_submission_kind in {
                    "password",
                    "password-unknown",
                }
                if (
                    password_submission_pending
                    and fingerprint_changed
                    and account_state_visible
                ):
                    raise RuntimeError(
                        "Microsoft returned to account selection after password submission"
                    )

                if password_submission_pending:
                    recognized_post_submit_state = bool(
                        otp_loc
                        or number_match_detected
                        or (
                            fingerprint_changed
                            and (
                                _page_has_text(list(MICROSOFT_KMSI_MARKERS))
                                or _page_has_text(
                                    list(MICROSOFT_PASSKEY_REGISTRATION_MARKERS)
                                )
                                or _actionable_method_choice_visible()
                                or _method_picker_context_visible()
                            )
                        )
                    )
                else:
                    recognized_post_submit_state = bool(
                        otp_loc
                        or number_match_detected
                        or password_field_visible
                        or (
                            fingerprint_changed
                            and (
                                _page_has_text(list(MICROSOFT_PASSKEY_MARKERS))
                                or _page_has_text(list(MICROSOFT_KMSI_MARKERS))
                                or account_state_visible
                                or _actionable_method_choice_visible()
                                or _method_picker_context_visible()
                            )
                        )
                    )
                if recognized_post_submit_state:
                    post_submit_grace_until = 0.0
                    form_submission_fingerprint = None
                    form_submission_kind = None
                    form_submission_hard_deadline = 0.0
                    password_submission_classify_until = 0.0
                if otp_loc:
                    password_bridge_pending_until = 0.0

                if (
                    form_submission_fingerprint is not None
                    and form_submission_hard_deadline > 0.0
                    and now >= form_submission_hard_deadline
                ):
                    # A submitted credential or MFA form is not a stale static
                    # page. Reloading it can duplicate a sign-in or phone prompt,
                    # so stop only at its immutable, protocol-clamped deadline.
                    raise RuntimeError(
                        "Microsoft did not complete the submitted sign-in within "
                        "the adaptive processing limit"
                    )

                form_submission_pending = bool(
                    form_submission_fingerprint is not None
                    and now < post_submit_grace_until
                )

                intentional_transition_pending = bool(
                    otp_loc
                    or number_match_detected
                    or form_submission_pending
                    or (
                        last_mfa_switch_time > 0.0
                        and not can_switch_mfa
                    )
                    or now < mfa_picker_pending_until
                    or now < mfa_method_pending_until
                    or now < number_match_switch_deadline
                    or now < primary_credential_picker_pending_until
                    or now < password_bridge_pending_until
                    or microsoft_credential_lookup_pending > 0
                    or now < microsoft_credential_lookup_settle_until
                )
                if (
                    not intentional_transition_pending
                    and _recover_stale_browser_ui(now)
                ):
                    continue
                if form_submission_pending and not (otp_loc or number_match_detected):
                    _interruptible_pause(0.1)
                    continue
                if (
                    microsoft_credential_lookup_pending > 0
                    or time.monotonic()
                    < microsoft_credential_lookup_settle_until
                ):
                    _interruptible_pause(0.1)
                    continue
                if not otp_loc and password_bridge_pending_until > 0.0:
                    password_input = _find_password_input()
                    if password_input is not None:
                        password_bridge_pending_until = 0.0
                        filled_password = False
                        password_input_ready_since = 0.0
                        password_input_identity = None
                    elif now < password_bridge_pending_until:
                        _interruptible_pause(0.2)
                        continue
                    else:
                        raise RuntimeError(
                            "Microsoft did not render password entry after selecting "
                            "the password bridge to TOTP"
                        )

                # The old OTP form can remain visible while Microsoft's method
                # picker becomes ready. Once the picker is genuinely visible,
                # stop treating that retained input as the active MFA state.
                if (
                    otp_loc
                    and (
                        otp_alternate_attempts
                        or method_selection_pending == "Authenticator push"
                    )
                    and _push_method_visible()
                ):
                    otp_loc = None

                if otp_loc and last_totp_counter is not None:
                    current_error = _totp_error_signature(otp_loc)
                    totp_rejected = bool(
                        current_error
                        and current_error != totp_error_before_submit
                    )
                    if totp_rejected:
                        totp_disabled_for_attempt = True
                        _report_progress("mfa-totp-rejected")
                        raise RuntimeError(
                            "Microsoft rejected the configured TOTP code; update the TOTP "
                            "secret, or explicitly set mfa-preference=push to use the phone"
                        )

                if totp_disabled_for_attempt and otp_loc:
                    # Never let generic Continue/Next handling resubmit a code
                    # after the automatic TOTP path has been abandoned.
                    _wait_until_ready(0.2)
                    continue

                if (
                    otp_loc
                    and not number_match_detected
                    and last_totp_counter is None
                    and (mfa_preference == "push" or not totp_available)
                ):
                    if method_selection_pending == "Authenticator push":
                        if not can_switch_mfa:
                            _interruptible_pause(0.2)
                            continue
                        raise RuntimeError(
                            "Microsoft did not transition to Authenticator phone approval"
                        )
                    if not can_switch_mfa:
                        _interruptible_pause(0.2)
                        continue
                    if otp_alternate_attempts < 2:
                        otp_alternate_attempts += 1
                        if _open_alternate_methods():
                            _report_progress("mfa-alternate-methods-opened")
                            last_mfa_switch_time = time.monotonic()
                            _interruptible_pause(0.25)
                            continue
                        if otp_alternate_attempts < 2:
                            _interruptible_pause(0.5)
                            continue
                    if mfa_preference == "push":
                        raise RuntimeError(
                            "Microsoft requires a verification code and did not offer "
                            "Authenticator push approval"
                        )
                    if not totp_available:
                        raise RuntimeError(
                            "Microsoft requires a verification code but no TOTP secret is configured"
                        )

                if not otp_loc and _page_has_text(
                    list(MICROSOFT_PASSKEY_REGISTRATION_MARKERS)
                ):
                    if _click_action(list(MICROSOFT_SKIP_OPTIONAL_LABELS)):
                        _report_progress("passkey-registration-skipped")
                        _interruptible_pause(0.25)
                        continue
                    raise RuntimeError(
                        "Microsoft requires interactive passkey registration, which cannot "
                        "be completed by the headless VPN login"
                    )

                should_prefer_totp = _prefer_totp_for_number_match(
                    mfa_preference,
                    totp_available,
                    totp_disabled_for_attempt,
                )
                totp_choice_visible = bool(
                    not otp_loc and _totp_method_visible()
                )
                picker_transition_pending = now < mfa_picker_pending_until
                adaptive_action = _adaptive_mfa_action(
                    prefer_totp=should_prefer_totp,
                    otp_input_visible=bool(otp_loc),
                    authenticator_challenge_visible=number_match_detected,
                    totp_choice_visible=totp_choice_visible,
                    picker_transition_pending=picker_transition_pending,
                )

                # A real verification-code input always wins over stale text
                # left behind by the previous Authenticator challenge panel.
                if adaptive_action == "submit-totp":
                    number_match_detected = False
                    method_selection_pending = None
                    mfa_picker_pending_until = 0.0
                    mfa_picker_settle_until = 0.0
                    mfa_method_pending_until = 0.0
                    number_match_switch_deadline = 0.0
                    number_match_detected_reported = False

                if number_match_detected:
                    if should_prefer_totp:
                        if not number_match_detected_reported:
                            _report_progress(
                                "mfa-number-match-detected"
                                if actual_number_match_detected
                                else "mfa-authenticator-push-detected"
                            )
                            number_match_detected_reported = True
                        if number_match_switch_deadline <= 0.0:
                            number_match_switch_deadline = (
                                now + MICROSOFT_MFA_TRANSITION_TIMEOUT_SECONDS
                            )
                        if method_selection_pending == "TOTP":
                            if now < mfa_method_pending_until:
                                _interruptible_pause(0.2)
                                continue
                            raise RuntimeError(
                                "Microsoft did not transition to the configured TOTP method"
                            )

                        if adaptive_action == "select-totp":
                            if _select_totp_method():
                                method_selection_pending = "TOTP"
                                mfa_method_pending_until = (
                                    now + MICROSOFT_MFA_TRANSITION_TIMEOUT_SECONDS
                                )
                                mfa_picker_pending_until = 0.0
                                mfa_picker_settle_until = 0.0
                                number_match_switch_deadline = 0.0
                                _report_progress("mfa-totp-direct-selected")
                                last_mfa_switch_time = now
                                _interruptible_pause(0.25)
                                continue
                        elif adaptive_action == "wait-for-picker":
                            _interruptible_pause(0.2)
                            continue
                        elif (
                            adaptive_action == "open-alternate-methods"
                            and now < number_match_switch_deadline
                        ):
                            if _open_alternate_methods():
                                _report_progress("mfa-alternate-methods-opened")
                                last_mfa_switch_time = now
                                mfa_picker_pending_until = (
                                    now + MICROSOFT_MFA_TRANSITION_TIMEOUT_SECONDS
                                )
                                mfa_picker_settle_until = (
                                    now + MICROSOFT_METHOD_PICKER_SETTLE_SECONDS
                                )
                                _interruptible_pause(0.25)
                                continue
                        if now < number_match_switch_deadline:
                            _interruptible_pause(0.5)
                            continue
                        raise RuntimeError(
                            "Microsoft showed Authenticator number matching but did not "
                            "offer the configured TOTP method after switching sign-in methods"
                        )

                    if not _should_notify_number_match(
                        mfa_preference,
                        totp_available,
                    ):
                        raise RuntimeError(
                            "Phone approval is disabled while a TOTP secret is configured; "
                            "update the TOTP secret or explicitly set mfa-preference=push"
                        )
                    if actual_number_match_detected and not number_match:
                        raise RuntimeError(
                            "Microsoft Authenticator number matching is required, but the "
                            "two-digit approval number could not be read unambiguously"
                        )
                    if not actual_number_match_detected:
                        # Ordinary approve/deny push has no two-digit value.
                        # Explicit push mode waits for the IdP callback.
                        _interruptible_pause(0.2)
                        continue
                    if number_match != last_number_match:
                        if _notify_number_match(number_match):
                            _report_progress("mfa-number-match-notified")
                        else:
                            raise RuntimeError(
                                "Microsoft Authenticator number matching is required, but the "
                                "desktop approval notification could not be shown"
                            )
                        last_number_match = number_match
                        totp_disabled_for_attempt = True
                        method_selection_pending = None
                    _interruptible_pause(0.2)
                    continue
                else:
                    number_match_detected_reported = False
                    if not picker_transition_pending:
                        number_match_switch_deadline = 0.0

                if last_number_match is not None:
                    _close_number_match_notification()
                    last_number_match = None

                # After clicking away from number matching, Microsoft can leave
                # a blank or partially rendered panel before the TOTP tile
                # appears. Poll that transition without running generic clicks.
                if not otp_loc and should_prefer_totp and picker_transition_pending:
                    if totp_choice_visible and _select_totp_method():
                        method_selection_pending = "TOTP"
                        mfa_method_pending_until = (
                            now + MICROSOFT_MFA_TRANSITION_TIMEOUT_SECONDS
                        )
                        mfa_picker_pending_until = 0.0
                        mfa_picker_settle_until = 0.0
                        _report_progress("mfa-totp-method-selected")
                        last_mfa_switch_time = now
                        _interruptible_pause(0.25)
                        continue
                    if _password_method_visible():
                        if now < mfa_picker_settle_until:
                            _interruptible_pause(0.2)
                            continue
                        if (
                            password_bridge_attempts < 1
                            and _select_password_method()
                        ):
                            password_bridge_attempts += 1
                            filled_password = False
                            password_input_ready_since = 0.0
                            password_input_identity = None
                            mfa_picker_pending_until = 0.0
                            mfa_picker_settle_until = 0.0
                            number_match_switch_deadline = 0.0
                            password_bridge_pending_until = (
                                now + MICROSOFT_MFA_TRANSITION_TIMEOUT_SECONDS
                            )
                            last_mfa_switch_time = now
                            _report_progress("mfa-password-bridge-selected")
                            _interruptible_pause(0.25)
                            continue
                    _interruptible_pause(0.2)
                    continue
                if (
                    not otp_loc
                    and should_prefer_totp
                    and mfa_picker_pending_until > 0.0
                ):
                    raise RuntimeError(
                        "Microsoft did not render the configured TOTP method after "
                        "opening alternate sign-in methods"
                    )

                # Once a method is selected, suppress unrelated account and
                # generic form actions until its input appears or the bounded
                # transition expires.
                if not otp_loc and method_selection_pending:
                    if now < mfa_method_pending_until:
                        _interruptible_pause(0.2)
                        continue
                    raise RuntimeError(
                        f"Microsoft did not transition after selecting {method_selection_pending}"
                    )

                if not otp_loc and primary_credential_picker_pending_until > 0.0:
                    if _password_method_visible() and _select_password_method():
                        primary_credential_picker_pending_until = 0.0
                        _report_progress("passkey-password-fallback-selected")
                        _interruptible_pause(0.25)
                        continue
                    if now < primary_credential_picker_pending_until:
                        _interruptible_pause(0.2)
                        continue
                    raise RuntimeError(
                        "Microsoft did not offer password sign-in after leaving the passkey prompt"
                    )

                if not otp_loc and _page_has_text(list(MICROSOFT_PASSKEY_MARKERS)):
                    passkey_action = _leave_passkey_prompt()
                    if passkey_action:
                        _report_progress(passkey_action)
                        last_mfa_switch_time = now
                        if passkey_action == "passkey-alternate-methods-opened":
                            primary_credential_picker_pending_until = (
                                now + MICROSOFT_MFA_TRANSITION_TIMEOUT_SECONDS
                            )
                        _interruptible_pause(0.25)
                    else:
                        raise RuntimeError(
                            "Microsoft requested an interactive passkey and did not offer "
                            "password or another sign-in method"
                        )
                    continue

                prefer_totp = (
                    mfa_preference != "push"
                    and totp_available
                    and not totp_disabled_for_attempt
                )
                requested_method_visible = (
                    _totp_method_visible() if prefer_totp else _push_method_visible()
                )
                if not otp_loc and requested_method_visible:
                    mfa_started = True
                    otp_alternate_attempts = 0
                    requested_method = "TOTP" if prefer_totp else "Authenticator push"
                    selected = _select_totp_method() if prefer_totp else _select_push_method()
                    if selected:
                        method_selection_pending = requested_method
                        mfa_method_pending_until = (
                            now + MICROSOFT_MFA_TRANSITION_TIMEOUT_SECONDS
                        )
                        _report_progress(
                            "mfa-totp-method-selected"
                            if prefer_totp
                            else "mfa-authenticator-push-selected"
                        )
                        last_mfa_switch_time = time.monotonic()
                        _interruptible_pause(0.25)
                        continue
                    raise RuntimeError(
                        f"Microsoft did not offer the requested {requested_method} MFA method"
                    )

                if otp_loc:
                    method_selection_pending = None
                    mfa_method_pending_until = 0.0

                # Step 2: account selection / alternate account
                if _page_has_text(["Pick an account", "issue looking up your account"]):
                    candidates = [username] if username else []
                    if username and "@" in username:
                        local_part, domain_part = username.split("@", 1)
                        candidates.extend([local_part, f"@{domain_part}"])
                    if candidates and _click_account_tile(candidates):
                        progressed = True
                    elif _click_action([
                        "Use another account",
                        "Sign in with another account",
                        "Use a different account",
                        "Add another account",
                        "Mit einem anderen Konto anmelden",
                        "Anderes Konto verwenden",
                    ]):
                        progressed = True
                    elif _click_action(["Next", "Weiter"]):
                        progressed = True
                    elif _click_known_ids(["idSIButton9"]):
                        progressed = True
                else:
                    if username and _click_account_tile([username]):
                        progressed = True

                    if not progressed:
                        if _click_action([
                            "Use another account",
                            "Sign in with another account",
                            "Use a different account",
                            "Add another account",
                            "Mit einem anderen Konto anmelden",
                            "Anderes Konto verwenden",
                        ]):
                            progressed = True

                # Step 3: username field (prefer explicit "Use another account" if no field yet)
                if username and (adfs_mode or not filled_username):
                    user_loc = (
                        _find_input_by_ids(["userNameInput", "username", "loginfmt", "i0116", "identifierId", "email"])
                        or _find_input_by_labels(["Benutzername", "Benutzer-ID", "Benutzer ID", "User name", "Username", "E-Mail", "Email"])
                        or _find_best_input("username")
                    )
                    if user_loc:
                        pass_loc = _find_best_input("password")
                        pass_present = pass_loc is not None
                        try:
                            current_value = _normalize_text(user_loc.input_value())
                        except Exception:
                            current_value = ""
                        try:
                            if adfs_mode or username.lower() not in current_value:
                                user_loc.fill(username)
                            filled_username = True
                            progressed = True
                            if not pass_present:
                                form_submitted = _click_action([
                                    "Next",
                                    "Weiter",
                                    "Continue",
                                    "Suivant",
                                    "Avanti",
                                ])
                                if not form_submitted:
                                    form_submitted = _click_known_ids(["idSIButton9"])
                                if form_submitted:
                                    submitted_form_kind = "username"
                                    _report_progress("username-submitted")
                        except RuntimeError:
                            raise
                        except Exception:
                            pass
                    else:
                        if _click_action(["Use another account", "Sign in with another account"]):
                            progressed = True

                # Microsoft resolves the account with GetCredentialType before
                # replacing the username panel. Never inspect or submit a
                # password control in the same loop as that asynchronous click.
                if form_submitted and submitted_form_kind == "username":
                    submitted_at = time.monotonic()
                    _arm_submission_wait("username", submitted_at)
                    _interruptible_pause(0.25)
                    continue

                # Step 4: password field
                if password and (adfs_mode or not filled_password):
                    pass_loc = _find_password_input()
                    if pass_loc:
                        password_now = time.monotonic()
                        current_password_identity = _password_control_identity(pass_loc)
                        if (
                            current_password_identity is None
                            or current_password_identity != password_input_identity
                            or password_input_ready_since <= 0.0
                        ):
                            password_input_identity = current_password_identity
                            password_input_ready_since = password_now
                            _interruptible_pause(0.1)
                            continue
                        if (
                            microsoft_credential_lookup_pending > 0
                            or password_now
                            < microsoft_credential_lookup_settle_until
                            or password_now - password_input_ready_since
                            < MICROSOFT_PASSWORD_STABILITY_SECONDS
                        ):
                            _interruptible_pause(0.1)
                            continue
                        try:
                            lookup_generation_before = (
                                microsoft_credential_lookup_generation
                            )
                            if adfs_mode or _input_value_empty(pass_loc):
                                pass_loc.fill(password)
                            progressed = True
                            form_submitted = _submit_password(pass_loc)
                            if form_submitted:
                                password_input_ready_since = 0.0
                                password_input_identity = None
                                filled_password = True
                                password_submission_lookup_generation = (
                                    lookup_generation_before
                                )
                                password_submission_classify_until = (
                                    time.monotonic() + 1.0
                                )
                                submitted_form_kind = "password-unknown"
                                _report_progress("password-action-submitted")
                        except RuntimeError:
                            raise
                        except Exception:
                            pass
                    else:
                        password_input_ready_since = 0.0
                        password_input_identity = None

                if form_submitted:
                    submitted_at = time.monotonic()
                    _interruptible_pause(0.25)
                    _arm_submission_wait(
                        submitted_form_kind or "generic",
                        submitted_at,
                    )
                    continue

                # ADFS direct submit fallback (JS-based)
                if adfs_mode and username and password and not progressed and adfs_submit_attempts < 3:
                    try:
                        result = page.evaluate(
                            """(creds) => {
                                const user = document.getElementById('userNameInput') || document.querySelector('input[name="UserName"]');
                                const pass = document.getElementById('passwordInput') || document.querySelector('input[name="Password"]');
                                if (user) user.value = creds.user;
                                if (pass) pass.value = creds.pass;
                                const btn = document.getElementById('submitButton') || document.querySelector('input[type="submit"]');
                                if (btn) btn.click();
                                return {hasUser: !!user, hasPass: !!pass, hasBtn: !!btn};
                            }""",
                            {"user": username, "pass": password},
                        )
                        adfs_submit_attempts += 1
                        if result.get("hasUser") or result.get("hasPass") or result.get("hasBtn"):
                            progressed = True
                            if result.get("hasBtn"):
                                submitted_at = time.monotonic()
                                _arm_submission_wait("password", submitted_at)
                                _interruptible_pause(0.25)
                                continue
                    except Exception:
                        pass

                # Step 5: OTP / MFA
                totp_submitted = False
                waiting_for_fresh_totp = False
                if totp_secret and auto_totp and not totp_disabled_for_attempt:
                    otp_loc = otp_loc or _find_otp_input()
                    if otp_loc:
                        if not otp_input_reported:
                            _report_progress("mfa-totp-input-found")
                            otp_input_reported = True
                        try:
                            totp_counter = int(time.time() // 30)
                            if _should_submit_totp_counter(
                                last_totp_counter,
                                totp_counter,
                            ):
                                if (
                                    totp_submission_attempts
                                    >= MICROSOFT_TOTP_MAX_SUBMISSIONS
                                ):
                                    raise RuntimeError(
                                        "Microsoft TOTP form did not progress after one "
                                        "fresh-code retry"
                                    )
                                # Avoid submitting a code that will expire while the
                                # Microsoft form is processing it.
                                valid_for = seconds_until_totp_rotation()
                                if valid_for < 5.0:
                                    _interruptible_pause(valid_for + 0.1)
                                    totp_counter = int(time.time() // 30)
                                if _should_submit_totp_counter(
                                    last_totp_counter,
                                    totp_counter,
                                ):
                                    totp_code = generate_totp(totp_secret)
                                    if not re.fullmatch(r"[0-9]{6,8}", totp_code or ""):
                                        raise ValueError("invalid generated TOTP")
                                    otp_loc.fill(totp_code)
                                    totp_error_before_submit = _totp_error_signature(otp_loc)
                                    progressed = True
                                    submitted = _submit_otp(otp_loc)
                                    if not submitted:
                                        raise RuntimeError("Could not submit the Microsoft verification code form")
                                    if submitted:
                                        last_totp_counter = totp_counter
                                        totp_submission_attempts += 1
                                        totp_submitted = True
                                        _report_progress("mfa-totp-submitted")
                                else:
                                    waiting_for_fresh_totp = True
                            else:
                                waiting_for_fresh_totp = True
                        except RuntimeError:
                            raise
                        except Exception as exc:
                            raise RuntimeError(
                                "Could not generate or submit the configured TOTP code"
                            ) from exc
                    else:
                        otp_input_reported = False

                if totp_submitted:
                    submitted_at = time.monotonic()
                    _arm_submission_wait("totp", submitted_at)
                    _interruptible_pause(0.25)
                    continue

                if waiting_for_fresh_totp:
                    # Do not let generic Continue/Next fallbacks resubmit the
                    # same code while Microsoft is still processing it.
                    _interruptible_pause(0.1)
                    continue

                # Microsoft can present a localized "Stay signed in?" page
                # after TOTP succeeds. Accepting it is appropriate for the
                # plugin's dedicated persistent browser profile and avoids a
                # full login on the next connection.
                if _page_has_text(list(MICROSOFT_KMSI_MARKERS)):
                    kmsi_submitted = _click_action(
                        list(MICROSOFT_KMSI_ACCEPT_LABELS)
                    )
                    if not kmsi_submitted:
                        kmsi_submitted = _click_known_ids([
                            "idSIButton9",
                            "acceptButton",
                            "primaryButton",
                        ])
                    if not kmsi_submitted:
                        kmsi_submitted = _click_first_selector([
                            "button[type='submit']",
                            "input[type='submit']",
                        ])
                    if kmsi_submitted:
                        _report_progress("microsoft-kmsi-accepted")
                        submitted_at = time.monotonic()
                        _arm_submission_wait("kmsi", submitted_at)
                        _interruptible_pause(0.25)
                        continue

                # Fallback clicks for common prompts
                if _click_action(["Use your password instead", "Use password instead"]):
                    last_progress_time = time.monotonic()
                    _interruptible_pause(0.25)
                    continue
                fallback_submitted = _click_action([
                    "OK",
                    "Continue",
                    "Next",
                    "Weiter",
                ])
                if not fallback_submitted:
                    fallback_submitted = _click_known_ids(["idSIButton9", "submitButton"])
                if fallback_submitted:
                    submitted_at = time.monotonic()
                    _arm_submission_wait("generic", submitted_at)
                    _interruptible_pause(0.25)
                    continue
                progressed = progressed or fallback_submitted

                if progressed:
                    last_progress_time = time.monotonic()
                    try:
                        remaining_ms = _remaining_timeout_ms(deadline)
                        if remaining_ms > 0:
                            page.wait_for_load_state(
                                "domcontentloaded",
                                timeout=min(1500, remaining_ms),
                            )
                    except Exception:
                        pass
                    _wait_until_ready(0.2)
                else:
                    now = time.monotonic()
                    if now - last_wait_report_time >= 5.0:
                        _report_progress(
                            f"waiting host={_page_host()} ui={'yes' if _auth_ui_ready() else 'no'}"
                        )
                        last_wait_report_time = now
                    if (
                        blank_login_reloads < 2
                        and "login.microsoftonline.com" in page.url.lower()
                        and not _auth_ui_ready()
                        and time.monotonic() - last_progress_time > 8
                    ):
                        try:
                            blank_login_reloads += 1
                            last_progress_time = time.monotonic()
                            _report_progress("microsoft-blank-page-reload")
                            if debug:
                                print("    [DEBUG] Microsoft login page stayed blank; reloading")
                            remaining_ms = _remaining_timeout_ms(deadline)
                            if remaining_ms <= 0:
                                break
                            page.reload(timeout=min(15000, remaining_ms), wait_until="domcontentloaded")
                            _wait_until_ready(1.0)
                            continue
                        except Exception as reload_error:
                            if debug:
                                print(f"    [DEBUG] Microsoft login reload failed: {reload_error}")
                    _wait_until_ready(0.1)

            if (
                form_submission_fingerprint is not None
                and not _auth_capture_complete()
                and not _is_vpn_url(page.url)
            ):
                raise RuntimeError(
                    "Microsoft did not complete the submitted sign-in within "
                    "the adaptive processing limit"
                )

            remaining_ms = _remaining_timeout_ms(deadline)
            if remaining_ms > 0:
                _report_progress(f"waiting-for-vpn-callback host={_page_host()}")
                _wait_for_vpn_callback(remaining_ms)
            _raise_if_cancelled()
            if (
                not _auth_capture_complete()
                and not _is_vpn_url(page.url)
            ):
                raise RuntimeError(
                    "SAML authentication did not complete before the protocol deadline"
                )

            # Collect cookies
            all_cookies = context.cookies()
            vpn_cookies = _collect_vpn_cookies()

            vpn_cookies = _merge_saml_artifacts(
                vpn_cookies,
                saml_result,
                protocol,
                gp_prelogin_cookie,
                gp_gateway_ip,
            )

            # Avoid returning only helper metadata without a real auth artifact
            if set(vpn_cookies.keys()) == {"_gateway_ip"}:
                vpn_cookies = {}
            if protocol == "anyconnect" and not _has_usable_auth_artifact(vpn_cookies):
                _report_progress(f"authentication-incomplete host={_page_host()}")
                if debug:
                    print(
                        "    [DEBUG] Ignoring incomplete AnyConnect auth result "
                        f"(cookies={list(vpn_cookies.keys())})"
                    )
                    try:
                        _secure_screenshot("/tmp/vpn-auth-incomplete.png")
                        print("    [DEBUG] Screenshot: /tmp/vpn-auth-incomplete.png")
                    except Exception:
                        pass
                vpn_cookies = {}

            if debug:
                final_url_parts = urllib.parse.urlsplit(page.url)
                debug_out = {
                    "vpn_server": vpn_server,
                    "vpn_server_host": vpn_server_host,
                    "vpn_server_netloc": vpn_server_netloc,
                    "vpn_server_ip": vpn_server_ip,
                    "final_host": final_url_parts.hostname or "unknown",
                    "final_path": final_url_parts.path or "/",
                    "cookies": list(vpn_cookies.keys()),
                    "cookie_domains": sorted({c.get("domain", "") for c in all_cookies}),
                    "saml_response": bool(saml_result["saml_response"]),
                    "prelogin_cookie": bool(vpn_cookies.get("prelogin-cookie")),
                }
                try:
                    with open("/tmp/nm-vpn-auth-debug.json", "w") as f:
                        json.dump(debug_out, f, indent=2)
                    os.chmod("/tmp/nm-vpn-auth-debug.json", 0o600)
                except Exception:
                    pass

            _close_context()
            return vpn_cookies
        except Exception as e:
            if debug:
                try:
                    _secure_screenshot("/tmp/vpn-auth-error.png")
                except Exception:
                    pass
            _close_context()
            raise e
