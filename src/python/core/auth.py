"""SAML authentication via headless Playwright with heuristic form handling."""

from __future__ import annotations

import base64
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
)

MICROSOFT_PASSWORD_METHOD_LABELS = (
    "Use your password instead",
    "Use password instead",
    "Sign in with your password",
    "Stattdessen Kennwort verwenden",
    "Mit Kennwort anmelden",
    "Mit Ihrem Kennwort anmelden",
)

MICROSOFT_PASSKEY_MARKERS = (
    "Use your passkey",
    "Sign in with a passkey",
    "Face, fingerprint, PIN, or security key",
    "Passkey verwenden",
    "Mit einem Passkey anmelden",
    "Gesichtserkennung, Fingerabdruck, PIN oder Sicherheitsschlüssel",
)

MICROSOFT_NUMBER_MATCH_MARKERS = (
    "Approve sign in request",
    "Approve a sign-in request",
    "Enter the number shown to sign in",
    "Anmeldeanforderung bestätigen",
    "Geben Sie die Nummer ein",
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
) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """Get prelogin-cookie and SAML request for GlobalProtect."""
    url = f"https://{server}/global-protect/prelogin.esp"
    retry_env = os.environ.get("MS_SSO_GP_PRELOGIN_RETRIES", "3").strip()
    delay_env = os.environ.get("MS_SSO_GP_PRELOGIN_DELAY", "2").strip()
    client_os = get_gp_client_os()
    os_version = gp_os_version or get_gp_os_version()
    host_id = socket.gethostname() or "localhost"
    request_body = urllib.parse.urlencode({
        "tmp": "tmp",
        "clientVer": "4100",
        "clientos": client_os,
        "os-version": os_version,
        "host-id": host_id,
        "ipv6-support": "yes",
        "default-browser": "1",
        "cas-support": "yes",
    }).encode("utf-8")
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
    fallback_url = f"{url}?tmp=tmp&clientVer=4100&clientos={urllib.parse.quote(client_os)}"
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
        )
        if debug:
            print(f"    [DEBUG] prelogin-cookie: {gp_prelogin_cookie[:20] if gp_prelogin_cookie else None}...")
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
            cache_candidates = []
            if real_user != "root":
                cache_candidates.append(
                    os.path.join(home, ".cache", "ms-sso-openconnect", "browser-session")
                )
            cache_candidates.extend([
                "/var/cache/ms-sso-openconnect/browser-session",
                "/tmp/ms-sso-openconnect/browser-session",
            ])

            for candidate in cache_candidates:
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
            if _is_vpn_url(request.url):
                vpn_request_event.set()
                ui_change_event.set()
                if debug:
                    print(f"    [DEBUG] Request to VPN: {request.url[:80]}...")
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
            if not _is_vpn_url(response.url):
                return
            ui_change_event.set()
            try:
                headers = response.headers
                if debug:
                    print(f"    [DEBUG] Response from VPN: {response.url[:80]}... status={response.status}")
                    for h in ["prelogin-cookie", "saml-username", "portal-userauthcookie", "set-cookie", "location"]:
                        if h in headers:
                            val = headers[h][:80] if len(headers[h]) > 80 else headers[h]
                            print(f"    [DEBUG] Header {h}: {val}...")
                if "prelogin-cookie" in headers:
                    saml_result["prelogin_cookie"] = headers["prelogin-cookie"]
                if "saml-username" in headers:
                    saml_result["saml_username"] = headers["saml-username"]
                if "portal-userauthcookie" in headers:
                    saml_result["portal_userauthcookie"] = headers["portal-userauthcookie"]
            except Exception:
                pass

        page.on("request", handle_request)
        page.on("response", handle_response)
        page.on("load", lambda *_: ui_change_event.set())
        page.on("domcontentloaded", lambda *_: ui_change_event.set())
        page.on("framenavigated", lambda *_: ui_change_event.set())

        def _first_visible(locator, limit: int = 20):
            try:
                count = min(locator.count(), limit)
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
                _find_input_by_ids(["idTxtBx_SAOTCC_OTC", "idTxtBx_SAOTCC_OTP", "otp", "otc", "code"])
                or _find_input_by_labels([
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

        def _click_action(labels: list[str]) -> bool:
            patterns = [re.compile(re.escape(label), re.IGNORECASE) for label in labels]
            for frame in page.frames:
                for pattern in patterns:
                    for role in ["button", "link"]:
                        try:
                            candidate = _first_visible(frame.get_by_role(role, name=pattern))
                            if candidate is not None:
                                candidate.click()
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
                                        candidate.click()
                                        return True
                                except Exception:
                                    continue
                    except Exception:
                        continue
                    try:
                        candidate = _first_visible(frame.get_by_text(pattern, exact=False))
                        if candidate is not None:
                            candidate.click()
                            return True
                    except Exception:
                        continue
            return False

        def _action_available(labels: list[str]) -> bool:
            patterns = [re.compile(re.escape(label), re.IGNORECASE) for label in labels]
            for frame in page.frames:
                for pattern in patterns:
                    for role in ("button", "link"):
                        try:
                            if _first_visible(frame.get_by_role(role, name=pattern)) is not None:
                                return True
                        except Exception:
                            continue
                    try:
                        submits = frame.locator("input[type='submit']")
                        for index in range(min(submits.count(), 10)):
                            candidate = submits.nth(index)
                            value = _normalize_text(candidate.get_attribute("value"))
                            if value and pattern.search(value) and candidate.is_visible():
                                return True
                    except Exception:
                        continue
            return False

        def _click_known_ids(ids: list[str]) -> bool:
            for frame in page.frames:
                for element_id in ids:
                    try:
                        candidate = _first_visible(frame.locator(f"#{element_id}"))
                        if candidate is not None:
                            candidate.click()
                            return True
                    except Exception:
                        continue
            return False

        def _click_first_selector(selectors) -> bool:
            loc = _find_visible_in_frames(list(selectors))
            if loc is None:
                return False
            try:
                loc.click()
                return True
            except Exception:
                return False

        def _submit_otp(otp_loc) -> bool:
            """Submit only the form that owns the OTP input."""
            labels = [
                "Verify",
                "Überprüfen",
                "Bestätigen",
                "Continue",
                "Weiter",
                "Next",
                "Submit",
            ]
            try:
                form = _first_visible(otp_loc.locator("xpath=ancestor::form[1]"), limit=1)
            except Exception:
                form = None
            if form is not None:
                for label in labels:
                    pattern = re.compile(re.escape(label), re.IGNORECASE)
                    try:
                        button = _first_visible(form.get_by_role("button", name=pattern))
                        if button is not None:
                            button.click()
                            return True
                    except Exception:
                        continue
                try:
                    submit = _first_visible(form.locator("input[type='submit'], button[type='submit']"))
                    if submit is not None:
                        submit.click()
                        return True
                except Exception:
                    pass
            if _click_known_ids([
                "idSubmit_SAOTCC_Continue",
                "idSIButton9",
                "submitButton",
            ]):
                return True
            try:
                otp_loc.press("Enter")
                return True
            except Exception:
                return False

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

        def _open_alternate_methods() -> bool:
            if _click_action(list(MICROSOFT_ALTERNATE_MFA_LABELS)):
                return True
            return _click_known_ids([
                "idA_SAASTO_Proofs",
                "idA_SAOTCS_SwitchProof",
                "idA_SAASTO_SwitchProof",
            ])

        def _method_picker_visible() -> bool:
            if _find_visible_in_frames(list(MICROSOFT_TOTP_DIRECT_SELECTORS)) is not None:
                return True
            if _find_visible_in_frames(list(MICROSOFT_PUSH_DIRECT_SELECTORS)) is not None:
                return True
            return _action_available(
                list(MICROSOFT_TOTP_METHOD_LABELS) + list(MICROSOFT_PUSH_METHOD_LABELS)
            )

        def _select_totp_method() -> bool:
            if _click_first_selector(MICROSOFT_TOTP_DIRECT_SELECTORS):
                return True
            return _click_action(list(MICROSOFT_TOTP_METHOD_LABELS))

        def _select_push_method() -> bool:
            if _click_first_selector(MICROSOFT_PUSH_DIRECT_SELECTORS):
                return True
            return _click_action(list(MICROSOFT_PUSH_METHOD_LABELS))

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
            if _click_action(list(MICROSOFT_PASSWORD_METHOD_LABELS)):
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
                _secure_screenshot("/tmp/vpn-step1-portal.png")
                print("    [DEBUG] Screenshot: /tmp/vpn-step1-portal.png")

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
                    if saml_result["saml_response"]:
                        session_cookies["SAMLResponse"] = saml_result["saml_response"]
                    if saml_result["prelogin_cookie"]:
                        session_cookies["prelogin-cookie"] = saml_result["prelogin_cookie"]
                    if gp_prelogin_cookie and "prelogin-cookie" not in session_cookies:
                        session_cookies["prelogin-cookie"] = gp_prelogin_cookie
                    _close_context()
                    return session_cookies

            filled_username = False
            filled_password = False
            last_totp_counter = None
            adfs_submit_attempts = 0
            blank_login_reloads = 0
            last_progress_time = time.monotonic()
            last_mfa_switch_time = 0.0
            last_wait_report_time = 0.0
            otp_input_reported = False
            totp_disabled_for_attempt = False
            totp_error_before_submit = None
            last_number_match = None
            alternate_method_attempts = 0
            otp_alternate_attempts = 0
            method_selection_pending = None

            while time.monotonic() < deadline:
                _raise_if_cancelled()
                if _auth_capture_complete():
                    break
                if _is_vpn_url(page.url) and protocol != "anyconnect":
                    break

                progressed = False
                form_submitted = False
                adfs_mode = _is_adfs_page()

                totp_available = bool(totp_secret and auto_totp)
                otp_loc = _find_otp_input()
                # Microsoft's MFA panels can retain the previous controls for
                # several seconds while the next method loads. Do not click or
                # reinterpret that stale panel during the transition.
                can_switch_mfa = time.monotonic() - last_mfa_switch_time >= 8.0
                number_match_detected, number_match = _number_match_state()

                # The old OTP form can remain visible while Microsoft's method
                # picker becomes ready. Once the picker is genuinely visible,
                # stop treating that retained input as the active MFA state.
                if (
                    otp_loc
                    and (
                        otp_alternate_attempts
                        or method_selection_pending == "Authenticator push"
                    )
                    and _method_picker_visible()
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
                            _wait_until_ready(0.2)
                            continue
                        raise RuntimeError(
                            "Microsoft did not transition to Authenticator phone approval"
                        )
                    if otp_alternate_attempts and not can_switch_mfa:
                        _wait_until_ready(0.2)
                        continue
                    if otp_alternate_attempts < 2 and can_switch_mfa:
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

                # A real verification-code input always wins over stale text
                # left behind by the previous Authenticator challenge panel.
                if otp_loc and should_prefer_totp:
                    number_match_detected = False
                    alternate_method_attempts = 0
                    method_selection_pending = None

                # Microsoft can retain the old number-matching text while the
                # alternative-method picker becomes interactive. Once that
                # picker is visible, handle it immediately instead of waiting
                # for the stale challenge panel to disappear.
                if (
                    number_match_detected
                    and should_prefer_totp
                    and (
                        alternate_method_attempts
                        or method_selection_pending == "TOTP"
                    )
                    and _method_picker_visible()
                ):
                    number_match_detected = False

                if number_match_detected:
                    if should_prefer_totp:
                        if method_selection_pending == "TOTP":
                            if not can_switch_mfa:
                                _wait_until_ready(0.2)
                                continue
                            raise RuntimeError(
                                "Microsoft did not transition to the configured TOTP method"
                            )
                        if alternate_method_attempts and not can_switch_mfa:
                            _wait_until_ready(0.2)
                            continue
                        if alternate_method_attempts < 2 and can_switch_mfa:
                            alternate_method_attempts += 1
                            if _open_alternate_methods():
                                _report_progress("mfa-alternate-methods-opened")
                                last_mfa_switch_time = time.monotonic()
                                _interruptible_pause(0.25)
                                continue
                            if alternate_method_attempts < 2:
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
                    if not number_match:
                        raise RuntimeError(
                            "Microsoft Authenticator number matching is required, but the "
                            "two-digit approval number could not be read unambiguously"
                        )
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
                    _wait_until_ready(0.2)
                    continue

                if last_number_match is not None:
                    _close_number_match_notification()
                    last_number_match = None

                if not otp_loc and _method_picker_visible():
                    alternate_method_attempts = 0
                    otp_alternate_attempts = 0
                    prefer_totp = (
                        mfa_preference != "push"
                        and totp_available
                        and not totp_disabled_for_attempt
                    )
                    requested_method = "TOTP" if prefer_totp else "Authenticator push"
                    if method_selection_pending:
                        if not can_switch_mfa:
                            _wait_until_ready(0.2)
                            continue
                        raise RuntimeError(
                            f"Microsoft did not transition after selecting {method_selection_pending}"
                        )
                    selected = _select_totp_method() if prefer_totp else _select_push_method()
                    if selected:
                        method_selection_pending = requested_method
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

                if not otp_loc and _page_has_text(list(MICROSOFT_PASSKEY_MARKERS)):
                    passkey_action = _leave_passkey_prompt()
                    if passkey_action:
                        _report_progress(passkey_action)
                        last_mfa_switch_time = time.monotonic()
                        _interruptible_pause(0.25)
                    else:
                        raise RuntimeError(
                            "Microsoft requested an interactive passkey and did not offer "
                            "password or another sign-in method"
                        )
                    continue

                if otp_loc:
                    method_selection_pending = None

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
                                    _report_progress("username-submitted")
                        except Exception:
                            pass
                    else:
                        if _click_action(["Use another account", "Sign in with another account"]):
                            progressed = True

                # Step 4: password field
                if password and (adfs_mode or not filled_password):
                    pass_loc = (
                        _find_input_by_ids(["passwordInput", "password", "i0118", "passwd", "Passwd"])
                        or _find_input_by_labels(["Kennwort", "Passwort", "Password", "Mot de passe"])
                        or _find_best_input("password")
                    )
                    if pass_loc:
                        try:
                            if adfs_mode or _input_value_empty(pass_loc):
                                pass_loc.fill(password)
                            filled_password = True
                            progressed = True
                            # Include German "Anmelden" label used by Unibas
                            form_submitted = _click_action([
                                "Anmelden",
                                "Sign in",
                                "Connexion",
                                "Accedi",
                                "Continue",
                                "Next",
                            ])
                            if not form_submitted:
                                form_submitted = _click_known_ids(["idSIButton9", "submitButton"])
                            if not form_submitted:
                                try:
                                    pass_loc.press("Enter")
                                    form_submitted = True
                                except Exception:
                                    pass
                            if form_submitted:
                                _report_progress("password-submitted")
                        except Exception:
                            pass

                if form_submitted:
                    last_progress_time = time.monotonic()
                    _interruptible_pause(0.25)
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
                            if last_totp_counter is None:
                                # Avoid submitting a code that will expire while the
                                # Microsoft form is processing it.
                                valid_for = seconds_until_totp_rotation()
                                if valid_for < 5.0:
                                    _interruptible_pause(valid_for + 0.1)
                                    totp_counter = int(time.time() // 30)
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
                                    totp_submitted = True
                                    _report_progress("mfa-totp-submitted")
                            else:
                                waiting_for_fresh_totp = True
                        except Exception as exc:
                            raise RuntimeError(
                                "Could not generate or submit the configured TOTP code"
                            ) from exc
                    else:
                        otp_input_reported = False

                if totp_submitted:
                    last_progress_time = time.monotonic()
                    _interruptible_pause(0.25)
                    continue

                if waiting_for_fresh_totp:
                    # Do not let generic Continue/Next fallbacks resubmit the
                    # same code while Microsoft is still processing it.
                    _wait_until_ready(0.1)
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
                        last_progress_time = time.monotonic()
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

            remaining_ms = _remaining_timeout_ms(deadline)
            if remaining_ms > 0:
                _report_progress(f"waiting-for-vpn-callback host={_page_host()}")
                _wait_for_vpn_callback(remaining_ms)
            _raise_if_cancelled()

            # Collect cookies
            all_cookies = context.cookies()
            vpn_cookies = _collect_vpn_cookies()

            if saml_result["saml_response"]:
                vpn_cookies["SAMLResponse"] = saml_result["saml_response"]
            if saml_result["prelogin_cookie"]:
                vpn_cookies["prelogin-cookie"] = saml_result["prelogin_cookie"]
            if gp_prelogin_cookie and "prelogin-cookie" not in vpn_cookies:
                vpn_cookies["prelogin-cookie"] = gp_prelogin_cookie
            if gp_gateway_ip:
                vpn_cookies["_gateway_ip"] = gp_gateway_ip

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
                debug_out = {
                    "vpn_server": vpn_server,
                    "vpn_server_host": vpn_server_host,
                    "vpn_server_netloc": vpn_server_netloc,
                    "vpn_server_ip": vpn_server_ip,
                    "final_url": page.url,
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
