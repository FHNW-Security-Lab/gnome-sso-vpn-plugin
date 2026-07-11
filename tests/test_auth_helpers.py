#!/usr/bin/env python3

import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src" / "python"))

from core.auth import (  # noqa: E402
    MICROSOFT_ALTERNATE_MFA_LABELS,
    MICROSOFT_ALTERNATE_MFA_SELECTORS,
    MICROSOFT_AUTHENTICATOR_PUSH_MARKERS,
    MICROSOFT_KMSI_ACCEPT_LABELS,
    MICROSOFT_KMSI_MARKERS,
    MICROSOFT_NUMBER_MATCH_MARKERS,
    MICROSOFT_MFA_TRANSITION_TIMEOUT_SECONDS,
    MICROSOFT_TOTP_MAX_SUBMISSIONS,
    MICROSOFT_PASSKEY_MARKERS,
    MICROSOFT_PASSWORD_DIRECT_SELECTORS,
    MICROSOFT_PASSWORD_METHOD_LABELS,
    MICROSOFT_PUSH_DIRECT_SELECTORS,
    MICROSOFT_TOTP_DIRECT_SELECTORS,
    SAML_UI_MAX_RECOVERIES,
    SAML_UI_MAX_PROCESSING_EXTENSIONS,
    SAML_UI_MAX_SUBMIT_WAIT_SECONDS,
    SAML_UI_POST_SUBMIT_GRACE_SECONDS,
    SAML_UI_PROCESSING_EXTENSION_SECONDS,
    SAML_UI_STALL_WINDOW_SECONDS,
    _detect_desktop_user,
    _adaptive_mfa_action,
    _allows_partial_action_label,
    _browser_session_cache_key,
    _exact_action_pattern,
    _extend_processing_grace,
    _get_gp_prelogin,
    _has_number_match_evidence,
    _is_actionable_control,
    _merge_saml_artifacts,
    _parse_saml_timeout,
    _prefer_totp_for_number_match,
    _remaining_timeout_ms,
    _submission_hard_deadline,
    _should_notify_number_match,
    _should_submit_totp_counter,
    _stale_ui_recovery_action,
    _standalone_two_digit_numbers,
)
from core.totp import generate_totp, seconds_until_totp_rotation  # noqa: E402


class AuthDeadlineTests(unittest.TestCase):
    def test_remaining_timeout_uses_single_deadline(self):
        self.assertEqual(_remaining_timeout_ms(12.5, now=10.0), 2500)

    def test_expired_deadline_never_becomes_negative(self):
        self.assertEqual(_remaining_timeout_ms(9.0, now=10.0), 0)

    def test_invalid_timeout_uses_safe_protocol_default(self):
        self.assertEqual(_parse_saml_timeout("anyconnect", "invalid"), 120)
        self.assertEqual(_parse_saml_timeout("anyconnect", "0"), 120)
        self.assertEqual(_parse_saml_timeout("gp", "30"), 180)


class BrowserSessionIsolationTests(unittest.TestCase):
    def test_cache_key_normalizes_identity_without_exposing_it(self):
        first = _browser_session_cache_key(
            " GP ",
            "https://VPN.Example.EDU.:443/ssl-vpn/login.esp",
            " Alice@Example.EDU ",
        )
        second = _browser_session_cache_key(
            "gp",
            "vpn.example.edu",
            "alice@example.edu",
        )

        self.assertEqual(first, second)
        self.assertRegex(first, r"^v2-[0-9a-f]{64}$")
        self.assertNotIn("vpn", first)
        self.assertNotIn("alice", first)
        self.assertNotIn("example", first)

    def test_cache_key_isolates_protocol_gateway_and_username(self):
        baseline = _browser_session_cache_key(
            "gp",
            "vpn.example.edu",
            "alice@example.edu",
        )
        variants = {
            _browser_session_cache_key(
                "anyconnect", "vpn.example.edu", "alice@example.edu"
            ),
            _browser_session_cache_key(
                "gp", "other.example.edu", "alice@example.edu"
            ),
            _browser_session_cache_key(
                "gp", "vpn.example.edu", "bob@example.edu"
            ),
        }

        self.assertEqual(len(variants), 3)
        self.assertNotIn(baseline, variants)


class BrowserUiRecoveryTests(unittest.TestCase):
    def test_explanatory_text_is_not_an_actionable_control(self):
        self.assertFalse(_is_actionable_control("div"))
        self.assertFalse(_is_actionable_control("p"))
        self.assertFalse(_is_actionable_control("input", input_type="text"))

    def test_short_submit_label_does_not_match_alternate_method_link(self):
        pattern = _exact_action_pattern("Anmelden")
        self.assertIsNotNone(pattern.search("Anmelden"))
        self.assertIsNotNone(pattern.search("  ANMELDEN  "))
        self.assertIsNone(pattern.search("Auf andere Weise anmelden"))
        self.assertFalse(_allows_partial_action_label("Anmelden"))
        self.assertTrue(_allows_partial_action_label(
            "Ich kann meine Microsoft Authenticator-App nicht verwenden"
        ))

    def test_only_enabled_button_link_or_submit_controls_are_actionable(self):
        self.assertTrue(_is_actionable_control("button"))
        self.assertTrue(_is_actionable_control("span", role="button"))
        self.assertTrue(_is_actionable_control("a", role="link"))
        self.assertTrue(_is_actionable_control("input", input_type="submit"))
        self.assertTrue(_is_actionable_control("a", has_href=True))
        self.assertTrue(_is_actionable_control("div", has_click_handler=True))
        self.assertTrue(_is_actionable_control("div", has_data_value=True))
        self.assertTrue(_is_actionable_control("div", tab_index=0))
        self.assertTrue(_is_actionable_control("div", pointer_cursor=True))
        self.assertFalse(_is_actionable_control("div", tab_index=-1))
        self.assertFalse(_is_actionable_control("button", disabled=True))

    def test_stale_ui_recovery_is_fast_but_honors_submit_grace(self):
        self.assertEqual(SAML_UI_MAX_RECOVERIES, 1)
        self.assertLessEqual(SAML_UI_STALL_WINDOW_SECONDS, 8.0)
        self.assertGreaterEqual(SAML_UI_POST_SUBMIT_GRACE_SECONDS, 20.0)
        self.assertEqual(
            _stale_ui_recovery_action(
                100.0,
                100.0 + SAML_UI_STALL_WINDOW_SECONDS - 0.1,
                0,
            ),
            "wait",
        )
        self.assertEqual(
            _stale_ui_recovery_action(
                100.0,
                100.0 + SAML_UI_STALL_WINDOW_SECONDS,
                0,
            ),
            "recover",
        )
        self.assertEqual(
            _stale_ui_recovery_action(
                100.0,
                100.0 + SAML_UI_STALL_WINDOW_SECONDS,
                0,
                grace_until=100.0 + SAML_UI_POST_SUBMIT_GRACE_SECONDS,
            ),
            "wait",
        )
        self.assertEqual(
            _stale_ui_recovery_action(
                100.0,
                100.0 + SAML_UI_STALL_WINDOW_SECONDS,
                1,
            ),
            "fail",
        )

    def test_unresolved_submission_gets_progressive_bounded_extensions(self):
        self.assertEqual(SAML_UI_MAX_PROCESSING_EXTENSIONS, 6)
        deadline, used = _extend_processing_grace(
            now=120.0,
            grace_until=120.0,
            processing_visible=True,
            extensions_used=0,
            hard_deadline=180.0,
        )
        self.assertEqual(deadline, 120.0 + SAML_UI_PROCESSING_EXTENSION_SECONDS)
        self.assertEqual(used, 1)
        deadline, used = _extend_processing_grace(
            now=deadline,
            grace_until=deadline,
            processing_visible=True,
            extensions_used=used,
            hard_deadline=180.0,
        )
        self.assertEqual(deadline, 150.0)
        self.assertEqual(used, 2)
        deadline, used = _extend_processing_grace(
            now=deadline,
            grace_until=deadline,
            processing_visible=True,
            extensions_used=used,
            hard_deadline=180.0,
        )
        self.assertEqual(deadline, 180.0)
        self.assertEqual(used, 3)
        self.assertEqual(
            _extend_processing_grace(
                now=deadline,
                grace_until=deadline,
                processing_visible=True,
                extensions_used=used,
                hard_deadline=180.0,
            ),
            (deadline, used),
        )

    def test_submission_deadline_is_immutable_and_protocol_clamped(self):
        self.assertEqual(SAML_UI_MAX_SUBMIT_WAIT_SECONDS, 180.0)
        self.assertEqual(
            _submission_hard_deadline(100.0, 400.0),
            280.0,
        )
        self.assertEqual(
            _submission_hard_deadline(100.0, 200.0),
            200.0,
        )


class MicrosoftMfaTests(unittest.TestCase):
    def test_fhnw_german_authenticator_fallback_is_supported(self):
        self.assertIn(
            "Ich kann meine Microsoft Authenticator-App im Moment nicht verwenden",
            MICROSOFT_ALTERNATE_MFA_LABELS,
        )

    def test_microsoft_totp_method_has_stable_selector(self):
        self.assertIn("[data-value='PhoneAppOTP']", MICROSOFT_TOTP_DIRECT_SELECTORS)

    def test_current_password_and_alternate_selectors_are_supported(self):
        self.assertIn("#idA_PWD_SwitchToPassword", MICROSOFT_PASSWORD_DIRECT_SELECTORS)
        self.assertIn("#idA_PWD_SwitchToCredPicker", MICROSOFT_ALTERNATE_MFA_SELECTORS)
        self.assertIn("Use my password", MICROSOFT_PASSWORD_METHOD_LABELS)
        self.assertIn("Mein Kennwort verwenden", MICROSOFT_PASSWORD_METHOD_LABELS)

    def test_german_stay_signed_in_prompt_is_supported(self):
        self.assertIn("Angemeldet bleiben", MICROSOFT_KMSI_MARKERS)
        self.assertIn("Ja", MICROSOFT_KMSI_ACCEPT_LABELS)

    def test_gp_saml_username_and_portal_cookie_are_preserved(self):
        result = _merge_saml_artifacts(
            {"SESSID": "session"},
            {
                "saml_response": "response",
                "prelogin_cookie": "prelogin",
                "portal_userauthcookie": "portal",
                "saml_username": "returned-user",
            },
            "gp",
            gp_prelogin_cookie="fallback",
            gp_gateway_ip="192.0.2.10",
        )

        self.assertEqual(result["prelogin-cookie"], "prelogin")
        self.assertEqual(result["portal-userauthcookie"], "portal")
        self.assertEqual(result["saml-username"], "returned-user")
        self.assertEqual(result["_gateway_ip"], "192.0.2.10")

    @patch("core.auth.urllib.request.urlopen")
    def test_gp_gateway_prelogin_uses_gateway_endpoint(self, urlopen):
        response = urlopen.return_value.__enter__.return_value
        response.status = 200
        response.read.return_value = (
            b"<response><saml-request>request</saml-request>"
            b"<server-ip>192.0.2.10</server-ip></response>"
        )

        _cookie, saml_request, gateway_ip = _get_gp_prelogin(
            "vpn.example.edu",
            gp_auth_interface="gateway",
        )

        request = urlopen.call_args.args[0]
        self.assertEqual(
            request.full_url,
            "https://vpn.example.edu/ssl-vpn/prelogin.esp",
        )
        self.assertEqual(saml_request, "request")
        self.assertEqual(gateway_ip, "192.0.2.10")

    def test_push_passkey_and_number_match_states_are_supported(self):
        self.assertIn("[data-value='PhoneAppNotification']", MICROSOFT_PUSH_DIRECT_SELECTORS)
        self.assertIn("Passkey verwenden", MICROSOFT_PASSKEY_MARKERS)
        self.assertIn("Geben Sie die Nummer ein", MICROSOFT_NUMBER_MATCH_MARKERS)
        self.assertIn("Geben Sie die angezeigte Zahl ein", MICROSOFT_NUMBER_MATCH_MARKERS)
        self.assertIn(
            "Approve a sign-in request",
            MICROSOFT_AUTHENTICATOR_PUSH_MARKERS,
        )
        self.assertNotIn(
            "Approve a sign-in request",
            MICROSOFT_NUMBER_MATCH_MARKERS,
        )

    def test_number_match_extraction_requires_unique_standalone_value(self):
        self.assertEqual(_standalone_two_digit_numbers("Approve\n65\nContinue"), {"65"})
        self.assertEqual(_standalone_two_digit_numbers("Code 65\n2026\n123456"), set())
        self.assertEqual(_standalone_two_digit_numbers("12\n65"), {"12", "65"})

    def test_number_match_selector_is_authoritative_without_known_wording(self):
        self.assertTrue(_has_number_match_evidence(False, True))
        self.assertTrue(_has_number_match_evidence(True, False))
        self.assertFalse(_has_number_match_evidence(False, False))

    def test_auto_and_totp_switch_number_match_to_totp(self):
        self.assertTrue(_prefer_totp_for_number_match("auto", True, False))
        self.assertFalse(_prefer_totp_for_number_match("push", True, False))
        self.assertTrue(_prefer_totp_for_number_match("totp", True, False))
        self.assertFalse(_prefer_totp_for_number_match("totp", True, True))

    def test_number_notification_is_only_a_phone_fallback(self):
        self.assertFalse(_should_notify_number_match("auto", True))
        self.assertTrue(_should_notify_number_match("auto", False))
        self.assertTrue(_should_notify_number_match("push", True))
        self.assertFalse(_should_notify_number_match("totp", False))

    def test_number_match_adaptively_prefers_each_totp_path(self):
        self.assertEqual(
            _adaptive_mfa_action(True, True, True, False, False),
            "submit-totp",
        )
        self.assertEqual(
            _adaptive_mfa_action(True, False, True, True, False),
            "select-totp",
        )
        self.assertEqual(
            _adaptive_mfa_action(True, False, True, False, True),
            "wait-for-picker",
        )
        self.assertEqual(
            _adaptive_mfa_action(True, False, True, False, False),
            "open-alternate-methods",
        )
        self.assertEqual(
            _adaptive_mfa_action(False, False, True, True, False),
            "phone",
        )
        self.assertEqual(
            _adaptive_mfa_action(True, False, False, False, False),
            "none",
        )

    def test_mfa_transition_allows_slow_spa_rendering(self):
        self.assertGreaterEqual(MICROSOFT_MFA_TRANSITION_TIMEOUT_SECONDS, 15.0)

    def test_totp_can_retry_only_after_counter_advances(self):
        self.assertEqual(MICROSOFT_TOTP_MAX_SUBMISSIONS, 2)
        self.assertTrue(_should_submit_totp_counter(None, 100))
        self.assertFalse(_should_submit_totp_counter(100, 100))
        self.assertTrue(_should_submit_totp_counter(100, 101))

    @patch("core.auth.subprocess.run")
    def test_desktop_user_comes_from_unique_active_graphical_session(self, run):
        def fake_run(command, **_kwargs):
            if command[1] == "list-sessions":
                return SimpleNamespace(returncode=0, stdout="2 1000 alice seat0\n3 1000 alice -\n")
            if command[2] == "2":
                return SimpleNamespace(
                    returncode=0,
                    stdout=(
                        "Active=yes\nRemote=no\nType=wayland\nClass=user\n"
                        "User=1000\nName=alice\n"
                    ),
                )
            return SimpleNamespace(
                returncode=0,
                stdout=(
                    "Active=yes\nRemote=no\nType=unspecified\nClass=manager\n"
                    "User=1000\nName=alice\n"
                ),
            )

        run.side_effect = fake_run
        self.assertEqual(_detect_desktop_user(), "alice")

    @patch("core.auth.subprocess.run")
    def test_multiple_active_desktop_users_fail_closed(self, run):
        def fake_run(command, **_kwargs):
            if command[1] == "list-sessions":
                return SimpleNamespace(returncode=0, stdout="2 1000 alice seat0\n4 1001 bob seat1\n")
            user = "alice" if command[2] == "2" else "bob"
            uid = "1000" if user == "alice" else "1001"
            return SimpleNamespace(
                returncode=0,
                stdout=(
                    "Active=yes\nRemote=no\nType=wayland\nClass=user\n"
                    f"User={uid}\nName={user}\n"
                ),
            )

        run.side_effect = fake_run
        self.assertIsNone(_detect_desktop_user())


class TotpTests(unittest.TestCase):
    def test_rfc_6238_sha1_vector(self):
        secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        self.assertEqual(generate_totp(secret, digits=8, timestamp=59), "94287082")

    def test_rotation_window(self):
        self.assertEqual(seconds_until_totp_rotation(timestamp=28.5), 1.5)
        self.assertEqual(seconds_until_totp_rotation(timestamp=30), 30.0)


if __name__ == "__main__":
    unittest.main()
