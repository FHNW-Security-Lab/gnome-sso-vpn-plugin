"""Real Chromium regression fixtures; all HTTP requests are served locally."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src/python'))
from core.auth import (
    _password_form_hydrated, _combined_action_pattern,
    MICROSOFT_PASSWORD_METHOD_LABELS, MICROSOFT_TOTP_DIRECT_SELECTORS,
)
from playwright.sync_api import sync_playwright


class BrowserReadinessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.playwright = sync_playwright().start()
        try:
            cls.browser = cls.playwright.chromium.launch(headless=True, args=['--no-sandbox'])
        except Exception:
            cls.playwright.stop()
            raise

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls.playwright.stop()

    def setUp(self):
        self.page = self.browser.new_page()
        self.page.route('**/*', lambda route: route.fulfill(body='<html><body></body></html>', content_type='text/html'))
        self.page.goto('https://login.microsoftonline.com/local-fixture')

    def tearDown(self):
        self.page.close()

    def test_visible_password_waits_for_binding_then_submits_once(self):
        self.page.set_content('''<form data-bind="submit: login">
          <input type="password" autocomplete="current-password">
          <button type="submit">Anmelden</button></form>
          <script>window.ko = {contextFor: () => window.bound ? {} : undefined};
          window.submissions = 0;</script>''')
        password = self.page.locator('input[type=password]')
        self.assertTrue(password.is_visible())
        self.assertTrue(password.is_enabled())
        self.assertFalse(_password_form_hydrated(password, 'anyconnect'))
        self.page.evaluate('''() => {
          document.querySelector('form').onsubmit = e => {
            e.preventDefault(); window.submissions++;
          };
          window.bound = true;
        }''')
        self.assertTrue(_password_form_hydrated(password, 'anyconnect'))
        password.fill('fixture-only')
        self.page.get_by_role('button', name='Anmelden').click()
        self.assertEqual(self.page.evaluate('window.submissions'), 1)

    def test_changed_ids_and_ready_non_knockout_form_take_fast_path(self):
        self.page.set_content('<form><input id="new-password-id" type="password"></form>')
        self.assertTrue(_password_form_hydrated(self.page.locator('input'), 'anyconnect'))

    def test_detached_field_is_reacquired_instead_of_entered(self):
        self.page.set_content('<form><input type="password"></form>')
        old = self.page.query_selector('input')
        self.page.evaluate("document.querySelector('input').remove()")
        self.assertFalse(_password_form_hydrated(old, 'anyconnect'))

    def test_other_provider_and_gp_do_not_wait_for_microsoft_binding(self):
        self.page.set_content('''<input type="password" data-bind="value: pass">
            <script>window.ko = {contextFor: () => undefined};</script>''')
        self.assertTrue(_password_form_hydrated(self.page.locator('input'), 'gp'))
        self.page.goto('https://vpn.example.test/local-fixture')
        self.page.set_content('<input type="password">')
        self.assertTrue(_password_form_hydrated(self.page.locator('input'), 'anyconnect'))

    def test_translated_password_choices_use_real_role_controls(self):
        for label in ('Use my password', 'Mein Kennwort verwenden',
                      'Utiliser mon mot de passe', 'Usa la password'):
            with self.subTest(label=label):
                self.page.set_content('<button></button>')
                self.page.locator('button').evaluate('(el, label) => el.textContent = label', label)
                self.assertEqual(self.page.get_by_role('button', name=_combined_action_pattern(
                    MICROSOFT_PASSWORD_METHOD_LABELS)).count(), 1)

    def test_totp_metadata_survives_unknown_language_and_changed_id(self):
        self.page.set_content('<button id="new-totp-choice" data-value="PhoneAppOTP">確認コード</button>')
        self.assertEqual(self.page.locator(','.join(MICROSOFT_TOTP_DIRECT_SELECTORS)).count(), 1)


if __name__ == '__main__':
    unittest.main()
