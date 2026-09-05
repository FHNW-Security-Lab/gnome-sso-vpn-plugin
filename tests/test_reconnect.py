import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock

SPEC = importlib.util.spec_from_file_location(
    'ms_sso_reconnect', Path(__file__).resolve().parents[1] / 'src/nm-ms-sso-reconnect.py')
M = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = M
SPEC.loader.exec_module(M)
NM = M.NM


def profile(uuid='vpn-1', enabled=True, service=M.SERVICE_TYPE):
    vpn = Mock()
    vpn.get_service_type.return_value = service
    vpn.get_data_item.return_value = None if enabled else 'false'
    connection = Mock()
    connection.get_uuid.return_value = uuid
    connection.get_setting_vpn.return_value = vpn
    return connection


def activation(connection, path='/active/1', state=NM.ActiveConnectionState.ACTIVATING):
    active = Mock()
    active.get_connection.return_value = connection
    active.get_uuid.return_value = connection.get_uuid()
    active.get_path.return_value = path
    active.get_state.return_value = state
    active.get_vpn.return_value = True
    return active


class ReconnectTests(unittest.TestCase):
    def setUp(self):
        self.now = 100.0
        self.profile = profile()
        self.client = Mock()
        self.client.get_active_connections.return_value = []
        self.client.get_connection_by_uuid.return_value = self.profile
        self.client.get_nm_running.return_value = True
        self.client.networking_get_enabled.return_value = True
        self.client.get_state.return_value = NM.State.CONNECTED_GLOBAL
        self.monitor = M.ReconnectMonitor(self.client, lambda: self.now)
        self.active = activation(self.profile)

    def start(self):
        self.client.get_active_connections.return_value = [self.active]
        self.monitor.added(self.client, self.active)

    def end(self, reason=NM.ActiveConnectionStateReason.SERVICE_STOPPED):
        self.active.get_state.return_value = NM.ActiveConnectionState.DEACTIVATED
        self.monitor.changed(self.active, NM.ActiveConnectionState.DEACTIVATED, reason)
        self.client.get_active_connections.return_value = []
        self.monitor.removed(self.client, self.active)

    def test_boot_does_not_activate_saved_profile(self):
        self.monitor.tick()
        self.client.activate_connection_async.assert_not_called()

    def test_server_timeout_reconnects_only_after_old_activation_is_removed(self):
        self.start()
        self.active.get_state.return_value = NM.ActiveConnectionState.DEACTIVATED
        self.monitor.changed(self.active, NM.ActiveConnectionState.DEACTIVATED, 4)
        self.now += 5
        self.monitor.tick()
        self.client.activate_connection_async.assert_not_called()
        self.client.get_active_connections.return_value = []
        self.monitor.removed(self.client, self.active)
        self.monitor.tick()
        self.client.activate_connection_async.assert_called_once()
        self.monitor.tick()
        self.client.activate_connection_async.assert_called_once()

    def test_disconnect_during_connect_or_after_connect_disarms(self):
        for state in (NM.ActiveConnectionState.ACTIVATING, NM.ActiveConnectionState.ACTIVATED):
            with self.subTest(state=state):
                self.active.get_state.return_value = state
                self.start()
                self.end(NM.ActiveConnectionStateReason.USER_DISCONNECTED)
                self.now += 1000
                self.monitor.tick()
                self.assertIsNone(self.monitor.intent)
        self.client.activate_connection_async.assert_not_called()

    def test_suspend_waits_for_resume_and_uplink(self):
        self.start()
        self.monitor.power_signal(None,None,None,None,'PrepareForSleep',M.GLib.Variant('(b)', (True,)))
        self.end(NM.ActiveConnectionStateReason.DEVICE_DISCONNECTED)
        self.now += 3600
        self.monitor.tick()
        self.client.activate_connection_async.assert_not_called()
        self.monitor.power_signal(None,None,None,None,'PrepareForSleep',M.GLib.Variant('(b)', (False,)))
        self.client.get_state.return_value = NM.State.CONNECTING
        self.monitor.tick()
        self.client.activate_connection_async.assert_not_called()
        self.client.get_state.return_value = NM.State.CONNECTED_SITE
        self.monitor.tick()
        self.client.activate_connection_async.assert_called_once()

    def test_user_disconnect_while_asleep_still_wins(self):
        self.start()
        self.monitor.sleeping = True
        self.end(NM.ActiveConnectionStateReason.USER_DISCONNECTED)
        self.assertIsNone(self.monitor.intent)

    def test_shutdown_discards_intent(self):
        self.start()
        self.monitor.power_signal(None,None,None,None,'PrepareForShutdown',M.GLib.Variant('(b)', (True,)))
        self.end()
        self.now += 1000
        self.monitor.tick()
        self.assertIsNone(self.monitor.intent)
        self.client.activate_connection_async.assert_not_called()

    def test_no_retry_limit_and_bounded_backoff(self):
        self.start()
        intent = self.monitor.intent
        for i in range(100):
            intent.failed(self.now)
            self.assertGreater(intent.retry_at, self.now)
            self.assertLessEqual(intent.retry_at - self.now, 300)
            self.now = intent.retry_at
        self.assertEqual(intent.attempts, 100)

    def test_success_resets_backoff(self):
        self.start()
        self.monitor.intent.attempts = 50
        self.monitor.changed(self.active, NM.ActiveConnectionState.ACTIVATED, 1)
        self.assertEqual(self.monitor.intent.attempts, 0)

    def test_profile_removed_or_disabled_stops_waiting(self):
        for connection in (None, profile(enabled=False)):
            self.active.get_state.return_value = NM.ActiveConnectionState.ACTIVATING
            self.start()
            self.end()
            self.client.get_connection_by_uuid.return_value = connection
            self.now += 500
            self.monitor.tick()
            self.assertIsNone(self.monitor.intent)
        self.client.activate_connection_async.assert_not_called()

    def test_unrelated_vpn_is_never_armed(self):
        self.monitor.added(self.client, activation(profile(service='other')))
        self.assertIsNone(self.monitor.intent)

    def test_stale_disconnect_cannot_cancel_new_user_choice(self):
        self.start()
        other = activation(profile('vpn-2'), '/active/2')
        self.monitor.added(self.client, other)
        self.monitor.changed(self.active, NM.ActiveConnectionState.DEACTIVATED, 2)
        self.assertEqual(self.monitor.intent.uuid, 'vpn-2')

    def test_stale_disconnect_cannot_cancel_same_uuid_replacement(self):
        self.start()
        other = activation(self.profile, '/active/2')
        self.monitor.added(self.client, other)
        self.monitor.changed(self.active, NM.ActiveConnectionState.DEACTIVATED, 2)
        self.assertEqual(self.monitor.intent.uuid, self.profile.get_uuid())

    def test_nm_crash_without_final_signal_still_retries(self):
        self.start()
        self.client.get_active_connections.return_value = []
        self.monitor.removed(self.client, self.active)
        self.client.get_nm_running.return_value = False
        self.now += 500
        self.monitor.tick()
        self.client.activate_connection_async.assert_not_called()
        self.client.get_nm_running.return_value = True
        self.monitor.tick()
        self.client.activate_connection_async.assert_called_once()

    def test_another_plugin_does_not_block_reconnect(self):
        self.start()
        self.end()
        self.now += 5
        foreign = activation(profile('other-vpn', service='other'), '/active/3')
        self.client.get_active_connections.return_value = [foreign]
        self.monitor.tick()
        self.client.activate_connection_async.assert_called_once()

    def test_same_plugin_manual_activation_is_not_duplicated(self):
        self.start()
        self.end()
        self.now += 5
        other = activation(profile('vpn-2', enabled=False), '/active/3')
        self.client.get_active_connections.return_value = [other]
        self.monitor.tick()
        self.client.activate_connection_async.assert_not_called()

    def test_cancelled_request_cannot_rearm_intent_via_added_signal(self):
        self.start()
        self.end()
        self.now += 5
        self.monitor.tick()
        context = self.client.activate_connection_async.call_args.args[-1]
        self.monitor.changed(self.active, NM.ActiveConnectionState.DEACTIVATED, 2)
        late = activation(self.profile, '/active/late')
        self.monitor.added(self.client, late)
        self.assertIsNone(self.monitor.intent)
        self.client.activate_connection_finish.return_value = late
        self.monitor.activated(self.client, None, context)
        self.monitor.added(self.client, late)
        self.assertIsNone(self.monitor.intent)
        self.client.deactivate_connection_async.assert_called_once()

    def test_sleep_cancelled_request_still_observes_user_disconnect(self):
        self.start()
        self.end()
        self.now += 5
        self.monitor.tick()
        self.monitor.power_signal(None,None,None,None,'PrepareForSleep',M.GLib.Variant('(b)', (True,)))
        late = activation(self.profile, '/active/late')
        self.monitor.added(self.client, late)
        self.assertIn(late.get_path(), self.monitor.tracked)
        self.monitor.changed(late, NM.ActiveConnectionState.DEACTIVATING, 2)
        self.assertIsNone(self.monitor.intent)

    def test_new_profile_choice_cancels_pending_old_request(self):
        self.start()
        self.end()
        self.now += 5
        self.monitor.tick()
        pending = self.monitor.pending
        other = activation(profile('vpn-2'), '/active/other')
        self.monitor.added(self.client, other)
        self.assertTrue(pending.is_cancelled())
        self.monitor.added(self.client, activation(self.profile, '/active/late'))
        self.assertEqual(self.monitor.intent.uuid, 'vpn-2')

    def test_activation_error_is_backed_off(self):
        self.start()
        self.end()
        self.now += 5
        self.monitor.tick()
        self.client.activate_connection_finish.side_effect = M.GLib.Error('offline')
        context = self.client.activate_connection_async.call_args.args[-1]
        self.monitor.activated(self.client, None, context)
        self.assertIsNone(self.monitor.pending)
        self.assertGreater(self.monitor.intent.retry_at, self.now)
        self.monitor.tick()
        self.client.activate_connection_async.assert_called_once()

    def test_late_activation_after_user_cancel_is_deactivated(self):
        self.start()
        self.end()
        self.now += 5
        self.monitor.tick()
        context = self.client.activate_connection_async.call_args.args[-1]
        self.monitor.changed(self.active, NM.ActiveConnectionState.DEACTIVATED, 2)
        self.assertTrue(context[1].is_cancelled())
        self.client.activate_connection_finish.return_value = self.active
        self.monitor.activated(self.client, None, context)
        self.client.deactivate_connection_async.assert_called_once()


def real_protocol_profile(protocol):
    """Exercise libnm's actual VPN data map, without secrets or a live tunnel."""
    connection = NM.SimpleConnection.new()
    identity = NM.SettingConnection.new()
    identity.props.id = 'reconnect-test-' + protocol
    identity.props.uuid = 'f35ad2dd-32ea-48d2-a665-dbeca659ca7a'
    identity.props.type = 'vpn'
    connection.add_setting(identity)
    vpn = NM.SettingVpn.new()
    vpn.props.service_type = M.SERVICE_TYPE
    vpn.add_data_item('protocol', protocol)
    vpn.add_data_item('auto-reconnect', 'true')
    if protocol == 'gp':
        vpn.add_data_item('gp-auth-interface', 'gateway')
        vpn.add_data_item('mfa-preference', 'totp')
    connection.add_setting(vpn)
    return connection


class GlobalProtectReconnectTests(ReconnectTests):
    """Run the lifecycle contract with an actual GlobalProtect NM profile."""
    protocol = 'gp'

    def setUp(self):
        super().setUp()
        self.profile = real_protocol_profile(self.protocol)
        self.assertTrue(self.profile.verify())
        self.client.get_connection_by_uuid.return_value = self.profile
        self.active = activation(self.profile)

    def test_real_profile_defaults_to_reconnect_and_honors_explicit_disable(self):
        vpn = self.profile.get_setting_vpn()
        vpn.remove_data_item('auto-reconnect')
        self.assertTrue(M.ReconnectMonitor.enabled(self.profile))
        vpn.add_data_item('auto-reconnect', 'false')
        self.assertFalse(M.ReconnectMonitor.enabled(self.profile))
        self.monitor.added(self.client, self.active)
        self.assertIsNone(self.monitor.intent)
        vpn.add_data_item('auto-reconnect', 'true')
        self.monitor.added(self.client, self.active)
        self.assertIsNotNone(self.monitor.intent)


class AnyConnectReconnectTests(GlobalProtectReconnectTests):
    """The identical lifecycle contract applies to a real AnyConnect profile."""
    protocol = 'anyconnect'


if __name__ == '__main__':
    unittest.main()
