#!/usr/bin/python3
"""Observe explicit VPN activations and reconnect them for this boot only.

NetworkManager must retire a failed activation before a new tunnel is created.
Keep this observer independent of the short-lived VPN plugin so its Disconnect
RPC (also used for failures and suspend) cannot be mistaken for user intent.
No credentials or desired-connection state are written to disk.
"""
import logging
import time
from dataclasses import dataclass

import gi

gi.require_version('NM', '1.0')
from gi.repository import Gio, GLib, NM

LOG = logging.getLogger('nm-ms-sso-reconnect')
SERVICE_TYPE = 'org.freedesktop.NetworkManager.ms-sso'


@dataclass
class Intent:
    uuid: str
    attempts: int = 0
    retry_at: float = 0.0

    def failed(self, now):
        self.attempts += 1
        self.retry_at = now + min(5 * 2 ** min(self.attempts - 1, 6), 300)


class ReconnectMonitor:
    def __init__(self, client, clock=time.monotonic):
        self.client = client
        self.clock = clock
        self.intent = None
        self.tracked = {}
        self.ignored = set()
        self.pending = None
        self.sleeping = False
        self.shutting_down = False
        client.connect('active-connection-added', self.added)
        client.connect('active-connection-removed', self.removed)
        # Also attach to a VPN already active when the package is upgraded.
        for active in client.get_active_connections():
            self.added(client, active)

    @staticmethod
    def is_ours(connection):
        vpn = connection.get_setting_vpn() if connection else None
        return bool(vpn and vpn.get_service_type() == SERVICE_TYPE)

    @staticmethod
    def enabled(connection):
        vpn = connection.get_setting_vpn() if connection else None
        return bool(
            vpn and vpn.get_service_type() == SERVICE_TYPE
            and str(vpn.get_data_item('auto-reconnect') or '').strip().lower()
            not in {'0', 'false', 'no', 'off'}
        )

    def added(self, _client, active):
        path = active.get_path()
        if (path in self.tracked or path in self.ignored
                or (self.pending and self.pending.is_cancelled()
                    and (self.intent is None
                         or self.intent.uuid != active.get_uuid()))
                or not self.enabled(active.get_connection())):
            return
        if active.get_state() >= NM.ActiveConnectionState.DEACTIVATING:
            return
        self.tracked[path] = active
        active.connect('state-changed', self.changed)
        # This service supports one activation at a time. A new user choice
        # replaces the old intention; stale callbacks cannot resurrect it.
        uuid = active.get_uuid()
        if self.intent is None or self.intent.uuid != uuid:
            if self.pending:
                self.pending.cancel()
            self.intent = Intent(uuid)
            LOG.info('Following VPN activation %s', uuid)
        if active.get_state() == NM.ActiveConnectionState.ACTIVATED:
            self.changed(active, active.get_state(), 1)

    def changed(self, active, state, reason):
        if not self.intent or active.get_uuid() != self.intent.uuid:
            return
        # Ignore a retired activation once a replacement exists for this UUID.
        if any(other.get_uuid() == active.get_uuid()
               and other.get_path() != active.get_path()
               and other.get_state() < NM.ActiveConnectionState.DEACTIVATING
               for other in self.tracked.values()):
            return
        if reason in (NM.ActiveConnectionStateReason.USER_DISCONNECTED,
                      NM.ActiveConnectionStateReason.CONNECTION_REMOVED):
            LOG.info('User disabled VPN reconnect for %s', self.intent.uuid)
            self.intent = None
            if self.pending:
                self.pending.cancel()
            return
        if state == NM.ActiveConnectionState.ACTIVATED:
            self.intent.attempts = 0
            self.intent.retry_at = 0.0
        elif state == NM.ActiveConnectionState.DEACTIVATED:
            self.intent.failed(self.clock())
            LOG.info('VPN ended (reason %s); reconnect scheduled', int(reason))

    def removed(self, _client, active):
        self.tracked.pop(active.get_path(), None)
        self.ignored.discard(active.get_path())
        # Covers a plugin/NM crash that removed the object without a final
        # state notification. Explicit user disconnect has already cleared it.
        if self.intent and self.intent.uuid == active.get_uuid():
            if self.intent.retry_at == 0.0:
                self.intent.failed(self.clock())

    def power_signal(self, _bus, _sender, _path, _interface, signal, parameters):
        value = bool(parameters.unpack()[0])
        if signal == 'PrepareForShutdown':
            self.shutting_down = value
            if value:
                self.intent = None
        elif signal == 'PrepareForSleep':
            self.sleeping = value
        if (self.sleeping or self.shutting_down) and self.pending:
            self.pending.cancel()

    def tick(self):
        if (not self.intent or self.pending or self.sleeping or self.shutting_down
                or not self.client.get_nm_running()
                or not self.client.networking_get_enabled()
                or self.client.get_state() < NM.State.CONNECTED_SITE
                or self.clock() < self.intent.retry_at):
            return GLib.SOURCE_CONTINUE
        connection = self.client.get_connection_by_uuid(self.intent.uuid)
        if not self.enabled(connection):
            self.intent = None
            return GLib.SOURCE_CONTINUE
        # Wait for complete removal of the old activation, including its DNS
        # and route withdrawal. Also avoid competing with another VPN choice.
        if any(active.get_uuid() == self.intent.uuid
               or (self.is_ours(active.get_connection()) and active.get_state()
                   < NM.ActiveConnectionState.DEACTIVATED)
               for active in self.client.get_active_connections()):
            return GLib.SOURCE_CONTINUE
        intent = self.intent
        cancellable = Gio.Cancellable()
        self.pending = cancellable
        LOG.info('Reconnecting VPN %s (attempt %s)', intent.uuid, intent.attempts)
        try:
            self.client.activate_connection_async(
                connection, None, None, cancellable, self.activated,
                (intent, cancellable),
            )
        except Exception as error:
            self.pending = None
            intent.failed(self.clock())
            LOG.warning('Could not request VPN activation: %s', error)
        return GLib.SOURCE_CONTINUE

    def activated(self, client, result, context):
        intent, cancellable = context
        if self.pending is cancellable:
            self.pending = None
        try:
            active = client.activate_connection_finish(result)
        except GLib.Error as error:
            if self.intent is intent:
                intent.failed(self.clock())
                LOG.warning('VPN activation request failed: %s', error.message)
            return
        if self.intent is not intent or self.shutting_down:
            # Cancellation and activation can cross on D-Bus. Honor the
            # cancellation even if NM completed the request first.
            self.ignored.add(active.get_path())
            client.deactivate_connection_async(active, None, None, None)
            return
        self.added(client, active)


def main():
    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
    client = NM.Client.new(None)
    monitor = ReconnectMonitor(client)
    bus = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)
    for signal in ('PrepareForSleep', 'PrepareForShutdown'):
        bus.signal_subscribe(
            'org.freedesktop.login1', 'org.freedesktop.login1.Manager', signal,
            '/org/freedesktop/login1', None, Gio.DBusSignalFlags.NONE,
            monitor.power_signal,
        )
    GLib.timeout_add_seconds(2, monitor.tick)
    GLib.MainLoop().run()


if __name__ == '__main__':
    main()
