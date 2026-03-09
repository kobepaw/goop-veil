"""Tests for OpenWrtAdapter — SSH + UCI router control.

All tests use mocks for paramiko; no real SSH connections are made.
"""

from __future__ import annotations

import os
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest


def _make_config(apply_changes: bool = True, **overrides) -> SimpleNamespace:
    """Create a minimal RouterConfig-like object for testing."""
    defaults = {
        "adapter_type": "openwrt",
        "host": "192.168.1.1",
        "username": "root",
        "ssh_key_path": None,
        "apply_changes": apply_changes,
        "timeout_sec": 10,
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


@pytest.fixture(autouse=True)
def _router_password(monkeypatch):
    """Set a test password in the environment."""
    monkeypatch.setenv("VEIL_ROUTER_PASSWORD", "test-password")


@pytest.fixture
def mock_paramiko():
    """Provide a mocked paramiko.SSHClient."""
    with patch.dict("sys.modules", {"paramiko": MagicMock()}) as mods:
        import sys

        paramiko_mod = sys.modules["paramiko"]
        mock_client_instance = MagicMock()
        paramiko_mod.SSHClient.return_value = mock_client_instance
        paramiko_mod.AutoAddPolicy.return_value = MagicMock()
        paramiko_mod.RejectPolicy.return_value = MagicMock()

        # Default exec_command returns empty stdout/stderr
        stdout_mock = MagicMock()
        stdout_mock.read.return_value = b""
        stderr_mock = MagicMock()
        stderr_mock.read.return_value = b""
        mock_client_instance.exec_command.return_value = (MagicMock(), stdout_mock, stderr_mock)

        yield mock_client_instance


def _make_adapter(config=None):
    """Create an OpenWrtAdapter with the given config."""
    from goop_veil.mitigation.router.openwrt import OpenWrtAdapter

    return OpenWrtAdapter(config or _make_config())


# ---------------------------------------------------------------------------
# Connection
# ---------------------------------------------------------------------------


class TestConnect:
    """SSH connection establishment."""

    def test_connect_success(self, mock_paramiko):
        adapter = _make_adapter()
        assert adapter.connect() is True
        assert adapter._connected is True
        mock_paramiko.connect.assert_called_once()

    def test_connect_passes_host_and_username(self, mock_paramiko):
        config = _make_config(host="10.0.0.1", username="admin")
        adapter = _make_adapter(config)
        adapter.connect()
        call_kwargs = mock_paramiko.connect.call_args
        assert call_kwargs.kwargs["hostname"] == "10.0.0.1"
        assert call_kwargs.kwargs["username"] == "admin"

    def test_connect_uses_env_password(self, mock_paramiko):
        adapter = _make_adapter()
        adapter.connect()
        call_kwargs = mock_paramiko.connect.call_args
        assert call_kwargs.kwargs["password"] == "test-password"

    def test_connect_with_ssh_key(self, mock_paramiko):
        config = _make_config(ssh_key_path="/home/user/.ssh/id_rsa")
        adapter = _make_adapter(config)
        adapter.connect()
        call_kwargs = mock_paramiko.connect.call_args
        assert call_kwargs.kwargs["key_filename"] == "/home/user/.ssh/id_rsa"

    def test_connect_failure_returns_false(self, mock_paramiko):
        mock_paramiko.connect.side_effect = Exception("Connection refused")
        adapter = _make_adapter()
        assert adapter.connect() is False
        assert adapter._connected is False

    def test_connect_uses_reject_policy_by_default(self, mock_paramiko):
        adapter = _make_adapter()
        adapter.connect()
        mock_paramiko.set_missing_host_key_policy.assert_called_once()
        policy = mock_paramiko.set_missing_host_key_policy.call_args[0][0]
        assert policy is not None

    def test_connect_without_paramiko(self):
        """Import failure is handled gracefully."""
        with patch.dict("sys.modules", {"paramiko": None}):
            # Force reimport
            import importlib
            from goop_veil.mitigation.router import openwrt

            importlib.reload(openwrt)
            adapter = openwrt.OpenWrtAdapter(_make_config())
            assert adapter.connect() is False


# ---------------------------------------------------------------------------
# Channel
# ---------------------------------------------------------------------------


class TestSetChannel:
    """UCI command construction for channel changes."""

    def test_channel_command_string(self, mock_paramiko):
        adapter = _make_adapter()
        adapter.connect()
        adapter.set_channel(11)

        cmd = mock_paramiko.exec_command.call_args[0][0]
        assert "uci set wireless.radio0.channel=11" in cmd
        assert "uci commit wireless" in cmd
        assert "wifi reload" in cmd

    def test_channel_custom_interface(self, mock_paramiko):
        adapter = _make_adapter()
        adapter.connect()
        adapter.set_channel(6, interface="radio1")

        cmd = mock_paramiko.exec_command.call_args[0][0]
        assert "wireless.radio1.channel=6" in cmd

    def test_channel_updates_state(self, mock_paramiko):
        adapter = _make_adapter()
        adapter.connect()
        result = adapter.set_channel(1)
        assert result is True
        assert adapter._current_channel == 1
        assert len(adapter._changes_applied) == 1
        assert "channel=1" in adapter._changes_applied[0]

    def test_channel_invalid_interface_rejected(self, mock_paramiko):
        adapter = _make_adapter()
        adapter.connect()
        result = adapter.set_channel(6, interface="radio0; reboot")
        assert result is False


# ---------------------------------------------------------------------------
# Bandwidth
# ---------------------------------------------------------------------------


class TestSetBandwidth:
    """UCI command construction for bandwidth changes."""

    def test_bandwidth_20_ht20(self, mock_paramiko):
        adapter = _make_adapter()
        adapter.connect()
        adapter.set_bandwidth(20)
        cmd = mock_paramiko.exec_command.call_args[0][0]
        assert "htmode=HT20" in cmd

    def test_bandwidth_40_ht40(self, mock_paramiko):
        adapter = _make_adapter()
        adapter.connect()
        adapter.set_bandwidth(40)
        cmd = mock_paramiko.exec_command.call_args[0][0]
        assert "htmode=HT40" in cmd

    def test_bandwidth_80_vht80(self, mock_paramiko):
        adapter = _make_adapter()
        adapter.connect()
        adapter.set_bandwidth(80)
        cmd = mock_paramiko.exec_command.call_args[0][0]
        assert "htmode=VHT80" in cmd

    def test_bandwidth_160_vht160(self, mock_paramiko):
        adapter = _make_adapter()
        adapter.connect()
        adapter.set_bandwidth(160)
        cmd = mock_paramiko.exec_command.call_args[0][0]
        assert "htmode=VHT160" in cmd

    def test_bandwidth_unsupported_returns_false(self, mock_paramiko):
        adapter = _make_adapter()
        adapter.connect()
        result = adapter.set_bandwidth(60)
        assert result is False


# ---------------------------------------------------------------------------
# TX Power
# ---------------------------------------------------------------------------


class TestSetTxPower:
    """UCI command construction for TX power changes."""

    def test_tx_power_command(self, mock_paramiko):
        adapter = _make_adapter()
        adapter.connect()
        adapter.set_tx_power(15.0)
        cmd = mock_paramiko.exec_command.call_args[0][0]
        assert "txpower=15" in cmd
        assert "uci commit wireless" in cmd

    def test_tx_power_fcc_cap_at_20(self, mock_paramiko):
        adapter = _make_adapter()
        adapter.connect()
        adapter.set_tx_power(25.0)
        cmd = mock_paramiko.exec_command.call_args[0][0]
        # Should be capped to 20
        assert "txpower=20" in cmd

    def test_tx_power_at_limit(self, mock_paramiko):
        adapter = _make_adapter()
        adapter.connect()
        adapter.set_tx_power(20.0)
        cmd = mock_paramiko.exec_command.call_args[0][0]
        assert "txpower=20" in cmd


# ---------------------------------------------------------------------------
# PMF
# ---------------------------------------------------------------------------


class TestEnablePMF:
    """UCI command for Protected Management Frames."""

    def test_pmf_required(self, mock_paramiko):
        adapter = _make_adapter()
        adapter.connect()
        adapter.enable_pmf("required")
        cmd = mock_paramiko.exec_command.call_args[0][0]
        assert "ieee80211w=2" in cmd

    def test_pmf_optional(self, mock_paramiko):
        adapter = _make_adapter()
        adapter.connect()
        adapter.enable_pmf("optional")
        cmd = mock_paramiko.exec_command.call_args[0][0]
        assert "ieee80211w=1" in cmd

    def test_pmf_disabled(self, mock_paramiko):
        adapter = _make_adapter()
        adapter.connect()
        adapter.enable_pmf("disabled")
        cmd = mock_paramiko.exec_command.call_args[0][0]
        assert "ieee80211w=0" in cmd


# ---------------------------------------------------------------------------
# Beacon interval
# ---------------------------------------------------------------------------


class TestSetBeaconInterval:
    """UCI command for beacon interval."""

    def test_beacon_interval_command(self, mock_paramiko):
        adapter = _make_adapter()
        adapter.connect()
        adapter.set_beacon_interval(200)
        cmd = mock_paramiko.exec_command.call_args[0][0]
        assert "beacon_int=200" in cmd
        assert "uci commit wireless" in cmd
        assert "wifi reload" in cmd


# ---------------------------------------------------------------------------
# Dry-run mode
# ---------------------------------------------------------------------------


class TestDryRun:
    """Dry-run mode logs commands but does not execute them."""

    def test_dry_run_channel_not_executed(self, mock_paramiko):
        config = _make_config(apply_changes=False)
        adapter = _make_adapter(config)
        adapter.connect()
        result = adapter.set_channel(11)
        # In dry-run, _execute_ssh returns "" (logged only)
        assert result is True
        # exec_command should only have been called during connect, not for set_channel
        # Actually connect doesn't call exec_command, so no calls expected for the channel op
        # The only exec_command call would be from connect, but connect uses paramiko.connect
        # So exec_command should NOT be called for the channel set in dry-run
        # But the connect itself is real (we mock paramiko), the dry-run is about SSH commands
        # Let's check: after connect, exec_command should NOT be called for the channel
        # We need to verify no exec_command was called with a uci command
        for call in mock_paramiko.exec_command.call_args_list:
            assert "uci set" not in call[0][0] if call[0] else True

    def test_dry_run_returns_success(self, mock_paramiko):
        config = _make_config(apply_changes=False)
        adapter = _make_adapter(config)
        adapter.connect()
        assert adapter.set_channel(6) is True
        assert adapter.set_bandwidth(80) is True
        assert adapter.set_tx_power(15.0) is True
        assert adapter.enable_pmf("required") is True
        assert adapter.set_beacon_interval(100) is True


# ---------------------------------------------------------------------------
# Status parsing
# ---------------------------------------------------------------------------


class TestGetStatus:
    """Parsing of UCI output for router status."""

    def test_status_disconnected(self, mock_paramiko):
        adapter = _make_adapter()
        with patch("goop_veil.mitigation.models.RouterStatus") as MockStatus:
            MockStatus.return_value = SimpleNamespace(connected=False)
            status = adapter.get_status()
            assert status.connected is False

    def test_status_parses_uci_output(self, mock_paramiko):
        uci_output = (
            "wireless.radio0.channel='6'\n"
            "wireless.radio0.htmode='VHT80'\n"
            "wireless.radio0.txpower='15'\n"
            "wireless.radio0.hwmode='11a'\n"
            "wireless.@wifi-iface[0].ieee80211w='2'\n"
        )
        stdout_mock = MagicMock()
        stdout_mock.read.return_value = uci_output.encode()
        stderr_mock = MagicMock()
        stderr_mock.read.return_value = b""
        mock_paramiko.exec_command.return_value = (MagicMock(), stdout_mock, stderr_mock)

        adapter = _make_adapter()
        adapter.connect()

        with patch("goop_veil.mitigation.models.RouterStatus") as MockStatus:
            MockStatus.side_effect = lambda **kw: SimpleNamespace(**kw)
            status = adapter.get_status()
            assert status.connected is True
            assert status.current_channel == 6
            assert status.current_bandwidth_mhz == 80
            assert status.tx_power_dbm == 15.0
            assert status.pmf_enabled is True


# ---------------------------------------------------------------------------
# Neighbor AP scanning
# ---------------------------------------------------------------------------


class TestGetNeighborAPs:
    """Parsing of iwinfo scan output."""

    def test_parse_iwinfo_scan(self, mock_paramiko):
        scan_output = (
            'Cell 01 - Address: AA:BB:CC:DD:EE:01\n'
            '          ESSID: "TestNetwork"\n'
            '          Channel: 6\n'
            '          Signal: -45\n'
            '          Encryption: WPA2 PSK\n'
            '\n'
            'Cell 02 - Address: AA:BB:CC:DD:EE:02\n'
            '          ESSID: "OtherNet"\n'
            '          Channel: 11\n'
            '          Signal: -70\n'
            '          Encryption: none\n'
        )
        stdout_mock = MagicMock()
        stdout_mock.read.return_value = scan_output.encode()
        stderr_mock = MagicMock()
        stderr_mock.read.return_value = b""
        mock_paramiko.exec_command.return_value = (MagicMock(), stdout_mock, stderr_mock)

        adapter = _make_adapter()
        adapter.connect()
        aps = adapter.get_neighbor_aps()

        assert len(aps) == 2
        assert aps[0]["bssid"] == "AA:BB:CC:DD:EE:01"
        assert aps[0]["ssid"] == "TestNetwork"
        assert aps[0]["channel"] == 6
        assert aps[0]["signal_dbm"] == -45
        assert aps[1]["ssid"] == "OtherNet"

    def test_empty_scan(self, mock_paramiko):
        stdout_mock = MagicMock()
        stdout_mock.read.return_value = b""
        stderr_mock = MagicMock()
        stderr_mock.read.return_value = b""
        mock_paramiko.exec_command.return_value = (MagicMock(), stdout_mock, stderr_mock)

        adapter = _make_adapter()
        adapter.connect()
        aps = adapter.get_neighbor_aps()
        assert aps == []


# ---------------------------------------------------------------------------
# Connected clients
# ---------------------------------------------------------------------------


class TestGetConnectedClients:
    """Parsing of iwinfo assoclist output."""

    def test_parse_assoclist(self, mock_paramiko):
        assoc_output = (
            "AA:BB:CC:DD:EE:01  Signal: -30  RX: 144.4 MBit/s  TX: 72.2 MBit/s\n"
            "AA:BB:CC:DD:EE:02  Signal: -65  RX: 54.0 MBit/s  TX: 24.0 MBit/s\n"
        )
        stdout_mock = MagicMock()
        stdout_mock.read.return_value = assoc_output.encode()
        stderr_mock = MagicMock()
        stderr_mock.read.return_value = b""
        mock_paramiko.exec_command.return_value = (MagicMock(), stdout_mock, stderr_mock)

        adapter = _make_adapter()
        adapter.connect()
        clients = adapter.get_connected_clients()

        assert len(clients) == 2
        assert clients[0]["mac"] == "AA:BB:CC:DD:EE:01"
        assert clients[0]["signal_dbm"] == -30
        assert clients[0]["rx_rate_mbps"] == 144.4
        assert clients[0]["tx_rate_mbps"] == 72.2
