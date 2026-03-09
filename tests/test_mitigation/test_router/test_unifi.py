"""Tests for UniFiAdapter — UniFi Controller REST API router control.

All tests use mocks for httpx; no real HTTP connections are made.
"""

from __future__ import annotations

import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest


def _make_config(apply_changes: bool = True, **overrides) -> SimpleNamespace:
    """Create a minimal RouterConfig-like object for testing."""
    defaults = {
        "adapter_type": "unifi",
        "host": "192.168.1.1",
        "username": "admin",
        "ssh_key_path": None,
        "apply_changes": apply_changes,
        "timeout_sec": 10,
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


@pytest.fixture(autouse=True)
def _router_password(monkeypatch):
    """Set a test password in the environment."""
    monkeypatch.setenv("VEIL_ROUTER_PASSWORD", "test-unifi-pass")


def _build_mock_httpx():
    """Build a mock httpx module with a mock Client."""
    mock_httpx = MagicMock()
    mock_client = MagicMock()
    mock_httpx.Client.return_value = mock_client

    # Default login response
    login_resp = MagicMock()
    login_resp.raise_for_status = MagicMock()
    mock_client.post.return_value = login_resp

    # Default PUT response
    put_resp = MagicMock()
    put_resp.raise_for_status = MagicMock()
    mock_client.put.return_value = put_resp

    def _route_get(url, **kwargs):
        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        if "stat/device" in url:
            resp.json.return_value = {"data": [{"_id": "device123"}]}
        elif "stat/sta" in url:
            resp.json.return_value = {"data": []}
        elif "stat/rogueap" in url:
            resp.json.return_value = {"data": []}
        else:
            resp.json.return_value = {"data": []}
        return resp

    mock_client.get.side_effect = _route_get

    return mock_httpx, mock_client


@pytest.fixture
def mock_httpx_env():
    """Inject a mock httpx into sys.modules so deferred import finds it."""
    mock_httpx, mock_client = _build_mock_httpx()
    with patch.dict(sys.modules, {"httpx": mock_httpx}):
        yield mock_httpx, mock_client


def _make_adapter(config=None):
    """Create a UniFiAdapter with the given config."""
    from goop_veil.mitigation.router.unifi import UniFiAdapter

    return UniFiAdapter(config or _make_config())


# ---------------------------------------------------------------------------
# Connection / Login
# ---------------------------------------------------------------------------


class TestConnect:
    """UniFi API login."""

    def test_login_api_call(self, mock_httpx_env):
        mock_httpx, mock_client = mock_httpx_env
        adapter = _make_adapter()
        assert adapter.connect() is True

        # Verify login POST
        mock_client.post.assert_called_once_with(
            "/api/login",
            json={
                "username": "admin",
                "password": "test-unifi-pass",
            },
        )

    def test_login_sets_connected(self, mock_httpx_env):
        _mock_httpx, _mock_client = mock_httpx_env
        adapter = _make_adapter()
        adapter.connect()
        assert adapter._connected is True

    def test_login_discovers_device(self, mock_httpx_env):
        _mock_httpx, _mock_client = mock_httpx_env
        adapter = _make_adapter()
        adapter.connect()
        assert adapter._device_id == "device123"

    def test_login_failure(self, mock_httpx_env):
        _mock_httpx, mock_client = mock_httpx_env
        mock_client.post.side_effect = Exception("Auth failed")
        adapter = _make_adapter()
        assert adapter.connect() is False
        assert adapter._connected is False

    def test_ssl_verification_disabled(self, mock_httpx_env):
        mock_httpx, _mock_client = mock_httpx_env
        adapter = _make_adapter()
        adapter.connect()
        # Verify Client was created with verify=False
        call_kwargs = mock_httpx.Client.call_args
        assert call_kwargs.kwargs.get("verify") is False


# ---------------------------------------------------------------------------
# Channel
# ---------------------------------------------------------------------------


class TestSetChannel:
    """Channel configuration via UniFi API."""

    def test_channel_change_api_call(self, mock_httpx_env):
        _mock_httpx, mock_client = mock_httpx_env
        adapter = _make_adapter()
        adapter.connect()
        result = adapter.set_channel(11)

        assert result is True
        # Verify PUT was called with radio_table
        put_call = mock_client.put.call_args
        assert "rest/device/device123" in put_call[0][0]
        payload = put_call.kwargs.get("json") or put_call[1].get("json")
        assert payload["radio_table"] == [{"channel": 11}]

    def test_channel_updates_state(self, mock_httpx_env):
        _mock_httpx, _mock_client = mock_httpx_env
        adapter = _make_adapter()
        adapter.connect()
        adapter.set_channel(6)
        assert adapter._current_channel == 6
        assert len(adapter._changes_applied) == 1
        assert "channel=6" in adapter._changes_applied[0]


# ---------------------------------------------------------------------------
# Bandwidth
# ---------------------------------------------------------------------------


class TestSetBandwidth:
    """Bandwidth configuration via UniFi API."""

    def test_bandwidth_80_api_call(self, mock_httpx_env):
        _mock_httpx, mock_client = mock_httpx_env
        adapter = _make_adapter()
        adapter.connect()
        result = adapter.set_bandwidth(80)

        assert result is True
        put_call = mock_client.put.call_args
        payload = put_call.kwargs.get("json") or put_call[1].get("json")
        assert payload["radio_table"] == [{"ht": "VHT80"}]

    def test_bandwidth_unsupported(self, mock_httpx_env):
        _mock_httpx, _mock_client = mock_httpx_env
        adapter = _make_adapter()
        adapter.connect()
        result = adapter.set_bandwidth(60)
        assert result is False


# ---------------------------------------------------------------------------
# TX Power
# ---------------------------------------------------------------------------


class TestSetTxPower:
    """TX power configuration via UniFi API."""

    def test_tx_power_api_call(self, mock_httpx_env):
        _mock_httpx, mock_client = mock_httpx_env
        adapter = _make_adapter()
        adapter.connect()
        result = adapter.set_tx_power(17.0)

        assert result is True
        put_call = mock_client.put.call_args
        payload = put_call.kwargs.get("json") or put_call[1].get("json")
        assert payload["radio_table"] == [
            {"tx_power": 17, "tx_power_mode": "custom"}
        ]


# ---------------------------------------------------------------------------
# Dry-run mode
# ---------------------------------------------------------------------------


class TestDryRun:
    """Dry-run mode logs API calls but does not send them."""

    def test_dry_run_channel(self, mock_httpx_env):
        _mock_httpx, mock_client = mock_httpx_env
        config = _make_config(apply_changes=False)
        adapter = _make_adapter(config)
        adapter.connect()
        adapter._device_id = "device123"
        result = adapter.set_channel(11)
        assert result is True
        # PUT should not be called (dry-run)
        mock_client.put.assert_not_called()

    def test_dry_run_bandwidth(self, mock_httpx_env):
        _mock_httpx, mock_client = mock_httpx_env
        config = _make_config(apply_changes=False)
        adapter = _make_adapter(config)
        adapter.connect()
        adapter._device_id = "device123"
        result = adapter.set_bandwidth(40)
        assert result is True
        mock_client.put.assert_not_called()


# ---------------------------------------------------------------------------
# Connected clients
# ---------------------------------------------------------------------------


class TestGetConnectedClients:
    """Client list fetching from UniFi API."""

    def test_fetch_clients(self, mock_httpx_env):
        _mock_httpx, mock_client = mock_httpx_env

        def _route_get(url, **kwargs):
            resp = MagicMock()
            resp.raise_for_status = MagicMock()
            if "stat/sta" in url:
                resp.json.return_value = {
                    "data": [
                        {
                            "mac": "aa:bb:cc:dd:ee:01",
                            "hostname": "laptop",
                            "rssi": -45,
                            "rx_rate": 144400,
                            "tx_rate": 72200,
                            "ip": "192.168.1.100",
                        }
                    ]
                }
            else:
                resp.json.return_value = {"data": [{"_id": "device123"}]}
            return resp

        mock_client.get.side_effect = _route_get

        adapter = _make_adapter()
        adapter.connect()
        clients = adapter.get_connected_clients()

        assert len(clients) == 1
        assert clients[0]["mac"] == "aa:bb:cc:dd:ee:01"
        assert clients[0]["hostname"] == "laptop"


# ---------------------------------------------------------------------------
# Neighbor APs
# ---------------------------------------------------------------------------


class TestGetNeighborAPs:
    """Rogue AP detection from UniFi API."""

    def test_fetch_rogueaps(self, mock_httpx_env):
        _mock_httpx, mock_client = mock_httpx_env

        def _route_get(url, **kwargs):
            resp = MagicMock()
            resp.raise_for_status = MagicMock()
            if "stat/rogueap" in url:
                resp.json.return_value = {
                    "data": [
                        {
                            "bssid": "aa:bb:cc:dd:ee:ff",
                            "essid": "NeighborWiFi",
                            "channel": 6,
                            "rssi": -70,
                            "security": "wpa2",
                        }
                    ]
                }
            else:
                resp.json.return_value = {"data": [{"_id": "device123"}]}
            return resp

        mock_client.get.side_effect = _route_get

        adapter = _make_adapter()
        adapter.connect()
        aps = adapter.get_neighbor_aps()

        assert len(aps) == 1
        assert aps[0]["bssid"] == "aa:bb:cc:dd:ee:ff"
        assert aps[0]["ssid"] == "NeighborWiFi"
        assert aps[0]["channel"] == 6
