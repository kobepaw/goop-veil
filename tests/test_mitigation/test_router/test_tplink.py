"""Tests for TPLinkAdapter — TP-Link HTTP API router control.

All tests use mocks for httpx; no real HTTP connections are made.
"""

from __future__ import annotations

import hashlib
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest


def _make_config(apply_changes: bool = True, **overrides) -> SimpleNamespace:
    """Create a minimal RouterConfig-like object for testing."""
    defaults = {
        "adapter_type": "tplink",
        "host": "192.168.0.1",
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
    monkeypatch.setenv("VEIL_ROUTER_PASSWORD", "test-tplink-pass")


def _build_mock_httpx():
    """Build a mock httpx module with a mock Client."""
    mock_httpx = MagicMock()
    mock_client = MagicMock()
    mock_httpx.Client.return_value = mock_client

    # Default login response with token
    login_resp = MagicMock()
    login_resp.raise_for_status = MagicMock()
    login_resp.headers = {"content-type": "application/json"}
    login_resp.json.return_value = {"stok": "abc123token"}
    mock_client.post.return_value = login_resp

    return mock_httpx, mock_client


@pytest.fixture
def mock_httpx_env():
    """Inject a mock httpx into sys.modules so deferred import finds it."""
    mock_httpx, mock_client = _build_mock_httpx()
    # Also block pytplinkrouter so we always fall through to raw HTTP
    with patch.dict(sys.modules, {"httpx": mock_httpx, "tplinkrouterc": None}):
        yield mock_httpx, mock_client


def _make_adapter(config=None):
    """Create a TPLinkAdapter."""
    from goop_veil.mitigation.router.tplink import TPLinkAdapter

    return TPLinkAdapter(config or _make_config())


# ---------------------------------------------------------------------------
# Connection
# ---------------------------------------------------------------------------


class TestConnect:
    """TP-Link HTTP authentication."""

    def test_connect_raw_http(self, mock_httpx_env):
        _mock_httpx, _mock_client = mock_httpx_env
        adapter = _make_adapter()
        assert adapter.connect() is True
        assert adapter._connected is True
        assert adapter._token == "abc123token"

    def test_connect_uses_md5_password(self, mock_httpx_env):
        """Password should be MD5-hashed for the login POST."""
        _mock_httpx, mock_client = mock_httpx_env
        adapter = _make_adapter()
        adapter.connect()

        call_kwargs = mock_client.post.call_args
        sent_data = call_kwargs.kwargs.get("data") or call_kwargs[1].get("data")
        expected_hash = hashlib.md5(b"test-tplink-pass").hexdigest()  # noqa: S324
        assert sent_data["password"] == expected_hash

    def test_connect_failure(self, mock_httpx_env):
        _mock_httpx, mock_client = mock_httpx_env
        mock_client.post.side_effect = Exception("Connection refused")
        adapter = _make_adapter()
        assert adapter.connect() is False

    def test_connect_without_httpx(self):
        """Import failure is handled gracefully."""
        with patch.dict(sys.modules, {"tplinkrouterc": None, "httpx": None}):
            adapter = _make_adapter()
            assert adapter.connect() is False


# ---------------------------------------------------------------------------
# Channel / Power
# ---------------------------------------------------------------------------


class TestSetChannel:
    """Channel configuration via TP-Link API."""

    def test_channel_api_call(self, mock_httpx_env):
        _mock_httpx, mock_client = mock_httpx_env
        # Return success for wireless POST
        post_resp = MagicMock()
        post_resp.raise_for_status = MagicMock()
        # First call is login, second is channel set
        login_resp = MagicMock()
        login_resp.raise_for_status = MagicMock()
        login_resp.headers = {"content-type": "application/json"}
        login_resp.json.return_value = {"stok": "abc123token"}
        mock_client.post.side_effect = [login_resp, post_resp]

        adapter = _make_adapter()
        adapter.connect()
        result = adapter.set_channel(11)

        assert result is True
        assert adapter._current_channel == 11

        # Verify the second POST was the channel set
        second_call = mock_client.post.call_args_list[1]
        endpoint = second_call[0][0]
        assert "stok=abc123token" in endpoint
        assert "admin/wireless" in endpoint

    def test_set_tx_power(self, mock_httpx_env):
        _mock_httpx, mock_client = mock_httpx_env
        login_resp = MagicMock()
        login_resp.raise_for_status = MagicMock()
        login_resp.headers = {"content-type": "application/json"}
        login_resp.json.return_value = {"stok": "tok"}

        post_resp = MagicMock()
        post_resp.raise_for_status = MagicMock()
        mock_client.post.side_effect = [login_resp, post_resp]

        adapter = _make_adapter()
        adapter.connect()
        result = adapter.set_tx_power(15.0)
        assert result is True
        assert adapter._tx_power_dbm == 15.0


# ---------------------------------------------------------------------------
# Graceful failure
# ---------------------------------------------------------------------------


class TestGracefulFailure:
    """Adapter returns False when API is unavailable."""

    def test_post_wireless_failure(self, mock_httpx_env):
        _mock_httpx, mock_client = mock_httpx_env
        login_resp = MagicMock()
        login_resp.raise_for_status = MagicMock()
        login_resp.headers = {"content-type": "application/json"}
        login_resp.json.return_value = {"stok": "tok"}

        fail_resp = MagicMock()
        fail_resp.raise_for_status.side_effect = Exception("404 Not Found")
        mock_client.post.side_effect = [login_resp, fail_resp]

        adapter = _make_adapter()
        adapter.connect()
        result = adapter.set_channel(6)
        assert result is False

    def test_unsupported_bandwidth(self, mock_httpx_env):
        _mock_httpx, _mock_client = mock_httpx_env
        adapter = _make_adapter()
        adapter.connect()
        result = adapter.set_bandwidth(60)
        assert result is False

    def test_neighbor_aps_returns_empty(self, mock_httpx_env):
        _mock_httpx, _mock_client = mock_httpx_env
        adapter = _make_adapter()
        adapter.connect()
        aps = adapter.get_neighbor_aps()
        assert aps == []


# ---------------------------------------------------------------------------
# Dry-run mode
# ---------------------------------------------------------------------------


class TestDryRun:
    """Dry-run mode logs calls but does not send them."""

    def test_dry_run_channel(self, mock_httpx_env):
        _mock_httpx, mock_client = mock_httpx_env
        config = _make_config(apply_changes=False)
        adapter = _make_adapter(config)
        adapter.connect()
        result = adapter.set_channel(11)
        assert result is True
        # Only the login POST should have been called, not the channel set
        assert mock_client.post.call_count == 1  # login only

    def test_dry_run_tx_power(self, mock_httpx_env):
        _mock_httpx, mock_client = mock_httpx_env
        config = _make_config(apply_changes=False)
        adapter = _make_adapter(config)
        adapter.connect()
        result = adapter.set_tx_power(10.0)
        assert result is True
        assert mock_client.post.call_count == 1  # login only

    def test_dry_run_beamforming(self, mock_httpx_env):
        _mock_httpx, mock_client = mock_httpx_env
        config = _make_config(apply_changes=False)
        adapter = _make_adapter(config)
        adapter.connect()
        result = adapter.set_beamforming(True)
        assert result is True
