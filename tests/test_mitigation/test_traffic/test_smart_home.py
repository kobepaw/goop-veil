"""Tests for SmartHomeCoordinator.

All external I/O (mDNS, avahi-browse, HTTP, pychromecast) is mocked.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from goop_veil.config import TrafficConfig
from goop_veil.mitigation.traffic.smart_home import SmartHomeCoordinator, SmartHomeDevice


# ---------------------------------------------------------------------------
# SmartHomeDevice
# ---------------------------------------------------------------------------


class TestSmartHomeDevice:
    def test_creation(self) -> None:
        d = SmartHomeDevice(
            name="Living Room Speaker",
            ip="192.168.1.100",
            port=8008,
            device_type="chromecast",
            protocol="mdns",
            mac="aa:bb:cc:dd:ee:ff",
        )
        assert d.name == "Living Room Speaker"
        assert d.ip == "192.168.1.100"
        assert d.port == 8008
        assert d.device_type == "chromecast"
        assert d.protocol == "mdns"
        assert d.mac == "aa:bb:cc:dd:ee:ff"

    def test_default_mac(self) -> None:
        d = SmartHomeDevice("dev", "10.0.0.1", 80, "unknown", "http")
        assert d.mac == ""

    def test_repr(self) -> None:
        d = SmartHomeDevice("tv", "10.0.0.5", 8060, "roku", "mdns")
        r = repr(d)
        assert "tv" in r
        assert "roku" in r


# ---------------------------------------------------------------------------
# SmartHomeCoordinator — Discovery
# ---------------------------------------------------------------------------


class TestDiscovery:
    def test_discover_no_zeroconf_no_avahi(self) -> None:
        """Falls back gracefully when zeroconf is not installed and avahi not found."""
        coord = SmartHomeCoordinator()
        with (
            patch.dict("sys.modules", {"zeroconf": None}),
            patch(
                "goop_veil.mitigation.traffic.smart_home.subprocess.run",
                side_effect=FileNotFoundError,
            ),
        ):
            devices = coord.discover_devices()
        assert devices == []

    def test_discover_avahi_parses_output(self) -> None:
        """Avahi-browse output is parsed correctly."""
        avahi_output = (
            "=;eth0;IPv4;My Device;_http._tcp;local;mydevice.local;192.168.1.50;8080;txt\n"
        )
        mock_result = MagicMock()
        mock_result.stdout = avahi_output

        coord = SmartHomeCoordinator()
        with (
            patch.dict("sys.modules", {"zeroconf": None}),
            patch(
                "goop_veil.mitigation.traffic.smart_home.subprocess.run",
                return_value=mock_result,
            ),
        ):
            devices = coord.discover_devices()

        assert len(devices) == 1
        assert devices[0].name == "My Device"
        assert devices[0].ip == "192.168.1.50"
        assert devices[0].port == 8080

    def test_discover_avahi_timeout(self) -> None:
        """Handles avahi-browse timeout gracefully."""
        import subprocess

        coord = SmartHomeCoordinator()
        with (
            patch.dict("sys.modules", {"zeroconf": None}),
            patch(
                "goop_veil.mitigation.traffic.smart_home.subprocess.run",
                side_effect=subprocess.TimeoutExpired(cmd="avahi-browse", timeout=10),
            ),
        ):
            devices = coord.discover_devices()
        assert devices == []


# ---------------------------------------------------------------------------
# SmartHomeCoordinator — Activity Triggering
# ---------------------------------------------------------------------------


class TestTriggerActivity:
    def test_unknown_device_type_returns_false(self) -> None:
        coord = SmartHomeCoordinator()
        device = SmartHomeDevice("sensor", "10.0.0.1", 80, "unknown", "http")
        assert coord.trigger_activity(device) is False

    def test_roku_trigger_with_httpx(self) -> None:
        coord = SmartHomeCoordinator()
        device = SmartHomeDevice("Roku TV", "192.168.1.10", 8060, "roku", "mdns")

        mock_httpx = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_httpx.get.return_value = mock_resp

        with patch.dict("sys.modules", {"httpx": mock_httpx}):
            result = coord.trigger_activity(device)
        assert result is True

    def test_homeassistant_trigger(self) -> None:
        coord = SmartHomeCoordinator()
        device = SmartHomeDevice("HA", "10.0.0.5", 8123, "homeassistant", "http")

        mock_httpx = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 401  # unauthenticated but device responded
        mock_httpx.get.return_value = mock_resp

        with patch.dict("sys.modules", {"httpx": mock_httpx}):
            result = coord.trigger_activity(device)
        assert result is True

    def test_chromecast_no_pychromecast(self) -> None:
        coord = SmartHomeCoordinator()
        device = SmartHomeDevice("Speaker", "10.0.0.2", 8008, "chromecast", "mdns")

        with patch.dict("sys.modules", {"pychromecast": None}):
            result = coord.trigger_activity(device)
        assert result is False


# ---------------------------------------------------------------------------
# SmartHomeCoordinator — RF Diversity Score
# ---------------------------------------------------------------------------


class TestRFDiversityScore:
    def test_no_devices_returns_zero(self) -> None:
        coord = SmartHomeCoordinator()
        assert coord.get_rf_diversity_score() == 0.0

    def test_score_with_devices_is_positive(self) -> None:
        coord = SmartHomeCoordinator()
        coord._devices = [
            SmartHomeDevice("d1", "10.0.0.1", 80, "chromecast", "mdns"),
            SmartHomeDevice("d2", "10.0.0.2", 80, "roku", "mdns"),
        ]
        score = coord.get_rf_diversity_score()
        assert 0.0 < score <= 1.0

    def test_score_bounded_0_to_1(self) -> None:
        coord = SmartHomeCoordinator()
        # Many devices of varied types
        coord._devices = [
            SmartHomeDevice(f"d{i}", f"10.0.0.{i}", 80, t, "mdns")
            for i, t in enumerate(
                ["chromecast", "roku", "homekit", "unknown", "speaker",
                 "display", "hub", "sensor", "light", "thermostat"]
            )
        ]
        score = coord.get_rf_diversity_score()
        assert 0.0 <= score <= 1.0

    def test_more_devices_higher_score(self) -> None:
        coord1 = SmartHomeCoordinator()
        coord1._devices = [
            SmartHomeDevice("d1", "10.0.0.1", 80, "chromecast", "mdns"),
        ]

        coord2 = SmartHomeCoordinator()
        coord2._devices = [
            SmartHomeDevice("d1", "10.0.0.1", 80, "chromecast", "mdns"),
            SmartHomeDevice("d2", "10.0.0.2", 80, "roku", "mdns"),
            SmartHomeDevice("d3", "10.0.0.3", 80, "homekit", "mdns"),
        ]

        assert coord2.get_rf_diversity_score() > coord1.get_rf_diversity_score()
