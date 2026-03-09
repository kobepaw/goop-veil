"""Mock router adapter for development and testing without real hardware.

Records all commands in a list for test assertions.
Follows the MockESP32HAL pattern from hardware/esp32_hal.py.
"""

from __future__ import annotations

import logging
from typing import Literal

from goop_veil.mitigation.models import RouterStatus
from goop_veil.mitigation.router.base import BaseRouterAdapter

logger = logging.getLogger(__name__)


class MockRouterAdapter(BaseRouterAdapter):
    """Mock router adapter that records all commands for test assertions."""

    def __init__(self) -> None:
        self._connected = False
        self._channel: int = 6
        self._bandwidth_mhz: int = 20
        self._band: str = "2.4"
        self._pmf: str = "disabled"
        self._tx_power_dbm: float = 17.0
        self._beacon_interval_tu: int = 100
        self._beamforming: bool = True
        self._changes: list[str] = []
        self._commands: list[dict] = []

    @property
    def commands(self) -> list[dict]:
        """All commands sent (for test assertions)."""
        return list(self._commands)

    @property
    def changes(self) -> list[str]:
        """All changes applied (for test assertions)."""
        return list(self._changes)

    def connect(self) -> bool:
        self._connected = True
        self._commands.append({"cmd": "connect"})
        return True

    def disconnect(self) -> None:
        self._connected = False
        self._commands.append({"cmd": "disconnect"})

    def get_status(self) -> RouterStatus:
        self._commands.append({"cmd": "get_status"})
        return RouterStatus(
            connected=self._connected,
            adapter_type="mock",
            current_channel=self._channel,
            current_bandwidth_mhz=self._bandwidth_mhz,
            current_band=self._band,
            pmf_enabled=self._pmf == "required" or self._pmf == "optional",
            tx_power_dbm=self._tx_power_dbm,
            beamforming_enabled=self._beamforming,
            changes_applied=list(self._changes),
        )

    def set_channel(self, channel: int, interface: str | None = None) -> bool:
        self._channel = channel
        change = f"channel={channel}"
        if interface:
            change += f" (iface={interface})"
        self._changes.append(change)
        self._commands.append({"cmd": "set_channel", "channel": channel, "interface": interface})
        return True

    def set_bandwidth(self, bandwidth_mhz: int, interface: str | None = None) -> bool:
        self._bandwidth_mhz = bandwidth_mhz
        change = f"bandwidth={bandwidth_mhz}MHz"
        if interface:
            change += f" (iface={interface})"
        self._changes.append(change)
        self._commands.append({"cmd": "set_bandwidth", "bandwidth_mhz": bandwidth_mhz, "interface": interface})
        return True

    def set_tx_power(self, power_dbm: float, interface: str | None = None) -> bool:
        self._tx_power_dbm = power_dbm
        change = f"tx_power={power_dbm}dBm"
        if interface:
            change += f" (iface={interface})"
        self._changes.append(change)
        self._commands.append({"cmd": "set_tx_power", "power_dbm": power_dbm, "interface": interface})
        return True

    def enable_pmf(self, mode: Literal["required", "optional", "disabled"]) -> bool:
        self._pmf = mode
        self._changes.append(f"pmf={mode}")
        self._commands.append({"cmd": "enable_pmf", "mode": mode})
        return True

    def set_band(self, band: Literal["2.4", "5", "6"], interface: str | None = None) -> bool:
        self._band = band
        change = f"band={band}GHz"
        if interface:
            change += f" (iface={interface})"
        self._changes.append(change)
        self._commands.append({"cmd": "set_band", "band": band, "interface": interface})
        return True

    def set_beacon_interval(self, interval_tu: int) -> bool:
        self._beacon_interval_tu = interval_tu
        self._changes.append(f"beacon_interval={interval_tu}TU")
        self._commands.append({"cmd": "set_beacon_interval", "interval_tu": interval_tu})
        return True

    def set_beamforming(self, enabled: bool) -> bool:
        self._beamforming = enabled
        self._changes.append(f"beamforming={'on' if enabled else 'off'}")
        self._commands.append({"cmd": "set_beamforming", "enabled": enabled})
        return True

    def get_connected_clients(self) -> list[dict]:
        self._commands.append({"cmd": "get_connected_clients"})
        return [
            {"mac": "aa:bb:cc:dd:ee:01", "rssi": -45, "band": self._band},
            {"mac": "aa:bb:cc:dd:ee:02", "rssi": -62, "band": self._band},
        ]

    def get_neighbor_aps(self) -> list[dict]:
        self._commands.append({"cmd": "get_neighbor_aps"})
        return [
            {"ssid": "Neighbor1", "channel": 1, "rssi": -70, "band": "2.4"},
            {"ssid": "Neighbor2", "channel": 6, "rssi": -55, "band": "2.4"},
            {"ssid": "Neighbor3", "channel": 11, "rssi": -65, "band": "2.4"},
            {"ssid": "Neighbor5G", "channel": 36, "rssi": -60, "band": "5"},
        ]
