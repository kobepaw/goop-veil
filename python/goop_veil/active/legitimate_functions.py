"""Legitimate functions — manages the real WiFi services that justify operation.

Each active defense node runs genuine WiFi services:
1. WiFi Mesh Access Point (beacons, data, ACKs, mesh peering)
2. IoT Environmental Sensors (BME280 via MQTT every 3 sec)
3. Indoor Positioning (802.11mc Fine Timing Measurement)
4. WiFi Site Survey (channel monitoring)
5. Occupancy Counting (WiFi-based occupancy for HVAC)

These functions are the primary purpose of the device. The privacy
enhancement effect is a secondary benefit of the legitimate RF activity.
"""

from __future__ import annotations

import logging
from datetime import datetime

from goop_veil.compliance import LegitimateFunction

logger = logging.getLogger(__name__)


class LegitimateServiceStatus:
    """Status of a single legitimate service."""

    __slots__ = ("function", "enabled", "active", "last_activity", "frame_count")

    def __init__(self, function: LegitimateFunction) -> None:
        self.function = function
        self.enabled = False
        self.active = False
        self.last_activity: datetime | None = None
        self.frame_count = 0

    def to_dict(self) -> dict:
        return {
            "function": self.function.value,
            "enabled": self.enabled,
            "active": self.active,
            "last_activity": self.last_activity.isoformat() if self.last_activity else None,
            "frame_count": self.frame_count,
        }


class LegitimateServiceManager:
    """Manages legitimate WiFi services on the ESP32 node."""

    def __init__(self, hal: object | None = None) -> None:
        self._hal = hal
        self._services: dict[LegitimateFunction, LegitimateServiceStatus] = {
            func: LegitimateServiceStatus(func) for func in LegitimateFunction
        }

    def enable(self, function: LegitimateFunction) -> None:
        """Enable a legitimate service."""
        status = self._services[function]
        status.enabled = True
        if self._hal is not None:
            self._hal.enable_function(function.value)
        logger.info("Enabled legitimate function: %s", function.value)

    def disable(self, function: LegitimateFunction) -> None:
        """Disable a legitimate service."""
        status = self._services[function]
        status.enabled = False
        status.active = False
        logger.info("Disabled legitimate function: %s", function.value)

    def start_all(self) -> None:
        """Start all enabled services."""
        for func, status in self._services.items():
            if status.enabled:
                status.active = True
                status.last_activity = datetime.now()
                logger.debug("Started service: %s", func.value)

    def stop_all(self) -> None:
        """Stop all services."""
        for status in self._services.values():
            status.active = False

    def record_activity(self, function: LegitimateFunction) -> None:
        """Record activity for a legitimate function (for audit trail)."""
        status = self._services[function]
        status.last_activity = datetime.now()
        status.frame_count += 1

    def get_status(self) -> list[dict]:
        """Get status of all legitimate services."""
        return [s.to_dict() for s in self._services.values()]

    def get_active_functions(self) -> list[LegitimateFunction]:
        """Get list of currently active legitimate functions."""
        return [func for func, s in self._services.items() if s.active]
