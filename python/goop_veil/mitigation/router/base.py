"""Abstract base class for router adapters and factory function.

Router adapters provide a uniform interface for reconfiguring home routers
to improve WiFi privacy (channel changes, TX power, PMF, beamforming, etc.).
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from goop_veil.config import RouterConfig
    from goop_veil.mitigation.models import RouterStatus

logger = logging.getLogger(__name__)


class BaseRouterAdapter(ABC):
    """Abstract base for router reconfiguration adapters."""

    @abstractmethod
    def connect(self) -> bool:
        """Establish connection to the router."""
        ...

    @abstractmethod
    def disconnect(self) -> None:
        """Close the router connection."""
        ...

    @abstractmethod
    def get_status(self) -> RouterStatus:
        """Return current router configuration status."""
        ...

    @abstractmethod
    def set_channel(self, channel: int, interface: str | None = None) -> bool:
        """Set the WiFi channel on the specified interface."""
        ...

    @abstractmethod
    def set_bandwidth(self, bandwidth_mhz: int, interface: str | None = None) -> bool:
        """Set the channel bandwidth (20/40/80/160 MHz)."""
        ...

    @abstractmethod
    def set_tx_power(self, power_dbm: float, interface: str | None = None) -> bool:
        """Set transmission power (must stay within FCC limits)."""
        ...

    @abstractmethod
    def enable_pmf(self, mode: Literal["required", "optional", "disabled"]) -> bool:
        """Enable or disable 802.11w Protected Management Frames."""
        ...

    @abstractmethod
    def set_band(self, band: Literal["2.4", "5", "6"], interface: str | None = None) -> bool:
        """Switch to the specified frequency band."""
        ...

    @abstractmethod
    def set_beacon_interval(self, interval_tu: int) -> bool:
        """Set the beacon interval in Time Units (1 TU = 1.024 ms)."""
        ...

    @abstractmethod
    def set_beamforming(self, enabled: bool) -> bool:
        """Enable or disable beamforming."""
        ...

    @abstractmethod
    def get_connected_clients(self) -> list[dict]:
        """Return list of currently connected WiFi clients."""
        ...

    @abstractmethod
    def get_neighbor_aps(self) -> list[dict]:
        """Return list of nearby access points (scan results)."""
        ...


def create_router_adapter(config: RouterConfig) -> BaseRouterAdapter | None:
    """Factory: create a router adapter based on configuration.

    Returns None if adapter_type is "none".

    Raises:
        ValueError: If adapter_type is not recognized.
    """
    if config.adapter_type == "none":
        return None

    if config.adapter_type == "mock":
        from goop_veil.mitigation.router.mock import MockRouterAdapter

        return MockRouterAdapter()

    if config.adapter_type == "openwrt":
        from goop_veil.mitigation.router.openwrt import OpenWrtAdapter

        return OpenWrtAdapter(config)

    if config.adapter_type == "unifi":
        from goop_veil.mitigation.router.unifi import UniFiAdapter

        return UniFiAdapter(config)

    if config.adapter_type == "tplink":
        from goop_veil.mitigation.router.tplink import TPLinkAdapter

        return TPLinkAdapter(config)

    raise ValueError(f"Unknown router adapter type: {config.adapter_type!r}")
