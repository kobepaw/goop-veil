"""UniFi router adapter — controls UniFi routers via REST API.

Uses httpx for HTTP communication (optional dependency).
Targets the UniFi Controller API at ``https://{host}:8443``.
"""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING, Literal

from goop_veil.mitigation.router.base import BaseRouterAdapter

if TYPE_CHECKING:
    from goop_veil.config import RouterConfig
    from goop_veil.mitigation.models import RouterStatus

logger = logging.getLogger(__name__)

# Bandwidth to UniFi channel width name
_BW_TO_UNIFI: dict[int, str] = {
    20: "HT20",
    40: "HT40",
    80: "VHT80",
    160: "VHT160",
}


class UniFiAdapter(BaseRouterAdapter):
    """Router adapter for UniFi devices via REST API.

    Requires ``httpx`` (install with ``pip install goop-veil[router]``).
    Password is read from the ``VEIL_ROUTER_PASSWORD`` environment variable.
    SSL verification is disabled by default (UniFi uses self-signed certs).
    """

    adapter_type: str = "unifi"

    def __init__(self, config: RouterConfig) -> None:
        self._config = config
        self._client = None
        self._connected = False
        self._base_url = f"https://{config.host}:8443"
        self._site = "default"
        self._device_id: str | None = None
        self._current_channel: int | None = None
        self._current_bandwidth_mhz: int | None = None
        self._current_band: str | None = None
        self._pmf_enabled: bool = False
        self._tx_power_dbm: float | None = None
        self._beamforming_enabled: bool = False
        self._changes_applied: list[str] = []
        self._password = os.environ.get("VEIL_ROUTER_PASSWORD", "")

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    def connect(self) -> bool:
        """Authenticate with the UniFi Controller API."""
        try:
            import httpx
        except ImportError:
            logger.error("httpx not installed: pip install goop-veil[router]")
            return False

        try:
            self._client = httpx.Client(
                base_url=self._base_url,
                verify=False,
                timeout=self._config.timeout_sec,
            )

            resp = self._client.post(
                "/api/login",
                json={
                    "username": self._config.username,
                    "password": self._password,
                },
            )
            resp.raise_for_status()

            # Discover the first device for configuration
            self._device_id = self._discover_device()
            self._connected = True
            logger.info("Connected to UniFi controller at %s", self._base_url)
            return True
        except Exception:
            logger.exception("Failed to connect to UniFi controller at %s", self._base_url)
            self._connected = False
            return False

    def disconnect(self) -> None:
        """Close the HTTP client session."""
        if self._client is not None:
            try:
                self._client.post("/api/logout")
            except Exception:
                logger.debug("Error during UniFi logout", exc_info=True)
            try:
                self._client.close()
            except Exception:
                logger.debug("Error closing HTTP client", exc_info=True)
            self._client = None
        self._connected = False
        logger.info("Disconnected from UniFi controller")

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    def get_status(self) -> RouterStatus:
        """Query the UniFi controller for device status."""
        from goop_veil.mitigation.models import RouterStatus

        if not self._connected or self._client is None:
            return RouterStatus(
                connected=False,
                adapter_type=self.adapter_type,
                changes_applied=list(self._changes_applied),
            )

        try:
            resp = self._api_get(f"/api/s/{self._site}/stat/device")
            if resp and isinstance(resp, list) and len(resp) > 0:
                device = resp[0]
                radio_table = device.get("radio_table_stats", [])
                if radio_table:
                    radio = radio_table[0]
                    self._current_channel = radio.get("channel")
                    self._tx_power_dbm = radio.get("tx_power")
        except Exception:
            logger.debug("Failed to fetch device status", exc_info=True)

        return RouterStatus(
            connected=True,
            adapter_type=self.adapter_type,
            current_channel=self._current_channel,
            current_bandwidth_mhz=self._current_bandwidth_mhz,
            current_band=self._current_band,
            pmf_enabled=self._pmf_enabled,
            tx_power_dbm=self._tx_power_dbm,
            beamforming_enabled=self._beamforming_enabled,
            changes_applied=list(self._changes_applied),
        )

    # ------------------------------------------------------------------
    # Configuration methods
    # ------------------------------------------------------------------

    def set_channel(self, channel: int, interface: str | None = None) -> bool:
        """Set the wireless channel via the UniFi API."""
        radio_override = {"channel": channel}
        if self._apply_radio_config(radio_override):
            self._current_channel = channel
            self._changes_applied.append(f"channel={channel}")
            return True
        return False

    def set_bandwidth(self, bandwidth_mhz: int, interface: str | None = None) -> bool:
        """Set the wireless bandwidth via the UniFi API."""
        ht_mode = _BW_TO_UNIFI.get(bandwidth_mhz)
        if ht_mode is None:
            logger.warning(
                "Unsupported bandwidth %d MHz; supported: %s",
                bandwidth_mhz,
                list(_BW_TO_UNIFI.keys()),
            )
            return False

        radio_override = {"ht": ht_mode}
        if self._apply_radio_config(radio_override):
            self._current_bandwidth_mhz = bandwidth_mhz
            self._changes_applied.append(f"bandwidth={bandwidth_mhz}MHz")
            return True
        return False

    def set_tx_power(self, power_dbm: float, interface: str | None = None) -> bool:
        """Set transmission power via the UniFi API."""
        radio_override = {"tx_power": int(power_dbm), "tx_power_mode": "custom"}
        if self._apply_radio_config(radio_override):
            self._tx_power_dbm = power_dbm
            self._changes_applied.append(f"tx_power={power_dbm}dBm")
            return True
        return False

    def enable_pmf(self, mode: Literal["required", "optional", "disabled"]) -> bool:
        """Enable or disable PMF via the UniFi API."""
        pmf_map = {"required": "required", "optional": "optional", "disabled": "disabled"}
        pmf_value = pmf_map.get(mode)
        if pmf_value is None:
            logger.warning("Unknown PMF mode: %s", mode)
            return False

        # PMF is set at the WLAN group level in UniFi
        payload = {"pmf_mode": pmf_value}
        if self._api_put_wlan(payload):
            self._pmf_enabled = mode == "required"
            self._changes_applied.append(f"pmf={mode}")
            return True
        return False

    def set_band(self, band: Literal["2.4", "5", "6"], interface: str | None = None) -> bool:
        """Set the wireless band via the UniFi API."""
        band_map = {"2.4": "ng", "5": "na", "6": "6e"}
        band_value = band_map.get(band)
        if band_value is None:
            logger.warning("Unsupported band: %s", band)
            return False

        radio_override = {"radio": band_value}
        if self._apply_radio_config(radio_override):
            self._current_band = band
            self._changes_applied.append(f"band={band}GHz")
            return True
        return False

    def set_beacon_interval(self, interval_tu: int) -> bool:
        """Set the beacon interval via the UniFi API."""
        radio_override = {"beacon_int": interval_tu}
        if self._apply_radio_config(radio_override):
            self._changes_applied.append(f"beacon_interval={interval_tu}TU")
            return True
        return False

    def set_beamforming(self, enabled: bool) -> bool:
        """Enable or disable beamforming via the UniFi API."""
        radio_override = {
            "mu_mimo": enabled,
            "tx_beamforming": enabled,
        }
        if self._apply_radio_config(radio_override):
            self._beamforming_enabled = enabled
            self._changes_applied.append(f"beamforming={'on' if enabled else 'off'}")
            return True
        return False

    # ------------------------------------------------------------------
    # Client and AP scanning
    # ------------------------------------------------------------------

    def get_connected_clients(self) -> list[dict]:
        """Fetch connected clients from the UniFi controller."""
        data = self._api_get(f"/api/s/{self._site}/stat/sta")
        if data is None:
            return []

        clients: list[dict] = []
        for sta in data:
            client: dict = {
                "mac": sta.get("mac", ""),
                "hostname": sta.get("hostname", ""),
                "signal_dbm": sta.get("rssi"),
                "rx_rate_mbps": sta.get("rx_rate", 0) / 1000.0 if sta.get("rx_rate") else None,
                "tx_rate_mbps": sta.get("tx_rate", 0) / 1000.0 if sta.get("tx_rate") else None,
                "ip": sta.get("ip"),
            }
            clients.append(client)
        return clients

    def get_neighbor_aps(self) -> list[dict]:
        """Fetch nearby rogue/neighbor APs from the UniFi controller."""
        data = self._api_get(f"/api/s/{self._site}/stat/rogueap")
        if data is None:
            return []

        aps: list[dict] = []
        for rogue in data:
            ap: dict = {
                "bssid": rogue.get("bssid", ""),
                "ssid": rogue.get("essid", ""),
                "channel": rogue.get("channel"),
                "signal_dbm": rogue.get("rssi"),
                "security": rogue.get("security", ""),
            }
            aps.append(ap)
        return aps

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _discover_device(self) -> str | None:
        """Find the first managed device ID."""
        data = self._api_get(f"/api/s/{self._site}/stat/device")
        if data and isinstance(data, list) and len(data) > 0:
            device_id = data[0].get("_id")
            logger.debug("Discovered UniFi device: %s", device_id)
            return device_id
        return None

    def _apply_radio_config(self, overrides: dict) -> bool:
        """Apply radio configuration overrides to the device."""
        if not self._device_id:
            logger.error("No device discovered — cannot apply radio config")
            return False

        endpoint = f"/api/s/{self._site}/rest/device/{self._device_id}"
        payload = {"radio_table": [overrides]}

        return self._api_put(endpoint, payload)

    def _api_get(self, endpoint: str) -> list | None:
        """Execute a GET request against the UniFi API."""
        if not self._config.apply_changes:
            logger.info("[DRY-RUN] Would GET: %s", endpoint)
            return []

        if not self._client:
            logger.error("Cannot call API — not connected")
            return None

        try:
            resp = self._client.get(endpoint)
            resp.raise_for_status()
            body = resp.json()
            return body.get("data", [])
        except Exception:
            logger.exception("UniFi API GET failed: %s", endpoint)
            return None

    def _api_put(self, endpoint: str, payload: dict) -> bool:
        """Execute a PUT request against the UniFi API."""
        if not self._config.apply_changes:
            logger.info("[DRY-RUN] Would PUT %s: %s", endpoint, payload)
            return True

        if not self._client:
            logger.error("Cannot call API — not connected")
            return False

        try:
            resp = self._client.put(endpoint, json=payload)
            resp.raise_for_status()
            return True
        except Exception:
            logger.exception("UniFi API PUT failed: %s", endpoint)
            return False

    def _api_put_wlan(self, payload: dict) -> bool:
        """Update WLAN group settings."""
        endpoint = f"/api/s/{self._site}/rest/wlanconf"

        if not self._config.apply_changes:
            logger.info("[DRY-RUN] Would PUT %s: %s", endpoint, payload)
            return True

        if not self._client:
            logger.error("Cannot call API — not connected")
            return False

        try:
            # Get current WLAN configs
            resp = self._client.get(endpoint)
            resp.raise_for_status()
            wlans = resp.json().get("data", [])
            if not wlans:
                logger.warning("No WLAN configurations found")
                return False

            # Update the first WLAN
            wlan_id = wlans[0].get("_id")
            resp = self._client.put(f"{endpoint}/{wlan_id}", json=payload)
            resp.raise_for_status()
            return True
        except Exception:
            logger.exception("UniFi WLAN config update failed")
            return False
