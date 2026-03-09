"""TP-Link router adapter — controls TP-Link routers via HTTP API.

Uses httpx for HTTP communication (optional dependency).
Optionally uses ``pytplinkrouter`` if available for richer control.
"""

from __future__ import annotations

import hashlib
import logging
import os
from typing import TYPE_CHECKING, Literal

from goop_veil.mitigation.router.base import BaseRouterAdapter

if TYPE_CHECKING:
    from goop_veil.config import RouterConfig
    from goop_veil.mitigation.models import RouterStatus

logger = logging.getLogger(__name__)


class TPLinkAdapter(BaseRouterAdapter):
    """Router adapter for TP-Link devices via HTTP API.

    Requires ``httpx`` (install with ``pip install goop-veil[router]``).
    Optionally uses ``pytplinkrouter`` for enhanced API coverage.
    Password is read from the ``VEIL_ROUTER_PASSWORD`` environment variable.
    """

    adapter_type: str = "tplink"

    def __init__(self, config: RouterConfig) -> None:
        self._config = config
        self._client = None
        self._tplink_client = None
        self._connected = False
        self._base_url = f"http://{config.host}"
        self._token: str | None = None
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
        """Authenticate with the TP-Link router.

        Attempts ``pytplinkrouter`` first, falls back to raw HTTP.
        """
        # Try pytplinkrouter library first
        if self._try_tplink_library():
            return True

        # Fall back to raw HTTP
        return self._connect_raw_http()

    def _try_tplink_library(self) -> bool:
        """Attempt connection using pytplinkrouter."""
        try:
            from tplinkrouterc import TplinkRouterProvider

            client = TplinkRouterProvider.get_client(
                self._base_url,
                self._password,
            )
            client.authorize()
            self._tplink_client = client
            self._connected = True
            logger.info(
                "Connected to TP-Link router at %s via pytplinkrouter",
                self._config.host,
            )
            return True
        except ImportError:
            logger.debug("pytplinkrouter not available, falling back to raw HTTP")
            return False
        except Exception:
            logger.debug("pytplinkrouter connection failed", exc_info=True)
            return False

    def _connect_raw_http(self) -> bool:
        """Authenticate via raw HTTP API."""
        try:
            import httpx
        except ImportError:
            logger.error("httpx not installed: pip install goop-veil[router]")
            return False

        try:
            self._client = httpx.Client(
                base_url=self._base_url,
                timeout=self._config.timeout_sec,
            )

            # TP-Link token-based auth: POST with MD5-hashed password
            password_hash = hashlib.md5(  # noqa: S324
                self._password.encode()
            ).hexdigest()

            resp = self._client.post(
                "/",
                data={
                    "operation": "login",
                    "username": self._config.username,
                    "password": password_hash,
                },
            )
            resp.raise_for_status()

            body = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
            self._token = body.get("stok") or body.get("token")

            if not self._token:
                # Some models return token in different format
                logger.warning(
                    "No auth token received from TP-Link router; "
                    "API access may be limited"
                )

            self._connected = True
            logger.info("Connected to TP-Link router at %s via HTTP", self._config.host)
            return True
        except Exception:
            logger.exception("Failed to connect to TP-Link router at %s", self._config.host)
            self._connected = False
            return False

    def disconnect(self) -> None:
        """Close the connection to the TP-Link router."""
        if self._tplink_client is not None:
            try:
                self._tplink_client.logout()
            except Exception:
                logger.debug("Error during TP-Link logout", exc_info=True)
            self._tplink_client = None

        if self._client is not None:
            try:
                self._client.close()
            except Exception:
                logger.debug("Error closing HTTP client", exc_info=True)
            self._client = None

        self._token = None
        self._connected = False
        logger.info("Disconnected from TP-Link router")

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    def get_status(self) -> RouterStatus:
        """Query the TP-Link router for current status."""
        from goop_veil.mitigation.models import RouterStatus

        if not self._connected:
            return RouterStatus(
                connected=False,
                adapter_type=self.adapter_type,
                changes_applied=list(self._changes_applied),
            )

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
        """Set the wireless channel."""
        payload = {"channel": channel}
        if self._post_wireless(payload):
            self._current_channel = channel
            self._changes_applied.append(f"channel={channel}")
            return True
        return False

    def set_bandwidth(self, bandwidth_mhz: int, interface: str | None = None) -> bool:
        """Set the wireless bandwidth."""
        bw_map = {20: "20MHz", 40: "40MHz", 80: "80MHz", 160: "160MHz"}
        bw_str = bw_map.get(bandwidth_mhz)
        if bw_str is None:
            logger.warning(
                "Unsupported bandwidth %d MHz; supported: %s",
                bandwidth_mhz,
                list(bw_map.keys()),
            )
            return False

        payload = {"bandwidth": bw_str}
        if self._post_wireless(payload):
            self._current_bandwidth_mhz = bandwidth_mhz
            self._changes_applied.append(f"bandwidth={bandwidth_mhz}MHz")
            return True
        return False

    def set_tx_power(self, power_dbm: float, interface: str | None = None) -> bool:
        """Set transmission power."""
        # TP-Link uses percentage-based power in some models
        # Map dBm to a rough percentage (20 dBm = 100%)
        power_pct = min(int((power_dbm / 20.0) * 100), 100)
        payload = {"tx_power": power_pct, "tx_power_dbm": int(power_dbm)}
        if self._post_wireless(payload):
            self._tx_power_dbm = power_dbm
            self._changes_applied.append(f"tx_power={power_dbm}dBm")
            return True
        return False

    def enable_pmf(self, mode: Literal["required", "optional", "disabled"]) -> bool:
        """Enable or disable PMF.

        Note: Many TP-Link models have limited PMF support via API.
        """
        logger.warning(
            "PMF configuration may not be available via TP-Link API; "
            "mode=%s logged but may not apply",
            mode,
        )
        payload = {"pmf": mode}
        if self._post_wireless(payload):
            self._pmf_enabled = mode == "required"
            self._changes_applied.append(f"pmf={mode}")
            return True
        return False

    def set_band(self, band: Literal["2.4", "5", "6"], interface: str | None = None) -> bool:
        """Set the wireless band."""
        payload = {"band": band}
        if self._post_wireless(payload):
            self._current_band = band
            self._changes_applied.append(f"band={band}GHz")
            return True
        return False

    def set_beacon_interval(self, interval_tu: int) -> bool:
        """Set the beacon interval.

        Note: Many TP-Link models do not expose beacon interval via API.
        """
        payload = {"beacon_interval": interval_tu}
        if self._post_wireless(payload):
            self._changes_applied.append(f"beacon_interval={interval_tu}TU")
            return True
        return False

    def set_beamforming(self, enabled: bool) -> bool:
        """Enable or disable beamforming."""
        payload = {"beamforming": "on" if enabled else "off"}
        if self._post_wireless(payload):
            self._beamforming_enabled = enabled
            self._changes_applied.append(f"beamforming={'on' if enabled else 'off'}")
            return True
        return False

    # ------------------------------------------------------------------
    # Client and AP scanning
    # ------------------------------------------------------------------

    def get_connected_clients(self) -> list[dict]:
        """Fetch connected clients from the TP-Link router."""
        if self._tplink_client is not None:
            return self._get_clients_tplink_lib()

        data = self._get_wireless_status()
        if data is None:
            return []

        clients_raw = data.get("clients", data.get("host_info", []))
        clients: list[dict] = []
        for entry in clients_raw:
            client: dict = {
                "mac": entry.get("mac", entry.get("macaddr", "")),
                "hostname": entry.get("hostname", entry.get("name", "")),
                "ip": entry.get("ip", entry.get("ipaddr", "")),
            }
            clients.append(client)
        return clients

    def get_neighbor_aps(self) -> list[dict]:
        """Fetch nearby APs.

        Note: Many TP-Link models do not expose AP scanning via their API.
        """
        logger.warning(
            "AP scanning may not be available via TP-Link API"
        )
        return []

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_clients_tplink_lib(self) -> list[dict]:
        """Fetch clients using pytplinkrouter."""
        try:
            status = self._tplink_client.get_status()
            clients: list[dict] = []
            if hasattr(status, "clients"):
                for mac, info in status.clients.items():
                    clients.append({
                        "mac": mac,
                        "hostname": getattr(info, "name", ""),
                        "ip": getattr(info, "ip", ""),
                    })
            return clients
        except Exception:
            logger.debug("pytplinkrouter get_status failed", exc_info=True)
            return []

    def _post_wireless(self, payload: dict) -> bool:
        """POST wireless configuration to the TP-Link API."""
        if not self._config.apply_changes:
            logger.info("[DRY-RUN] Would POST wireless config: %s", payload)
            return True

        if self._tplink_client is not None:
            logger.warning(
                "pytplinkrouter does not support direct wireless config; "
                "setting may not apply: %s",
                payload,
            )
            return False

        if not self._client:
            logger.error("Cannot call API — not connected")
            return False

        endpoint = self._wireless_endpoint()

        try:
            resp = self._client.post(endpoint, json=payload)
            resp.raise_for_status()
            return True
        except Exception:
            logger.warning(
                "TP-Link API call failed for payload %s — "
                "this setting may not be supported by this model",
                payload,
            )
            return False

    def _get_wireless_status(self) -> dict | None:
        """GET wireless status from the TP-Link API."""
        if not self._config.apply_changes:
            logger.info("[DRY-RUN] Would GET wireless status")
            return {}

        if not self._client:
            return None

        endpoint = self._wireless_endpoint()
        try:
            resp = self._client.get(endpoint)
            resp.raise_for_status()
            return resp.json()
        except Exception:
            logger.debug("Failed to get wireless status", exc_info=True)
            return None

    def _wireless_endpoint(self) -> str:
        """Build the wireless configuration endpoint URL."""
        if self._token:
            return f"/cgi-bin/luci/;stok={self._token}/admin/wireless"
        return "/cgi-bin/luci/admin/wireless"
