"""OpenWrt router adapter — controls OpenWrt routers via SSH + UCI commands.

Uses paramiko for SSH communication (optional dependency).
Supports channel, bandwidth, TX power, PMF, beacon interval,
beamforming, and band configuration via UCI command interface.
"""

from __future__ import annotations

import logging
import os
import re
from typing import TYPE_CHECKING, Literal

from goop_veil.mitigation.router.base import BaseRouterAdapter

if TYPE_CHECKING:
    from goop_veil.config import RouterConfig
    from goop_veil.mitigation.models import RouterStatus

logger = logging.getLogger(__name__)

# Bandwidth to HT mode mapping
_BW_TO_HTMODE: dict[int, str] = {
    20: "HT20",
    40: "HT40",
    80: "VHT80",
    160: "VHT160",
}

# PMF mode to ieee80211w value mapping
_PMF_TO_80211W: dict[str, int] = {
    "disabled": 0,
    "optional": 1,
    "required": 2,
}

# Band to hwmode mapping
_BAND_TO_HWMODE: dict[str, str] = {
    "2.4": "11g",
    "5": "11a",
    "6": "11a",
}

# FCC maximum conducted power (dBm)
_MAX_TX_POWER_DBM = 20.0


class OpenWrtAdapter(BaseRouterAdapter):
    """Router adapter for OpenWrt devices via SSH + UCI.

    Requires ``paramiko`` (install with ``pip install goop-veil[router]``).
    Password is read from the ``VEIL_ROUTER_PASSWORD`` environment variable.
    """

    adapter_type: str = "openwrt"

    def __init__(self, config: RouterConfig) -> None:
        self._config = config
        self._ssh_client = None
        self._connected = False
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
        """Establish SSH connection to the OpenWrt router."""
        try:
            import paramiko
        except ImportError:
            logger.error("paramiko not installed: pip install goop-veil[router]")
            return False

        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            connect_kwargs: dict = {
                "hostname": self._config.host,
                "username": self._config.username,
                "timeout": self._config.timeout_sec,
            }

            if self._config.ssh_key_path:
                connect_kwargs["key_filename"] = self._config.ssh_key_path
            if self._password:
                connect_kwargs["password"] = self._password

            client.connect(**connect_kwargs)
            self._ssh_client = client
            self._connected = True
            logger.info("Connected to OpenWrt router at %s", self._config.host)
            return True
        except Exception:
            logger.exception("Failed to connect to OpenWrt router at %s", self._config.host)
            self._connected = False
            return False

    def disconnect(self) -> None:
        """Close the SSH connection."""
        if self._ssh_client is not None:
            try:
                self._ssh_client.close()
            except Exception:
                logger.debug("Error closing SSH connection", exc_info=True)
            self._ssh_client = None
        self._connected = False
        logger.info("Disconnected from OpenWrt router")

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    def get_status(self) -> RouterStatus:
        """Query router status via UCI and return a RouterStatus model."""
        from goop_veil.mitigation.models import RouterStatus

        if not self._connected:
            return RouterStatus(
                connected=False,
                adapter_type=self.adapter_type,
                changes_applied=self._changes_applied,
            )

        # Parse live state from the router
        uci_output = self._execute_ssh("uci show wireless")
        iwinfo_output = self._execute_ssh("iwinfo")

        channel = self._parse_uci_value(uci_output, r"wireless\.radio0\.channel='?(\d+)'?")
        htmode = self._parse_uci_value(uci_output, r"wireless\.radio0\.htmode='?(\w+)'?")
        txpower = self._parse_uci_value(uci_output, r"wireless\.radio0\.txpower='?(\d+)'?")
        hwmode = self._parse_uci_value(uci_output, r"wireless\.radio0\.hwmode='?(\w+)'?")
        pmf_val = self._parse_uci_value(
            uci_output, r"wireless\.@wifi-iface\[0\]\.ieee80211w='?(\d+)'?"
        )

        # Derive bandwidth from htmode
        bw = None
        if htmode:
            for mhz, mode in _BW_TO_HTMODE.items():
                if mode == htmode:
                    bw = mhz
                    break

        # Derive band from hwmode
        band = None
        if hwmode:
            for b, hw in _BAND_TO_HWMODE.items():
                if hw == hwmode:
                    band = b
                    break

        return RouterStatus(
            connected=True,
            adapter_type=self.adapter_type,
            current_channel=int(channel) if channel else self._current_channel,
            current_bandwidth_mhz=bw if bw else self._current_bandwidth_mhz,
            current_band=band if band else self._current_band,
            pmf_enabled=pmf_val == "2" if pmf_val else self._pmf_enabled,
            tx_power_dbm=float(txpower) if txpower else self._tx_power_dbm,
            beamforming_enabled=self._beamforming_enabled,
            changes_applied=self._changes_applied,
        )

    # ------------------------------------------------------------------
    # Configuration methods
    # ------------------------------------------------------------------

    def set_channel(self, channel: int, interface: str | None = None) -> bool:
        """Set the wireless channel via UCI."""
        radio = interface or "radio0"
        cmd = (
            f"uci set wireless.{radio}.channel={channel} "
            f"&& uci commit wireless && wifi reload"
        )
        result = self._execute_ssh(cmd)
        if result is not None:
            self._current_channel = channel
            self._changes_applied.append(f"channel={channel}")
            return True
        return False

    def set_bandwidth(self, bandwidth_mhz: int, interface: str | None = None) -> bool:
        """Set the wireless bandwidth (HT mode) via UCI."""
        htmode = _BW_TO_HTMODE.get(bandwidth_mhz)
        if htmode is None:
            logger.warning(
                "Unsupported bandwidth %d MHz; supported: %s",
                bandwidth_mhz,
                list(_BW_TO_HTMODE.keys()),
            )
            return False

        radio = interface or "radio0"
        cmd = (
            f"uci set wireless.{radio}.htmode={htmode} "
            f"&& uci commit wireless && wifi reload"
        )
        result = self._execute_ssh(cmd)
        if result is not None:
            self._current_bandwidth_mhz = bandwidth_mhz
            self._changes_applied.append(f"bandwidth={bandwidth_mhz}MHz")
            return True
        return False

    def set_tx_power(self, power_dbm: float, interface: str | None = None) -> bool:
        """Set transmission power via UCI.

        Power is capped at the FCC maximum of 20 dBm.
        """
        if power_dbm > _MAX_TX_POWER_DBM:
            logger.warning(
                "TX power %.1f dBm exceeds FCC limit of %.1f dBm, capping",
                power_dbm,
                _MAX_TX_POWER_DBM,
            )
            power_dbm = _MAX_TX_POWER_DBM

        radio = interface or "radio0"
        tx_int = int(power_dbm)
        cmd = (
            f"uci set wireless.{radio}.txpower={tx_int} "
            f"&& uci commit wireless && wifi reload"
        )
        result = self._execute_ssh(cmd)
        if result is not None:
            self._tx_power_dbm = power_dbm
            self._changes_applied.append(f"tx_power={power_dbm}dBm")
            return True
        return False

    def enable_pmf(self, mode: Literal["required", "optional", "disabled"]) -> bool:
        """Enable or disable Protected Management Frames (802.11w) via UCI."""
        w_value = _PMF_TO_80211W.get(mode)
        if w_value is None:
            logger.warning("Unknown PMF mode: %s", mode)
            return False

        cmd = (
            f"uci set wireless.@wifi-iface[0].ieee80211w={w_value} "
            f"&& uci commit wireless && wifi reload"
        )
        result = self._execute_ssh(cmd)
        if result is not None:
            self._pmf_enabled = mode == "required"
            self._changes_applied.append(f"pmf={mode}")
            return True
        return False

    def set_band(self, band: Literal["2.4", "5", "6"], interface: str | None = None) -> bool:
        """Set the wireless band via UCI hwmode."""
        hwmode = _BAND_TO_HWMODE.get(band)
        if hwmode is None:
            logger.warning("Unsupported band: %s", band)
            return False

        radio = interface or "radio0"
        cmd = (
            f"uci set wireless.{radio}.hwmode={hwmode} "
            f"&& uci commit wireless && wifi reload"
        )
        result = self._execute_ssh(cmd)
        if result is not None:
            self._current_band = band
            self._changes_applied.append(f"band={band}GHz")
            return True
        return False

    def set_beacon_interval(self, interval_tu: int) -> bool:
        """Set the beacon interval (in TU) via UCI."""
        cmd = (
            f"uci set wireless.radio0.beacon_int={interval_tu} "
            f"&& uci commit wireless && wifi reload"
        )
        result = self._execute_ssh(cmd)
        if result is not None:
            self._changes_applied.append(f"beacon_interval={interval_tu}TU")
            return True
        return False

    def set_beamforming(self, enabled: bool) -> bool:
        """Enable or disable beamforming.

        Note: OpenWrt beamforming support depends on the hardware/driver.
        This sets a vendor-specific UCI option.
        """
        value = "1" if enabled else "0"
        cmd = (
            f"uci set wireless.radio0.txbf={value} "
            f"&& uci commit wireless && wifi reload"
        )
        result = self._execute_ssh(cmd)
        if result is not None:
            self._beamforming_enabled = enabled
            self._changes_applied.append(f"beamforming={'on' if enabled else 'off'}")
            return True
        return False

    # ------------------------------------------------------------------
    # Client and AP scanning
    # ------------------------------------------------------------------

    def get_connected_clients(self) -> list[dict]:
        """Parse connected clients from ``iwinfo wlan0 assoclist``."""
        output = self._execute_ssh("iwinfo wlan0 assoclist")
        if output is None:
            return []

        clients: list[dict] = []
        # Each client block starts with a MAC address line
        blocks = re.split(r"\n(?=[0-9A-Fa-f]{2}:)", output.strip())
        for block in blocks:
            if not block.strip():
                continue
            mac_match = re.match(r"([0-9A-Fa-f:]{17})", block)
            if not mac_match:
                continue
            client: dict = {"mac": mac_match.group(1)}

            signal_match = re.search(r"Signal:\s*(-?\d+)", block)
            if signal_match:
                client["signal_dbm"] = int(signal_match.group(1))

            rx_match = re.search(r"RX:\s*([\d.]+)\s*MBit/s", block)
            if rx_match:
                client["rx_rate_mbps"] = float(rx_match.group(1))

            tx_match = re.search(r"TX:\s*([\d.]+)\s*MBit/s", block)
            if tx_match:
                client["tx_rate_mbps"] = float(tx_match.group(1))

            clients.append(client)

        return clients

    def get_neighbor_aps(self) -> list[dict]:
        """Parse nearby APs from ``iwinfo wlan0 scan``."""
        output = self._execute_ssh("iwinfo wlan0 scan")
        if output is None:
            return []

        aps: list[dict] = []
        # Each AP block starts with a line containing a BSSID
        blocks = re.split(r"\n(?=Cell \d+)", output.strip())
        for block in blocks:
            if not block.strip():
                continue

            ap: dict = {}

            bssid_match = re.search(r"Address:\s*([0-9A-Fa-f:]{17})", block)
            if bssid_match:
                ap["bssid"] = bssid_match.group(1)

            ssid_match = re.search(r'ESSID:\s*"([^"]*)"', block)
            if ssid_match:
                ap["ssid"] = ssid_match.group(1)

            channel_match = re.search(r"Channel:\s*(\d+)", block)
            if channel_match:
                ap["channel"] = int(channel_match.group(1))

            signal_match = re.search(r"Signal:\s*(-?\d+)", block)
            if signal_match:
                ap["signal_dbm"] = int(signal_match.group(1))

            encryption_match = re.search(r"Encryption:\s*(.+)", block)
            if encryption_match:
                ap["encryption"] = encryption_match.group(1).strip()

            if ap:
                aps.append(ap)

        return aps

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_uci_value(uci_output: str | None, pattern: str) -> str | None:
        """Extract a value from UCI output using a regex pattern."""
        if not uci_output:
            return None
        match = re.search(pattern, uci_output)
        return match.group(1) if match else None

    def _execute_ssh(self, cmd: str) -> str | None:
        """Execute a command over SSH.

        If ``config.apply_changes`` is False, the command is logged
        but not executed (dry-run mode).

        Returns the command stdout on success, or None on failure.
        """
        if not self._config.apply_changes:
            logger.info("[DRY-RUN] Would execute: %s", cmd)
            return ""

        if not self._connected or self._ssh_client is None:
            logger.error("Cannot execute command — not connected")
            return None

        try:
            _stdin, stdout, stderr = self._ssh_client.exec_command(
                cmd, timeout=self._config.timeout_sec
            )
            output = stdout.read().decode("utf-8", errors="replace")
            err = stderr.read().decode("utf-8", errors="replace")
            if err.strip():
                logger.debug("SSH stderr: %s", err.strip())
            return output
        except Exception:
            logger.exception("SSH command failed: %s", cmd)
            return None
