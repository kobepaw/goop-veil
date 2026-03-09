"""WiFi HAL — abstraction for WiFi interface operations (monitor mode, scanning).

Provides interface for WiFi monitor mode capture, channel control, and
live frame capture. Three implementations:

- LinuxWiFiHAL: Real monitor mode via iw + tcpdump (requires root/CAP_NET_ADMIN)
- ScanWiFiHAL: Network scanning without monitor mode (no root needed on some systems)
- MockWiFiHAL: Testing without WiFi hardware
"""

from __future__ import annotations

import logging
import subprocess
import tempfile
import time
from abc import ABC, abstractmethod
from pathlib import Path

logger = logging.getLogger(__name__)


class BaseWiFiHAL(ABC):
    """Abstract base for WiFi hardware abstraction."""

    @abstractmethod
    def start_monitor(self, interface: str, channel: int | None = None) -> bool:
        """Start WiFi monitor mode on an interface."""
        ...

    @abstractmethod
    def stop_monitor(self) -> None:
        """Stop monitor mode."""
        ...

    @abstractmethod
    def set_channel(self, channel: int) -> bool:
        """Set the monitoring channel."""
        ...

    @abstractmethod
    def capture_frames(self, duration_sec: float) -> list[bytes]:
        """Capture raw 802.11 frames for the given duration."""
        ...

    @abstractmethod
    def capture_to_pcap(self, output_path: str | Path, duration_sec: float) -> bool:
        """Capture frames directly to a pcap file."""
        ...

    @abstractmethod
    def get_interface_info(self) -> dict:
        """Get information about the WiFi interface."""
        ...

    @abstractmethod
    def scan_networks(self) -> list[dict]:
        """Scan for visible WiFi networks (no monitor mode needed)."""
        ...


class LinuxWiFiHAL(BaseWiFiHAL):
    """Real WiFi HAL for Linux — uses iw + tcpdump for monitor mode capture.

    Requires root or CAP_NET_ADMIN capability for monitor mode.
    Falls back to scan-only mode if permissions are insufficient.
    """

    def __init__(self, interface: str | None = None) -> None:
        self._interface = interface or self._detect_interface()
        self._monitor_interface: str | None = None
        self._monitoring = False
        self._original_type: str | None = None

    @staticmethod
    def _detect_interface() -> str:
        """Auto-detect the WiFi interface via iw dev."""
        try:
            result = subprocess.run(
                ["iw", "dev"],
                capture_output=True, text=True, timeout=5,
            )
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.startswith("Interface "):
                    iface = line.split()[1]
                    logger.info("Auto-detected WiFi interface: %s", iface)
                    return iface
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return "wlan0"

    @staticmethod
    def _supports_monitor(interface: str) -> bool:
        """Check if interface supports monitor mode."""
        try:
            result = subprocess.run(
                ["iw", "phy", "phy0", "info"],
                capture_output=True, text=True, timeout=5,
            )
            return "monitor" in result.stdout
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def start_monitor(self, interface: str | None = None, channel: int | None = None) -> bool:
        """Enter monitor mode on the WiFi interface.

        Requires root or CAP_NET_ADMIN.
        """
        iface = interface or self._interface

        if not self._supports_monitor(iface):
            logger.error("Interface %s does not support monitor mode", iface)
            return False

        try:
            # Bring interface down
            subprocess.run(["ip", "link", "set", iface, "down"], check=True, timeout=5)
            # Set monitor mode
            subprocess.run(["iw", iface, "set", "type", "monitor"], check=True, timeout=5)
            # Bring interface up
            subprocess.run(["ip", "link", "set", iface, "up"], check=True, timeout=5)

            if channel:
                subprocess.run(
                    ["iw", iface, "set", "channel", str(channel)],
                    check=True, timeout=5,
                )

            self._monitor_interface = iface
            self._monitoring = True
            logger.info("Monitor mode active on %s (channel %s)", iface, channel or "auto")
            return True

        except subprocess.CalledProcessError as e:
            logger.error("Failed to enter monitor mode (need root?): %s", e)
            return False
        except FileNotFoundError:
            logger.error("iw command not found — install iw: sudo apt install iw")
            return False

    def stop_monitor(self) -> None:
        """Return interface to managed mode."""
        if not self._monitoring or not self._monitor_interface:
            return

        iface = self._monitor_interface
        try:
            subprocess.run(["ip", "link", "set", iface, "down"], check=True, timeout=5)
            subprocess.run(["iw", iface, "set", "type", "managed"], check=True, timeout=5)
            subprocess.run(["ip", "link", "set", iface, "up"], check=True, timeout=5)
            logger.info("Restored managed mode on %s", iface)
        except (subprocess.CalledProcessError, FileNotFoundError):
            logger.exception("Failed to restore managed mode")

        self._monitoring = False
        self._monitor_interface = None

    def set_channel(self, channel: int) -> bool:
        if not self._monitoring or not self._monitor_interface:
            return False
        try:
            subprocess.run(
                ["iw", self._monitor_interface, "set", "channel", str(channel)],
                check=True, timeout=5,
            )
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False

    def capture_frames(self, duration_sec: float) -> list[bytes]:
        """Capture raw frames via tcpdump, parse with Rust core."""
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
            pcap_path = tmp.name

        if not self.capture_to_pcap(pcap_path, duration_sec):
            return []

        try:
            from goop_veil._core import parse_pcap_bytes

            data = Path(pcap_path).read_bytes()
            frames = parse_pcap_bytes(data)
            return [bytes(frame_bytes) for _, frame_bytes in frames]
        finally:
            Path(pcap_path).unlink(missing_ok=True)

    def capture_to_pcap(self, output_path: str | Path, duration_sec: float) -> bool:
        """Capture frames directly to pcap file via tcpdump."""
        iface = self._monitor_interface or self._interface

        try:
            proc = subprocess.run(
                [
                    "tcpdump", "-i", iface,
                    "-w", str(output_path),
                    "-G", str(int(duration_sec)),
                    "-W", "1",  # Single rotation = stop after duration
                    "type", "mgt", "or", "type", "data",
                ],
                capture_output=True, timeout=duration_sec + 10,
            )
            logger.info(
                "Captured to %s (%d bytes)",
                output_path,
                Path(output_path).stat().st_size if Path(output_path).exists() else 0,
            )
            return Path(output_path).exists()
        except subprocess.TimeoutExpired:
            # Expected — tcpdump runs for duration then we kill it
            return Path(output_path).exists()
        except FileNotFoundError:
            logger.error("tcpdump not found — install: sudo apt install tcpdump")
            return False

    def get_interface_info(self) -> dict:
        result = {"interface": self._interface, "monitoring": self._monitoring}
        try:
            out = subprocess.run(
                ["iw", self._interface, "info"],
                capture_output=True, text=True, timeout=5,
            )
            for line in out.stdout.splitlines():
                line = line.strip()
                if line.startswith("type "):
                    result["type"] = line.split()[1]
                elif line.startswith("channel "):
                    result["channel"] = int(line.split()[1])
                elif line.startswith("ssid "):
                    result["ssid"] = line.split(maxsplit=1)[1]
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass
        return result

    def scan_networks(self) -> list[dict]:
        """Scan visible networks using iw (no monitor mode needed)."""
        try:
            result = subprocess.run(
                ["iw", self._interface, "scan", "-u"],
                capture_output=True, text=True, timeout=30,
            )
            return self._parse_iw_scan(result.stdout)
        except subprocess.CalledProcessError:
            # May need trigger first
            try:
                subprocess.run(
                    ["iw", self._interface, "scan", "trigger"],
                    capture_output=True, timeout=10,
                )
                time.sleep(2)
                result = subprocess.run(
                    ["iw", self._interface, "scan", "dump"],
                    capture_output=True, text=True, timeout=10,
                )
                return self._parse_iw_scan(result.stdout)
            except (subprocess.CalledProcessError, FileNotFoundError):
                return []
        except FileNotFoundError:
            return []

    @staticmethod
    def _parse_iw_scan(output: str) -> list[dict]:
        """Parse iw scan output into network dicts."""
        networks: list[dict] = []
        current: dict = {}

        for line in output.splitlines():
            line = line.strip()
            if line.startswith("BSS "):
                if current:
                    networks.append(current)
                bssid = line.split()[1].rstrip("(")
                current = {"bssid": bssid}
            elif line.startswith("SSID:"):
                current["ssid"] = line.split(":", 1)[1].strip()
            elif line.startswith("signal:"):
                try:
                    current["signal_dbm"] = float(line.split(":")[1].strip().split()[0])
                except (ValueError, IndexError):
                    pass
            elif line.startswith("freq:"):
                try:
                    current["freq_mhz"] = int(line.split(":")[1].strip())
                except (ValueError, IndexError):
                    pass
            elif "primary channel:" in line.lower():
                try:
                    current["channel"] = int(line.split(":")[1].strip())
                except (ValueError, IndexError):
                    pass

        if current:
            networks.append(current)

        return networks


class ScanOnlyHAL(BaseWiFiHAL):
    """WiFi HAL that only scans for networks — no monitor mode needed.

    Uses nmcli or iw scan to detect visible networks and check for
    Espressif devices, suspicious SSIDs, and rapid AP changes.
    No root required on most Linux systems.
    """

    def __init__(self, interface: str | None = None) -> None:
        self._interface = interface or "wlan0"

    def start_monitor(self, interface: str = "wlan0", channel: int | None = None) -> bool:
        logger.warning("ScanOnlyHAL does not support monitor mode — use scan_networks()")
        return False

    def stop_monitor(self) -> None:
        pass

    def set_channel(self, channel: int) -> bool:
        return False

    def capture_frames(self, duration_sec: float) -> list[bytes]:
        logger.warning("ScanOnlyHAL cannot capture raw frames — use scan_networks()")
        return []

    def capture_to_pcap(self, output_path: str | Path, duration_sec: float) -> bool:
        logger.warning("ScanOnlyHAL cannot capture pcap — use scan_networks()")
        return False

    def get_interface_info(self) -> dict:
        return {"interface": self._interface, "monitoring": False, "mode": "scan_only"}

    def scan_networks(self) -> list[dict]:
        """Scan using nmcli (works without root on most systems)."""
        try:
            result = subprocess.run(
                [
                    "nmcli", "-t", "-f",
                    "BSSID,SSID,CHAN,FREQ,SIGNAL,SECURITY",
                    "device", "wifi", "list",
                    "--rescan", "yes",
                ],
                capture_output=True, text=True, timeout=30,
            )
            networks: list[dict] = []
            for line in result.stdout.strip().splitlines():
                parts = line.split(":")
                if len(parts) >= 6:
                    # nmcli escapes colons in BSSID with backslash
                    bssid = ":".join(parts[:6]).replace("\\", "")
                    rest = parts[6:]
                    if len(rest) >= 5:
                        networks.append({
                            "bssid": bssid,
                            "ssid": rest[0],
                            "channel": int(rest[1]) if rest[1].isdigit() else 0,
                            "freq_mhz": int(rest[2]) if rest[2].isdigit() else 0,
                            "signal_pct": int(rest[3]) if rest[3].isdigit() else 0,
                            "security": rest[4],
                        })
            return networks
        except (FileNotFoundError, subprocess.TimeoutExpired):
            logger.debug("nmcli not available, falling back to iw scan")
            return LinuxWiFiHAL(self._interface).scan_networks()


class MockWiFiHAL(BaseWiFiHAL):
    """Mock WiFi HAL for testing without WiFi hardware."""

    def __init__(self, pcap_path: str | Path | None = None) -> None:
        self._monitoring = False
        self._channel = 6
        self._interface = "wlan0mon"
        self._pcap_path = Path(pcap_path) if pcap_path else None

    def start_monitor(self, interface: str = "wlan0", channel: int | None = None) -> bool:
        self._interface = interface + "mon"
        self._monitoring = True
        if channel:
            self._channel = channel
        logger.info("Mock WiFi monitor started on %s, channel %d", self._interface, self._channel)
        return True

    def stop_monitor(self) -> None:
        self._monitoring = False

    def set_channel(self, channel: int) -> bool:
        self._channel = channel
        return True

    def capture_frames(self, duration_sec: float) -> list[bytes]:
        if self._pcap_path and self._pcap_path.exists():
            from goop_veil._core import parse_pcap_bytes

            data = self._pcap_path.read_bytes()
            frames = parse_pcap_bytes(data)
            return [bytes(frame_bytes) for _, frame_bytes in frames]
        return []

    def capture_to_pcap(self, output_path: str | Path, duration_sec: float) -> bool:
        if self._pcap_path and self._pcap_path.exists():
            import shutil
            shutil.copy2(self._pcap_path, output_path)
            return True
        return False

    def get_interface_info(self) -> dict:
        return {
            "interface": self._interface,
            "monitoring": self._monitoring,
            "channel": self._channel,
            "driver": "mock",
        }

    def scan_networks(self) -> list[dict]:
        return []


def create_wifi_hal(interface: str | None = None, mode: str = "auto") -> BaseWiFiHAL:
    """Factory — creates the best available WiFi HAL for the current system.

    Args:
        interface: WiFi interface name (auto-detected if None).
        mode: "auto" (best available), "monitor" (requires root),
              "scan" (no root needed), "mock" (testing).
    """
    if mode == "mock":
        return MockWiFiHAL()

    if mode == "scan":
        return ScanOnlyHAL(interface)

    if mode == "monitor":
        return LinuxWiFiHAL(interface)

    # Auto: try monitor, fall back to scan
    import os
    if os.geteuid() == 0:
        hal = LinuxWiFiHAL(interface)
        if hal._supports_monitor(hal._interface):
            return hal
    return ScanOnlyHAL(interface)
