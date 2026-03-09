"""Smart home device discovery and coordination for RF diversity.

Discovers existing IoT devices on the local network and coordinates them
to generate additional legitimate WiFi traffic, increasing RF diversity
that degrades CSI-based sensing quality.

Uses deferred imports for optional dependencies (zeroconf, pychromecast).
"""

from __future__ import annotations

import logging
import subprocess
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from goop_veil.config import TrafficConfig

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# SmartHomeDevice value object
# ---------------------------------------------------------------------------


class SmartHomeDevice:
    """A discovered smart home device on the local network."""

    __slots__ = ("name", "ip", "port", "device_type", "protocol", "mac")

    def __init__(
        self,
        name: str,
        ip: str,
        port: int,
        device_type: str,
        protocol: str,
        mac: str = "",
    ) -> None:
        self.name = name
        self.ip = ip
        self.port = port
        self.device_type = device_type
        self.protocol = protocol
        self.mac = mac

    def __repr__(self) -> str:
        return (
            f"SmartHomeDevice(name={self.name!r}, ip={self.ip!r}, "
            f"type={self.device_type!r}, protocol={self.protocol!r})"
        )


# ---------------------------------------------------------------------------
# SmartHomeCoordinator
# ---------------------------------------------------------------------------


class SmartHomeCoordinator:
    """Discovers and coordinates smart home devices for RF diversity.

    Discovery uses zeroconf (mDNS) if available, falling back to
    subprocess-based avahi-browse.  Device coordination triggers
    legitimate activity (media casts, API calls) to increase traffic
    diversity on the WiFi channel.
    """

    #: Known mDNS service types for discovery
    MDNS_SERVICES: list[str] = [
        "_googlecast._tcp.local.",
        "_roku._tcp.local.",
        "_hap._tcp.local.",
        "_http._tcp.local.",
    ]

    def __init__(self, config: TrafficConfig | None = None) -> None:
        if config is None:
            from goop_veil.config import TrafficConfig as _TC

            config = _TC()
        self._config = config
        self._devices: list[SmartHomeDevice] = []

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------

    def discover_devices(self) -> list[SmartHomeDevice]:
        """Discover smart home devices via mDNS/SSDP.

        Tries zeroconf first; falls back to avahi-browse subprocess.
        Returns the list of discovered devices.
        """
        devices: list[SmartHomeDevice] = []

        # Try zeroconf (deferred import)
        devices = self._discover_zeroconf()
        if devices:
            self._devices = devices
            return devices

        # Fallback: avahi-browse
        devices = self._discover_avahi()
        self._devices = devices
        return devices

    def _discover_zeroconf(self) -> list[SmartHomeDevice]:
        """Discover devices via zeroconf (python-zeroconf)."""
        try:
            from zeroconf import ServiceBrowser, Zeroconf  # deferred import

            devices: list[SmartHomeDevice] = []
            zc = Zeroconf()
            try:

                class _Listener:
                    def add_service(self, zc_inst: Zeroconf, type_: str, name: str) -> None:
                        info = zc_inst.get_service_info(type_, name)
                        if info and info.parsed_addresses():
                            device_type = "unknown"
                            if "googlecast" in type_:
                                device_type = "chromecast"
                            elif "roku" in type_:
                                device_type = "roku"
                            elif "hap" in type_:
                                device_type = "homekit"
                            devices.append(
                                SmartHomeDevice(
                                    name=info.name,
                                    ip=info.parsed_addresses()[0],
                                    port=info.port or 0,
                                    device_type=device_type,
                                    protocol="mdns",
                                )
                            )

                    def remove_service(self, zc_inst: Zeroconf, type_: str, name: str) -> None:
                        pass

                    def update_service(self, zc_inst: Zeroconf, type_: str, name: str) -> None:
                        pass

                listener = _Listener()
                browsers = [
                    ServiceBrowser(zc, svc, listener) for svc in self.MDNS_SERVICES
                ]
                # Brief scan window
                import time

                time.sleep(3.0)
                for b in browsers:
                    b.cancel()
            finally:
                zc.close()

            logger.info("Zeroconf discovery found %d devices", len(devices))
            return devices

        except ImportError:
            logger.debug("zeroconf not available, falling back to avahi-browse")
            return []

    def _discover_avahi(self) -> list[SmartHomeDevice]:
        """Discover devices via avahi-browse subprocess (Linux fallback)."""
        devices: list[SmartHomeDevice] = []
        try:
            result = subprocess.run(
                ["avahi-browse", "-t", "-r", "-p", "_http._tcp"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            for line in result.stdout.splitlines():
                parts = line.split(";")
                if len(parts) >= 8 and parts[0] == "=":
                    name = parts[3]
                    ip = parts[7]
                    port_str = parts[8] if len(parts) > 8 else "0"
                    try:
                        port = int(port_str)
                    except ValueError:
                        port = 0
                    devices.append(
                        SmartHomeDevice(
                            name=name,
                            ip=ip,
                            port=port,
                            device_type="unknown",
                            protocol="avahi",
                        )
                    )
        except FileNotFoundError:
            logger.debug("avahi-browse not found on this system")
        except subprocess.TimeoutExpired:
            logger.debug("avahi-browse timed out")
        except Exception:
            logger.exception("avahi-browse discovery failed")

        logger.info("Avahi discovery found %d devices", len(devices))
        return devices

    # ------------------------------------------------------------------
    # Activity triggering
    # ------------------------------------------------------------------

    def trigger_activity(self, device: SmartHomeDevice) -> bool:
        """Trigger legitimate activity on a discovered device.

        Supports Chromecast (via pychromecast), Roku (via ECP HTTP),
        and Home Assistant (via REST API).

        Returns True if activity was successfully triggered.
        """
        handler = {
            "chromecast": self._trigger_chromecast,
            "roku": self._trigger_roku,
            "homeassistant": self._trigger_homeassistant,
        }.get(device.device_type)

        if handler is None:
            logger.debug("No activity handler for device type: %s", device.device_type)
            return False

        return handler(device)

    def _trigger_chromecast(self, device: SmartHomeDevice) -> bool:
        """Trigger Chromecast activity via pychromecast."""
        try:
            import pychromecast  # deferred import

            chromecasts, browser = pychromecast.get_listed_chromecasts(
                friendly_names=[device.name]
            )
            if not chromecasts:
                logger.debug("Chromecast not found: %s", device.name)
                browser.stop_discovery()
                return False

            cast = chromecasts[0]
            cast.wait()
            mc = cast.media_controller
            # Play a short public-domain audio clip to generate traffic
            mc.play_media(
                "https://upload.wikimedia.org/wikipedia/commons/4/40/"
                "Toccata_and_Fugue_in_D_minor.ogg",
                "audio/ogg",
            )
            mc.block_until_active(timeout=10)
            browser.stop_discovery()
            logger.info("Triggered Chromecast activity: %s", device.name)
            return True
        except ImportError:
            logger.debug("pychromecast not available")
            return False
        except Exception:
            logger.exception("Chromecast trigger failed: %s", device.name)
            return False

    def _trigger_roku(self, device: SmartHomeDevice) -> bool:
        """Trigger Roku activity via ECP (External Control Protocol)."""
        try:
            import httpx  # deferred import

            # ECP endpoint for Roku device-info (generates traffic)
            url = f"http://{device.ip}:8060/query/device-info"
            resp = httpx.get(url, timeout=5.0)
            if resp.status_code == 200:
                logger.info("Triggered Roku activity: %s", device.name)
                return True
            return False
        except ImportError:
            logger.debug("httpx not available for Roku trigger")
            return False
        except Exception:
            logger.debug("Roku trigger failed: %s", device.name)
            return False

    def _trigger_homeassistant(self, device: SmartHomeDevice) -> bool:
        """Trigger Home Assistant activity via REST API."""
        try:
            import httpx  # deferred import

            url = f"http://{device.ip}:{device.port}/api/states"
            resp = httpx.get(url, timeout=5.0)
            if resp.status_code in (200, 401):
                # Even 401 means the device responded (traffic generated)
                logger.info("Triggered Home Assistant activity: %s", device.name)
                return True
            return False
        except ImportError:
            logger.debug("httpx not available for Home Assistant trigger")
            return False
        except Exception:
            logger.debug("Home Assistant trigger failed: %s", device.name)
            return False

    # ------------------------------------------------------------------
    # RF diversity scoring
    # ------------------------------------------------------------------

    def get_rf_diversity_score(self) -> float:
        """Estimate RF diversity based on active device count and distribution.

        Returns a score between 0.0 and 1.0, where:
        - 0.0 = no devices contributing to RF diversity
        - 1.0 = excellent diversity (many devices, varied types)
        """
        if not self._devices:
            return 0.0

        n_devices = len(self._devices)
        # Unique device types add more diversity
        unique_types = len({d.device_type for d in self._devices})
        # Unique IPs (different physical locations on the network)
        unique_ips = len({d.ip for d in self._devices})

        # Scoring formula:
        #   device_score: logarithmic scaling (diminishing returns after ~10 devices)
        #   type_bonus: +0.1 per unique device type (max 0.3)
        #   ip_bonus: +0.05 per unique IP (max 0.2)
        import math

        device_score = min(math.log2(n_devices + 1) / math.log2(11), 0.5)
        type_bonus = min(unique_types * 0.1, 0.3)
        ip_bonus = min(unique_ips * 0.05, 0.2)

        score = device_score + type_bonus + ip_bonus
        return min(max(score, 0.0), 1.0)
