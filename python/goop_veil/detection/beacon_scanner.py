"""Beacon scanner — detects WiFi sensing mesh networks via beacon analysis.

Identifies Espressif ESP32 devices forming sensing meshes by analyzing:
- OUI prefixes (Espressif MAC ranges)
- Beacon intervals (sensing meshes use non-standard intervals)
- SSID patterns (hidden SSIDs, suspicious naming)
- Mesh topology (multiple coordinated Espressif devices)
"""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path

from goop_veil._core import classify_frames, is_espressif_oui, parse_pcap_bytes, parse_raw_frame
from goop_veil.config import DetectionConfig
from goop_veil.models import BeaconAnomaly, DeviceFingerprint

logger = logging.getLogger(__name__)

#: Standard beacon interval (ms) for most consumer APs
STANDARD_BEACON_INTERVAL_MS = 102.4

#: Known sensing mesh SSID patterns (case-insensitive)
SENSING_SSID_PATTERNS: tuple[str, ...] = (
    "ruview",
    "wifisense",
    "csi_mesh",
    "sensing",
    "espnow",
    "esp_mesh",
    "wifi_csi",
)


class BeaconScanner:
    """Scans for WiFi sensing mesh networks via beacon frame analysis."""

    def __init__(self, config: DetectionConfig | None = None) -> None:
        self._config = config or DetectionConfig()
        self._devices: dict[str, DeviceFingerprint] = {}

    @property
    def devices(self) -> dict[str, DeviceFingerprint]:
        """Currently tracked devices by MAC address."""
        return dict(self._devices)

    def scan_pcap(self, pcap_path: str | Path) -> list[BeaconAnomaly]:
        """Scan a pcap file for beacon anomalies.

        Uses Rust core for fast pcap parsing and frame classification.
        """
        pcap_data = Path(pcap_path).read_bytes()
        raw_frames = parse_pcap_bytes(pcap_data)

        anomalies: list[BeaconAnomaly] = []
        now = datetime.now()

        for timestamp_us, frame_bytes in raw_frames:
            try:
                frame = parse_raw_frame(frame_bytes)
            except (ValueError, Exception):
                continue

            if not frame.is_beacon:
                continue

            mac = frame.addr2 or "unknown"
            if mac == "unknown":
                continue

            # Update device fingerprint
            espressif = is_espressif_oui(mac)
            device = self._devices.get(mac)
            if device is None:
                from goop_veil._core import lookup_oui

                vendor = lookup_oui(mac)
                device = DeviceFingerprint(
                    mac_address=mac,
                    vendor=vendor,
                    is_espressif=espressif,
                    ssid=frame.ssid,
                    first_seen=now,
                    last_seen=now,
                    frame_count=1,
                )
            else:
                device = device.model_copy(
                    update={
                        "last_seen": now,
                        "frame_count": device.frame_count + 1,
                        "ssid": frame.ssid if frame.ssid else device.ssid,
                    }
                )
            self._devices[mac] = device

            # Check for anomalies
            anomalies.extend(self._check_beacon_anomalies(device, frame))

        # Check for mesh patterns (multiple coordinated Espressif devices)
        anomalies.extend(self._check_mesh_pattern())

        logger.info(
            "Beacon scan complete: %d frames, %d devices, %d anomalies",
            len(raw_frames),
            len(self._devices),
            len(anomalies),
        )
        return anomalies

    def scan_frames(self, frame_bytes_list: list[bytes]) -> list[BeaconAnomaly]:
        """Scan a list of raw frame bytes for beacon anomalies."""
        anomalies: list[BeaconAnomaly] = []
        now = datetime.now()

        for frame_bytes in frame_bytes_list:
            try:
                frame = parse_raw_frame(frame_bytes)
            except (ValueError, Exception):
                continue

            if not frame.is_beacon:
                continue

            mac = frame.addr2 or "unknown"
            if mac == "unknown":
                continue

            espressif = is_espressif_oui(mac)
            from goop_veil._core import lookup_oui

            vendor = lookup_oui(mac)
            device = DeviceFingerprint(
                mac_address=mac,
                vendor=vendor,
                is_espressif=espressif,
                ssid=frame.ssid,
                first_seen=now,
                last_seen=now,
                frame_count=1,
            )
            self._devices[mac] = device
            anomalies.extend(self._check_beacon_anomalies(device, frame))

        anomalies.extend(self._check_mesh_pattern())
        return anomalies

    def _check_beacon_anomalies(
        self, device: DeviceFingerprint, frame: object
    ) -> list[BeaconAnomaly]:
        """Check a single beacon frame for anomalies."""
        anomalies: list[BeaconAnomaly] = []

        # Anomaly: Espressif device (common sensing hardware)
        if device.is_espressif:
            anomalies.append(
                BeaconAnomaly(
                    device=device,
                    anomaly_type="espressif_device",
                    score=0.4,
                    description=f"Espressif device detected: {device.mac_address} ({device.vendor})",
                )
            )

        # Anomaly: Hidden SSID (common for sensing meshes)
        ssid = getattr(frame, "ssid", None)
        if ssid is not None and ssid == "":
            anomalies.append(
                BeaconAnomaly(
                    device=device,
                    anomaly_type="hidden_ssid",
                    score=0.3,
                    description=f"Hidden SSID on {device.mac_address}",
                )
            )

        # Anomaly: Suspicious SSID pattern
        if ssid and any(p in ssid.lower() for p in SENSING_SSID_PATTERNS):
            anomalies.append(
                BeaconAnomaly(
                    device=device,
                    anomaly_type="suspicious_ssid",
                    score=0.8,
                    description=f"Sensing-related SSID: '{ssid}' on {device.mac_address}",
                )
            )

        return anomalies

    def _check_mesh_pattern(self) -> list[BeaconAnomaly]:
        """Check if multiple Espressif devices form a sensing mesh."""
        espressif_devices = [d for d in self._devices.values() if d.is_espressif]

        if len(espressif_devices) >= self._config.espressif_device_threshold:
            # Multiple Espressif devices = potential sensing mesh
            score = min(1.0, 0.3 + 0.2 * len(espressif_devices))
            macs = [d.mac_address for d in espressif_devices]
            return [
                BeaconAnomaly(
                    device=espressif_devices[0],
                    anomaly_type="espressif_mesh",
                    score=score,
                    description=(
                        f"Potential sensing mesh: {len(espressif_devices)} "
                        f"Espressif devices detected: {', '.join(macs[:5])}"
                    ),
                )
            ]
        return []

    def reset(self) -> None:
        """Clear all tracked devices."""
        self._devices.clear()
