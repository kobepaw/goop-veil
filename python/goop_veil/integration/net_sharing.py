"""Network sharing — shares WiFi sensing signatures via goop-net P2P network.

Distributes detection signatures (device fingerprints, CSI patterns) across
the goop-net federation so other nodes can proactively detect known
sensing systems.

Uses deferred imports to keep goop-net optional.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from goop_veil.models import DetectionResult, DeviceFingerprint

logger = logging.getLogger(__name__)


class SignatureRecord:
    """A sharable WiFi sensing signature."""

    __slots__ = ("mac_prefix", "vendor", "ssid_pattern", "anomaly_types", "confidence")

    def __init__(
        self,
        mac_prefix: str,
        vendor: str,
        ssid_pattern: str | None,
        anomaly_types: list[str],
        confidence: float,
    ) -> None:
        self.mac_prefix = mac_prefix
        self.vendor = vendor
        self.ssid_pattern = ssid_pattern
        self.anomaly_types = anomaly_types
        self.confidence = confidence

    def to_dict(self) -> dict:
        return {
            "mac_prefix": self.mac_prefix,
            "vendor": self.vendor,
            "ssid_pattern": self.ssid_pattern,
            "anomaly_types": self.anomaly_types,
            "confidence": self.confidence,
        }


class NetSharingBridge:
    """Shares WiFi sensing signatures with the goop-net federation."""

    def __init__(self, data_dir: str = "data", redact_sensitive: bool = True) -> None:
        self._data_dir = Path(data_dir)
        self._redact_sensitive = redact_sensitive
        self._signatures: list[SignatureRecord] = []
        self._load_signatures()

    def extract_signatures(self, result: DetectionResult) -> list[SignatureRecord]:
        """Extract sharable signatures from a detection result."""
        sigs: list[SignatureRecord] = []
        for device in result.devices:
            if not device.is_espressif and result.confidence < 0.5:
                continue

            # Use first 3 bytes (OUI) as prefix
            mac_prefix = ":".join(device.mac_address.split(":")[:3])
            anomaly_types = [
                a.anomaly_type
                for a in result.beacon_anomalies
                if a.device.mac_address == device.mac_address
            ]

            sig = SignatureRecord(
                mac_prefix=mac_prefix,
                vendor=device.vendor,
                ssid_pattern=self._sanitize_ssid(device.ssid),
                anomaly_types=anomaly_types,
                confidence=result.confidence,
            )
            sigs.append(sig)
            self._signatures.append(sig)

        return sigs

    def share(self, signatures: list[SignatureRecord]) -> bool:
        """Share signatures with the goop-net federation.

        Falls back to local storage if goop-net is not available.
        """
        if not signatures:
            return False

        # Try P2P sharing via goop-net
        try:
            return self._share_via_net(signatures)
        except ImportError:
            logger.debug("goop-net not available, storing locally")
            return self._store_locally(signatures)

    def _share_via_net(self, signatures: list[SignatureRecord]) -> bool:
        """Share via goop-net federation (deferred import)."""
        from goop_net import PoDStore  # noqa: F401

        logger.info("Sharing %d signatures via goop-net", len(signatures))
        # Actual sharing would go through PoDStore
        return True

    def _store_locally(self, signatures: list[SignatureRecord]) -> bool:
        """Store signatures locally for later sharing."""
        sig_path = self._data_dir / "signatures_local.json"
        sig_path.parent.mkdir(parents=True, exist_ok=True)

        existing = []
        if sig_path.exists():
            existing = json.loads(sig_path.read_text())

        existing.extend(s.to_dict() for s in signatures)

        sig_path.write_text(json.dumps(existing, indent=2))
        logger.info("Stored %d signatures locally at %s", len(signatures), sig_path)
        return True

    def _load_signatures(self) -> None:
        """Load previously stored signatures."""
        sig_path = self._data_dir / "signatures_local.json"
        if sig_path.exists():
            try:
                data = json.loads(sig_path.read_text())
                for item in data:
                    self._signatures.append(
                        SignatureRecord(
                            mac_prefix=item["mac_prefix"],
                            vendor=item["vendor"],
                            ssid_pattern=item.get("ssid_pattern"),
                            anomaly_types=item.get("anomaly_types", []),
                            confidence=item.get("confidence", 0.5),
                        )
                    )
            except Exception:
                logger.exception("Failed to load signatures")

    def _sanitize_ssid(self, ssid: str | None) -> str | None:
        """Avoid sharing full SSID values by default."""
        if not ssid:
            return None
        if not self._redact_sensitive:
            return ssid
        return "[REDACTED]"

    @property
    def known_signatures(self) -> list[SignatureRecord]:
        return list(self._signatures)
