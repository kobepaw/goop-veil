"""Alert engine — aggregates detection signals into threat assessments.

Combines outputs from beacon scanner, traffic analyzer, channel hop detector,
and CSI signature analyzer into unified DetectionResult and VeilAlert objects.
"""

from __future__ import annotations

import logging
from datetime import datetime

from goop_veil.config import DetectionConfig
from goop_veil.models import (
    AlertSeverity,
    BeaconAnomaly,
    CSISignature,
    DetectionResult,
    DeviceFingerprint,
    SensingCapability,
    ThreatLevel,
    VeilAlert,
)

logger = logging.getLogger(__name__)

#: Anomaly score weights for threat level calculation
ANOMALY_WEIGHTS: dict[str, float] = {
    "espressif_mesh": 0.8,
    "rapid_channel_hop": 0.9,
    "suspicious_ssid": 0.7,
    "hidden_ssid": 0.3,
    "espressif_device": 0.2,
}


class AlertEngine:
    """Aggregates detection signals into threat assessments and alerts."""

    def __init__(self, config: DetectionConfig | None = None) -> None:
        self._config = config or DetectionConfig()
        self._alerts: list[VeilAlert] = []

    @property
    def alerts(self) -> list[VeilAlert]:
        return list(self._alerts)

    def assess(
        self,
        devices: list[DeviceFingerprint] | None = None,
        beacon_anomalies: list[BeaconAnomaly] | None = None,
        csi_signatures: list[CSISignature] | None = None,
        traffic_indicators: list[str] | None = None,
        traffic_threat: ThreatLevel = ThreatLevel.NONE,
        channel_hop_anomalies: list[BeaconAnomaly] | None = None,
    ) -> DetectionResult:
        """Produce a unified detection result from all subsystem outputs."""
        devices = devices or []
        beacon_anomalies = beacon_anomalies or []
        csi_signatures = csi_signatures or []
        traffic_indicators = traffic_indicators or []
        channel_hop_anomalies = channel_hop_anomalies or []

        all_anomalies = beacon_anomalies + channel_hop_anomalies

        # Calculate composite threat score
        anomaly_score = self._calculate_anomaly_score(all_anomalies)
        traffic_score = self._threat_to_score(traffic_threat)
        csi_score = max((s.confidence for s in csi_signatures), default=0.0)

        # Weighted composite
        composite = 0.4 * anomaly_score + 0.3 * traffic_score + 0.3 * csi_score

        # Determine threat level
        threat_level = self._score_to_threat(composite)

        # Collect capabilities
        from goop_veil.detection.csi_signature import LABEL_TO_CAPABILITY

        capabilities: list[SensingCapability] = []
        for sig in csi_signatures:
            cap = LABEL_TO_CAPABILITY.get(sig.label)
            if cap and cap not in capabilities:
                capabilities.append(cap)

        # Check specific indicators
        espressif_mesh = any(a.anomaly_type == "espressif_mesh" for a in all_anomalies)
        channel_hop = any(a.anomaly_type == "rapid_channel_hop" for a in all_anomalies)

        # Build summary
        parts: list[str] = []
        if threat_level != ThreatLevel.NONE:
            parts.append(f"Threat level: {threat_level.value.upper()}")
        if espressif_mesh:
            esp_count = sum(1 for d in devices if d.is_espressif)
            parts.append(f"{esp_count} Espressif devices forming mesh")
        if channel_hop:
            parts.append("Rapid channel hopping detected")
        if capabilities:
            parts.append(f"Sensing capabilities: {', '.join(c.value for c in capabilities)}")
        if traffic_indicators:
            parts.append(f"Traffic indicators: {len(traffic_indicators)}")
        summary = "; ".join(parts) if parts else "No WiFi sensing detected"

        result = DetectionResult(
            timestamp=datetime.now(),
            threat_level=threat_level,
            detected_capabilities=capabilities,
            devices=devices,
            beacon_anomalies=all_anomalies,
            csi_signatures=csi_signatures,
            channel_hop_detected=channel_hop,
            espressif_mesh_detected=espressif_mesh,
            confidence=round(composite, 2),
            summary=summary,
        )

        # Generate alert if threat is significant
        if threat_level in (ThreatLevel.HIGH, ThreatLevel.CONFIRMED):
            self._emit_alert(result)

        return result

    def _calculate_anomaly_score(self, anomalies: list[BeaconAnomaly]) -> float:
        """Calculate weighted anomaly score from beacon anomalies."""
        if not anomalies:
            return 0.0
        weighted = sum(
            a.score * ANOMALY_WEIGHTS.get(a.anomaly_type, 0.5) for a in anomalies
        )
        # Normalize to [0, 1] — more anomalies = higher score
        return min(1.0, weighted / max(len(anomalies), 1))

    @staticmethod
    def _threat_to_score(level: ThreatLevel) -> float:
        return {
            ThreatLevel.NONE: 0.0,
            ThreatLevel.LOW: 0.25,
            ThreatLevel.MEDIUM: 0.50,
            ThreatLevel.HIGH: 0.75,
            ThreatLevel.CONFIRMED: 1.0,
        }[level]

    @staticmethod
    def _score_to_threat(score: float) -> ThreatLevel:
        if score >= 0.85:
            return ThreatLevel.CONFIRMED
        elif score >= 0.65:
            return ThreatLevel.HIGH
        elif score >= 0.40:
            return ThreatLevel.MEDIUM
        elif score >= 0.20:
            return ThreatLevel.LOW
        return ThreatLevel.NONE

    def _emit_alert(self, result: DetectionResult) -> None:
        severity = (
            AlertSeverity.CRITICAL
            if result.threat_level == ThreatLevel.CONFIRMED
            else AlertSeverity.WARNING
        )
        alert = VeilAlert(
            severity=severity,
            category="detection",
            title=f"WiFi sensing {result.threat_level.value}: {len(result.devices)} devices",
            description=result.summary,
            source="alert_engine",
            metadata={
                "threat_level": result.threat_level.value,
                "device_count": len(result.devices),
                "capability_count": len(result.detected_capabilities),
            },
        )
        self._alerts.append(alert)
        logger.warning("ALERT: %s — %s", alert.title, alert.description)

    def clear_alerts(self) -> None:
        self._alerts.clear()
