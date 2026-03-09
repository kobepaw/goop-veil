"""Tests for goop-veil data models.

Validates creation, frozen behavior, field constraints, and enum correctness
for all detection, passive defense, active defense, and alert models.
"""

from __future__ import annotations

from datetime import datetime

import pytest
from pydantic import ValidationError

from goop_veil.models import (
    ActiveDefenseStatus,
    AlertSeverity,
    BeaconAnomaly,
    CSISignature,
    DefenseMode,
    DetectionResult,
    DeviceFingerprint,
    MaterialRecommendation,
    RoomAssessment,
    SensingCapability,
    ThreatLevel,
    VeilAlert,
)


# ---------------------------------------------------------------------------
# Enum tests
# ---------------------------------------------------------------------------


class TestEnums:
    """StrEnum values and membership."""

    def test_threat_level_values(self):
        assert ThreatLevel.NONE == "none"
        assert ThreatLevel.LOW == "low"
        assert ThreatLevel.MEDIUM == "medium"
        assert ThreatLevel.HIGH == "high"
        assert ThreatLevel.CONFIRMED == "confirmed"

    def test_threat_level_count(self):
        assert len(ThreatLevel) == 5

    def test_sensing_capability_values(self):
        assert SensingCapability.PRESENCE == "presence"
        assert SensingCapability.MOTION == "motion"
        assert SensingCapability.BREATHING == "breathing"
        assert SensingCapability.HEARTBEAT == "heartbeat"
        assert SensingCapability.POSE == "pose"
        assert SensingCapability.GESTURE == "gesture"

    def test_sensing_capability_count(self):
        assert len(SensingCapability) == 6

    def test_alert_severity_values(self):
        assert AlertSeverity.INFO == "info"
        assert AlertSeverity.WARNING == "warning"
        assert AlertSeverity.CRITICAL == "critical"

    def test_defense_mode_values(self):
        assert DefenseMode.VITALS_PRIVACY == "vitals_privacy"
        assert DefenseMode.MOTION_PRIVACY == "motion_privacy"
        assert DefenseMode.FULL_PRIVACY == "full_privacy"


# ---------------------------------------------------------------------------
# Detection model tests (T1)
# ---------------------------------------------------------------------------


class TestDeviceFingerprint:
    """DeviceFingerprint creation and constraints."""

    def test_basic_creation(self):
        fp = DeviceFingerprint(mac_address="aa:bb:cc:dd:ee:ff")
        assert fp.mac_address == "aa:bb:cc:dd:ee:ff"
        assert fp.vendor == "Unknown"
        assert fp.is_espressif is False
        assert fp.frame_count == 0

    def test_full_creation(self):
        now = datetime.now()
        fp = DeviceFingerprint(
            mac_address="24:0a:c4:00:11:22",
            vendor="Espressif",
            is_espressif=True,
            ssid="TestMesh",
            channels_observed=[1, 6, 11],
            first_seen=now,
            last_seen=now,
            frame_count=42,
        )
        assert fp.is_espressif is True
        assert fp.ssid == "TestMesh"
        assert fp.channels_observed == [1, 6, 11]
        assert fp.frame_count == 42

    def test_frozen(self):
        fp = DeviceFingerprint(mac_address="aa:bb:cc:dd:ee:ff")
        with pytest.raises(ValidationError):
            fp.mac_address = "11:22:33:44:55:66"


class TestBeaconAnomaly:
    """BeaconAnomaly creation and score constraints."""

    def test_creation(self):
        device = DeviceFingerprint(mac_address="aa:bb:cc:dd:ee:ff")
        anomaly = BeaconAnomaly(
            device=device,
            anomaly_type="espressif_device",
            score=0.4,
            description="Test anomaly",
        )
        assert anomaly.score == 0.4
        assert anomaly.anomaly_type == "espressif_device"

    def test_score_out_of_range(self):
        device = DeviceFingerprint(mac_address="aa:bb:cc:dd:ee:ff")
        with pytest.raises(ValidationError):
            BeaconAnomaly(device=device, anomaly_type="bad", score=1.5)


class TestCSISignature:
    """CSISignature creation and confidence constraints."""

    def test_creation(self):
        sig = CSISignature(
            frequency_hz=0.25,
            magnitude=0.5,
            label="breathing",
            snr_db=15.0,
            confidence=0.85,
        )
        assert sig.label == "breathing"
        assert sig.confidence == 0.85

    def test_confidence_out_of_range(self):
        with pytest.raises(ValidationError):
            CSISignature(
                frequency_hz=0.25,
                magnitude=0.5,
                label="breathing",
                snr_db=15.0,
                confidence=1.5,
            )


class TestDetectionResult:
    """DetectionResult creation and defaults."""

    def test_default_creation(self):
        result = DetectionResult()
        assert result.threat_level == ThreatLevel.NONE
        assert result.detected_capabilities == []
        assert result.devices == []
        assert result.channel_hop_detected is False
        assert result.espressif_mesh_detected is False

    def test_frozen(self):
        result = DetectionResult()
        with pytest.raises(ValidationError):
            result.threat_level = ThreatLevel.HIGH


# ---------------------------------------------------------------------------
# Passive defense model tests (T2)
# ---------------------------------------------------------------------------


class TestMaterialRecommendation:
    """MaterialRecommendation creation."""

    def test_creation(self):
        rec = MaterialRecommendation(
            material="Aluminum Foil",
            thickness_m=0.00002,
            area_m2=30.0,
            attenuation_db=0.8,
            cost_usd=15.0,
            location="wall_interior",
            priority=1,
        )
        assert rec.material == "Aluminum Foil"
        assert rec.priority == 1

    def test_priority_must_be_positive(self):
        with pytest.raises(ValidationError):
            MaterialRecommendation(
                material="test",
                thickness_m=0.01,
                area_m2=10.0,
                attenuation_db=1.0,
                cost_usd=10.0,
                location="wall",
                priority=0,
            )


class TestRoomAssessment:
    """RoomAssessment creation."""

    def test_creation(self):
        assessment = RoomAssessment(
            room_dimensions_m=(4.5, 3.5, 2.7),
            frequency_mhz=2437.0,
            vulnerability_score=0.5,
        )
        assert assessment.room_dimensions_m == (4.5, 3.5, 2.7)
        assert assessment.estimated_cost_usd == 0.0


# ---------------------------------------------------------------------------
# Active defense model tests (T3)
# ---------------------------------------------------------------------------


class TestActiveDefenseStatus:
    """ActiveDefenseStatus creation."""

    def test_creation(self):
        status = ActiveDefenseStatus(
            mode=DefenseMode.VITALS_PRIVACY,
            power_dbm=15.0,
            channel=6,
            utilization_pct=3.2,
        )
        assert status.mode == DefenseMode.VITALS_PRIVACY
        assert status.compliant is True
        assert status.frames_transmitted == 0

    def test_frozen(self):
        status = ActiveDefenseStatus(
            mode=DefenseMode.FULL_PRIVACY,
            power_dbm=18.0,
            channel=1,
            utilization_pct=5.0,
        )
        with pytest.raises(ValidationError):
            status.power_dbm = 20.0


# ---------------------------------------------------------------------------
# Alert model tests
# ---------------------------------------------------------------------------


class TestVeilAlert:
    """VeilAlert creation."""

    def test_creation(self):
        alert = VeilAlert(
            severity=AlertSeverity.WARNING,
            category="detection",
            title="Test alert",
            description="Test description",
        )
        assert alert.severity == AlertSeverity.WARNING
        assert alert.category == "detection"
        assert alert.source == ""
        assert alert.metadata == {}

    def test_with_metadata(self):
        alert = VeilAlert(
            severity=AlertSeverity.CRITICAL,
            category="compliance",
            title="Power violation",
            description="Exceeded limit",
            source="compliance_monitor",
            metadata={"rule": "max_power", "measured": 22.0},
        )
        assert alert.metadata["rule"] == "max_power"
        assert alert.source == "compliance_monitor"

    def test_frozen(self):
        alert = VeilAlert(
            severity=AlertSeverity.INFO,
            category="test",
            title="t",
            description="d",
        )
        with pytest.raises(ValidationError):
            alert.severity = AlertSeverity.CRITICAL
