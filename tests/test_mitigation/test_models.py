"""Tests for mitigation layer data models.

Validates creation, frozen behavior, extra="forbid", field constraints,
and StrEnum correctness for all mitigation models.
"""

from __future__ import annotations

from datetime import datetime

import pytest
from pydantic import ValidationError

from goop_veil.mitigation.models import (
    EvidencePackage,
    MitigationCategory,
    MitigationDifficulty,
    MitigationPlan,
    MitigationRecommendation,
    RouterStatus,
)
from goop_veil.models import ThreatLevel


# ---------------------------------------------------------------------------
# StrEnum tests
# ---------------------------------------------------------------------------


class TestMitigationCategory:
    """MitigationCategory StrEnum values."""

    def test_all_values(self):
        assert MitigationCategory.ROUTER_CONFIG == "router_config"
        assert MitigationCategory.TRAFFIC_ORCHESTRATION == "traffic_orchestration"
        assert MitigationCategory.BAND_MIGRATION == "band_migration"
        assert MitigationCategory.PMF_ENABLEMENT == "pmf_enablement"
        assert MitigationCategory.BEAMFORMING_CONTROL == "beamforming_control"
        assert MitigationCategory.LEGAL_ACTION == "legal_action"
        assert MitigationCategory.CHANNEL_MANAGEMENT == "channel_management"
        assert MitigationCategory.BEACON_MANAGEMENT == "beacon_management"

    def test_count(self):
        assert len(MitigationCategory) == 8


class TestMitigationDifficulty:
    """MitigationDifficulty StrEnum values."""

    def test_all_values(self):
        assert MitigationDifficulty.TRIVIAL == "trivial"
        assert MitigationDifficulty.EASY == "easy"
        assert MitigationDifficulty.MODERATE == "moderate"
        assert MitigationDifficulty.HARD == "hard"
        assert MitigationDifficulty.EXPERT == "expert"

    def test_count(self):
        assert len(MitigationDifficulty) == 5


# ---------------------------------------------------------------------------
# MitigationRecommendation tests
# ---------------------------------------------------------------------------


class TestMitigationRecommendation:
    """MitigationRecommendation creation and constraints."""

    def test_basic_creation(self):
        rec = MitigationRecommendation(
            category=MitigationCategory.ROUTER_CONFIG,
            title="Enable TX power variation",
            description="Vary TX power for privacy enhancement.",
            effectiveness_score=0.8,
            difficulty=MitigationDifficulty.MODERATE,
            estimated_time_minutes=5,
            priority=1,
        )
        assert rec.category == MitigationCategory.ROUTER_CONFIG
        assert rec.effectiveness_score == 0.8
        assert rec.auto_applicable is False
        assert rec.requires_router is False
        assert rec.wifi_impact == "none"

    def test_full_creation(self):
        rec = MitigationRecommendation(
            category=MitigationCategory.BAND_MIGRATION,
            title="Migrate to 5 GHz",
            description="Switch to higher band for wall attenuation.",
            effectiveness_score=0.85,
            difficulty=MitigationDifficulty.EASY,
            auto_applicable=True,
            requires_router=True,
            estimated_time_minutes=2,
            priority=1,
            wifi_impact="brief_drop",
        )
        assert rec.auto_applicable is True
        assert rec.requires_router is True
        assert rec.wifi_impact == "brief_drop"

    def test_frozen(self):
        rec = MitigationRecommendation(
            category=MitigationCategory.ROUTER_CONFIG,
            title="Test",
            description="Test",
            effectiveness_score=0.5,
            difficulty=MitigationDifficulty.EASY,
            estimated_time_minutes=1,
            priority=1,
        )
        with pytest.raises(ValidationError):
            rec.effectiveness_score = 0.9

    def test_extra_forbidden(self):
        with pytest.raises(ValidationError, match="extra"):
            MitigationRecommendation(
                category=MitigationCategory.ROUTER_CONFIG,
                title="Test",
                description="Test",
                effectiveness_score=0.5,
                difficulty=MitigationDifficulty.EASY,
                estimated_time_minutes=1,
                priority=1,
                unknown_field="bad",
            )

    def test_effectiveness_above_one(self):
        with pytest.raises(ValidationError):
            MitigationRecommendation(
                category=MitigationCategory.ROUTER_CONFIG,
                title="Test",
                description="Test",
                effectiveness_score=1.5,
                difficulty=MitigationDifficulty.EASY,
                estimated_time_minutes=1,
                priority=1,
            )

    def test_effectiveness_below_zero(self):
        with pytest.raises(ValidationError):
            MitigationRecommendation(
                category=MitigationCategory.ROUTER_CONFIG,
                title="Test",
                description="Test",
                effectiveness_score=-0.1,
                difficulty=MitigationDifficulty.EASY,
                estimated_time_minutes=1,
                priority=1,
            )

    def test_priority_must_be_positive(self):
        with pytest.raises(ValidationError):
            MitigationRecommendation(
                category=MitigationCategory.ROUTER_CONFIG,
                title="Test",
                description="Test",
                effectiveness_score=0.5,
                difficulty=MitigationDifficulty.EASY,
                estimated_time_minutes=1,
                priority=0,
            )


# ---------------------------------------------------------------------------
# MitigationPlan tests
# ---------------------------------------------------------------------------


class TestMitigationPlan:
    """MitigationPlan creation and constraints."""

    def test_minimal_creation(self):
        plan = MitigationPlan(
            detection_summary="No threats detected.",
            threat_level=ThreatLevel.NONE,
            estimated_effectiveness=0.0,
        )
        assert plan.recommendations == []
        assert plan.auto_applied == []
        assert plan.threat_level == ThreatLevel.NONE

    def test_frozen(self):
        plan = MitigationPlan(
            detection_summary="Test",
            threat_level=ThreatLevel.LOW,
            estimated_effectiveness=0.5,
        )
        with pytest.raises(ValidationError):
            plan.threat_level = ThreatLevel.HIGH

    def test_extra_forbidden(self):
        with pytest.raises(ValidationError, match="extra"):
            MitigationPlan(
                detection_summary="Test",
                threat_level=ThreatLevel.LOW,
                estimated_effectiveness=0.5,
                bogus=True,
            )

    def test_estimated_effectiveness_range(self):
        with pytest.raises(ValidationError):
            MitigationPlan(
                detection_summary="Test",
                threat_level=ThreatLevel.LOW,
                estimated_effectiveness=1.5,
            )


# ---------------------------------------------------------------------------
# RouterStatus tests
# ---------------------------------------------------------------------------


class TestRouterStatus:
    """RouterStatus creation and defaults."""

    def test_default_creation(self):
        status = RouterStatus()
        assert status.connected is False
        assert status.adapter_type == "none"
        assert status.current_channel is None
        assert status.current_bandwidth_mhz is None
        assert status.current_band is None
        assert status.pmf_enabled is None
        assert status.tx_power_dbm is None
        assert status.beamforming_enabled is None
        assert status.changes_applied == []

    def test_full_creation(self):
        status = RouterStatus(
            connected=True,
            adapter_type="mock",
            current_channel=6,
            current_bandwidth_mhz=40,
            current_band="5",
            pmf_enabled=True,
            tx_power_dbm=17.0,
            beamforming_enabled=False,
            changes_applied=["channel=6"],
        )
        assert status.connected is True
        assert status.current_channel == 6

    def test_frozen(self):
        status = RouterStatus(connected=True, adapter_type="mock")
        with pytest.raises(ValidationError):
            status.connected = False


# ---------------------------------------------------------------------------
# EvidencePackage tests
# ---------------------------------------------------------------------------


class TestEvidencePackage:
    """EvidencePackage creation and defaults."""

    def test_default_creation(self):
        pkg = EvidencePackage()
        assert pkg.detection_results == []
        assert pkg.device_fingerprints == []
        assert pkg.timeline == []
        assert pkg.output_path == ""
        assert pkg.report_hash == ""
        assert "automatically" in pkg.disclaimer

    def test_full_creation(self):
        pkg = EvidencePackage(
            timestamp=datetime(2026, 3, 8, 12, 0, 0),
            detection_results=[{"threat": "high"}],
            device_fingerprints=[{"mac": "aa:bb:cc:dd:ee:ff"}],
            timeline=[{"event": "detected", "time": "12:00"}],
            output_path="/tmp/evidence.json",
            report_hash="abc123",
            disclaimer="Custom disclaimer.",
        )
        assert len(pkg.detection_results) == 1
        assert pkg.report_hash == "abc123"

    def test_frozen(self):
        pkg = EvidencePackage()
        with pytest.raises(ValidationError):
            pkg.report_hash = "changed"
