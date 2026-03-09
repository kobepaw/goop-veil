"""Tests for MitigationAdvisor — the brain of the T5 mitigation layer.

Validates recommendation generation, ranking, auto-apply logic,
and interaction with router adapters.
"""

from __future__ import annotations

import pytest

from goop_veil.config import MitigationConfig, RouterConfig
from goop_veil.mitigation.advisor import MitigationAdvisor, _rank_score
from goop_veil.mitigation.models import (
    MitigationCategory,
    MitigationPlan,
    MitigationRecommendation,
)
from goop_veil.mitigation.router.mock import MockRouterAdapter
from goop_veil.models import (
    DetectionResult,
    DeviceFingerprint,
    SensingCapability,
    ThreatLevel,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_detection(
    threat_level: ThreatLevel = ThreatLevel.NONE,
    capabilities: list[SensingCapability] | None = None,
    devices: list[DeviceFingerprint] | None = None,
    summary: str = "",
) -> DetectionResult:
    """Helper to build DetectionResult for tests."""
    return DetectionResult(
        threat_level=threat_level,
        detected_capabilities=capabilities or [],
        devices=devices or [],
        summary=summary,
    )


def _make_advisor_with_mock() -> tuple[MitigationAdvisor, MockRouterAdapter]:
    """Create an advisor with a connected mock router adapter."""
    router = MockRouterAdapter()
    router.connect()
    advisor = MitigationAdvisor(router_adapter=router)
    return advisor, router


# ---------------------------------------------------------------------------
# No-detection / minimal tests
# ---------------------------------------------------------------------------


class TestMinimalDetection:
    """Advisor with no significant threats."""

    def test_no_detection_produces_plan(self):
        advisor = MitigationAdvisor()
        detection = _make_detection(ThreatLevel.NONE)
        plan = advisor.assess_and_recommend(detection)
        assert isinstance(plan, MitigationPlan)
        assert plan.threat_level == ThreatLevel.NONE

    def test_no_detection_still_has_recommendations(self):
        """Even with NONE threat, basic hygiene recommendations appear."""
        advisor = MitigationAdvisor()
        detection = _make_detection(ThreatLevel.NONE)
        plan = advisor.assess_and_recommend(detection)
        # At minimum: TX power, PMF, beacon, bandwidth (depending on router status)
        assert len(plan.recommendations) >= 1

    def test_no_router_recommendations_not_auto_applicable(self):
        """Without router adapter, nothing is auto-applicable."""
        advisor = MitigationAdvisor()
        detection = _make_detection(ThreatLevel.HIGH)
        plan = advisor.assess_and_recommend(detection)
        for rec in plan.recommendations:
            if rec.requires_router:
                assert rec.auto_applicable is False


# ---------------------------------------------------------------------------
# HIGH threat tests
# ---------------------------------------------------------------------------


class TestHighThreat:
    """Advisor with HIGH threat level."""

    def test_high_threat_many_recommendations(self):
        advisor, _ = _make_advisor_with_mock()
        detection = _make_detection(ThreatLevel.HIGH)
        plan = advisor.assess_and_recommend(detection)
        # Should have multiple recommendations
        assert len(plan.recommendations) >= 5

    def test_high_threat_includes_legal(self):
        advisor, _ = _make_advisor_with_mock()
        detection = _make_detection(ThreatLevel.HIGH)
        plan = advisor.assess_and_recommend(detection)
        categories = [r.category for r in plan.recommendations]
        assert MitigationCategory.LEGAL_ACTION in categories

    def test_confirmed_threat_includes_legal(self):
        advisor, _ = _make_advisor_with_mock()
        detection = _make_detection(ThreatLevel.CONFIRMED)
        plan = advisor.assess_and_recommend(detection)
        categories = [r.category for r in plan.recommendations]
        assert MitigationCategory.LEGAL_ACTION in categories

    def test_low_threat_no_legal(self):
        advisor, _ = _make_advisor_with_mock()
        detection = _make_detection(ThreatLevel.LOW)
        plan = advisor.assess_and_recommend(detection)
        categories = [r.category for r in plan.recommendations]
        assert MitigationCategory.LEGAL_ACTION not in categories


# ---------------------------------------------------------------------------
# PMF always recommended
# ---------------------------------------------------------------------------


class TestPMFRecommendation:
    """PMF should always be recommended when not enabled."""

    def test_pmf_in_recommendations(self):
        advisor, _ = _make_advisor_with_mock()
        detection = _make_detection(ThreatLevel.MEDIUM)
        plan = advisor.assess_and_recommend(detection)
        categories = [r.category for r in plan.recommendations]
        assert MitigationCategory.PMF_ENABLEMENT in categories

    def test_pmf_recommended_even_for_low(self):
        advisor, _ = _make_advisor_with_mock()
        detection = _make_detection(ThreatLevel.LOW)
        plan = advisor.assess_and_recommend(detection)
        categories = [r.category for r in plan.recommendations]
        assert MitigationCategory.PMF_ENABLEMENT in categories


# ---------------------------------------------------------------------------
# Priority / presence-vs-vitals tests
# ---------------------------------------------------------------------------


class TestThreatSpecificPrioritization:
    """Different threat types should prioritize different mitigations."""

    def test_band_steering_present_for_presence_threats(self):
        advisor, router = _make_advisor_with_mock()
        # Mock router on 2.4 GHz
        router._band = "2.4"
        detection = _make_detection(
            ThreatLevel.HIGH,
            capabilities=[SensingCapability.PRESENCE],
        )
        plan = advisor.assess_and_recommend(detection)
        categories = [r.category for r in plan.recommendations]
        assert MitigationCategory.BAND_MIGRATION in categories

    def test_tx_power_prioritized_for_vitals(self):
        advisor, _ = _make_advisor_with_mock()
        detection = _make_detection(
            ThreatLevel.HIGH,
            capabilities=[SensingCapability.BREATHING, SensingCapability.HEARTBEAT],
        )
        plan = advisor.assess_and_recommend(detection)
        # TX power should have priority 2 for vitals threats
        tx_recs = [
            r for r in plan.recommendations
            if "power" in r.title.lower()
        ]
        assert len(tx_recs) >= 1
        assert tx_recs[0].priority == 2

    def test_tx_power_lower_priority_without_vitals(self):
        advisor, _ = _make_advisor_with_mock()
        detection = _make_detection(
            ThreatLevel.HIGH,
            capabilities=[SensingCapability.PRESENCE],
        )
        plan = advisor.assess_and_recommend(detection)
        tx_recs = [
            r for r in plan.recommendations
            if "power" in r.title.lower()
        ]
        assert len(tx_recs) >= 1
        assert tx_recs[0].priority == 3


# ---------------------------------------------------------------------------
# Ranking order
# ---------------------------------------------------------------------------


class TestRankingOrder:
    """Recommendations should be ranked by composite score."""

    def test_legal_action_always_last(self):
        advisor, _ = _make_advisor_with_mock()
        detection = _make_detection(ThreatLevel.HIGH)
        plan = advisor.assess_and_recommend(detection)
        if plan.recommendations:
            last = plan.recommendations[-1]
            assert last.category == MitigationCategory.LEGAL_ACTION

    def test_ranking_scores_descending(self):
        """Non-legal recommendations should be in descending rank score."""
        advisor, _ = _make_advisor_with_mock()
        detection = _make_detection(ThreatLevel.HIGH)
        plan = advisor.assess_and_recommend(detection)
        non_legal = [
            r for r in plan.recommendations
            if r.category != MitigationCategory.LEGAL_ACTION
        ]
        scores = [_rank_score(r) for r in non_legal]
        for i in range(len(scores) - 1):
            assert scores[i] >= scores[i + 1], (
                f"Score at index {i} ({scores[i]:.3f}) < score at index {i+1} ({scores[i+1]:.3f})"
            )


# ---------------------------------------------------------------------------
# Auto-apply tests
# ---------------------------------------------------------------------------


class TestAutoApply:
    """Auto-apply logic with dry-run and mock router."""

    def test_dry_run_applies_nothing(self):
        advisor, router = _make_advisor_with_mock()
        detection = _make_detection(ThreatLevel.HIGH)
        plan = advisor.assess_and_recommend(detection)
        applied = advisor.auto_apply(plan, dry_run=True)
        assert applied == []

    def test_auto_apply_with_mock_router(self):
        advisor, router = _make_advisor_with_mock()
        detection = _make_detection(ThreatLevel.HIGH)
        plan = advisor.assess_and_recommend(detection)
        applied = advisor.auto_apply(plan, dry_run=False)
        # Should have applied at least some auto-applicable mitigations
        assert len(applied) >= 1

    def test_auto_apply_records_commands(self):
        advisor, router = _make_advisor_with_mock()
        detection = _make_detection(ThreatLevel.HIGH)
        plan = advisor.assess_and_recommend(detection)
        advisor.auto_apply(plan, dry_run=False)
        # Mock router should have recorded commands beyond the initial
        # connect + get_status + get_neighbor_aps
        assert len(router.commands) > 3

    def test_auto_apply_without_router_returns_empty(self):
        advisor = MitigationAdvisor()
        detection = _make_detection(ThreatLevel.HIGH)
        plan = advisor.assess_and_recommend(detection)
        applied = advisor.auto_apply(plan, dry_run=False)
        assert applied == []

    def test_legal_not_auto_applied(self):
        advisor, router = _make_advisor_with_mock()
        detection = _make_detection(ThreatLevel.CONFIRMED)
        plan = advisor.assess_and_recommend(detection)
        applied = advisor.auto_apply(plan, dry_run=False)
        # Legal action should never be auto-applied
        for title in applied:
            assert "legal" not in title.lower()


# ---------------------------------------------------------------------------
# No router adapter tests
# ---------------------------------------------------------------------------


class TestNoRouterAdapter:
    """Recommendations still generated without router adapter."""

    def test_recommendations_without_router(self):
        advisor = MitigationAdvisor()
        detection = _make_detection(ThreatLevel.HIGH)
        plan = advisor.assess_and_recommend(detection)
        assert len(plan.recommendations) >= 1

    def test_summary_present(self):
        advisor = MitigationAdvisor()
        detection = _make_detection(ThreatLevel.HIGH)
        plan = advisor.assess_and_recommend(detection)
        assert plan.summary != ""

    def test_estimated_effectiveness_in_range(self):
        advisor = MitigationAdvisor()
        detection = _make_detection(ThreatLevel.HIGH)
        plan = advisor.assess_and_recommend(detection)
        assert 0.0 <= plan.estimated_effectiveness <= 1.0


# ---------------------------------------------------------------------------
# Attacker channel detection
# ---------------------------------------------------------------------------


class TestAttackerChannelDetection:
    """Advisor uses device fingerprint channels for strategy input."""

    def test_attacker_channels_used(self):
        advisor, router = _make_advisor_with_mock()
        # Set current channel to something different from attacker
        router._channel = 1
        device = DeviceFingerprint(
            mac_address="aa:bb:cc:dd:ee:ff",
            channels_observed=[11],
        )
        detection = _make_detection(
            ThreatLevel.HIGH,
            devices=[device],
        )
        plan = advisor.assess_and_recommend(detection)
        # Should recommend channel 11 (attacker's channel)
        channel_recs = [
            r for r in plan.recommendations
            if r.category == MitigationCategory.CHANNEL_MANAGEMENT
        ]
        assert len(channel_recs) >= 1
        assert "11" in channel_recs[0].title


# ---------------------------------------------------------------------------
# Beamforming disabled under threat
# ---------------------------------------------------------------------------


class TestBeamformingRecommendation:
    """Beamforming disable recommended under threat."""

    def test_beamforming_disabled_high_threat(self):
        advisor, router = _make_advisor_with_mock()
        router._beamforming = True
        detection = _make_detection(ThreatLevel.HIGH)
        plan = advisor.assess_and_recommend(detection)
        bf_recs = [
            r for r in plan.recommendations
            if r.category == MitigationCategory.BEAMFORMING_CONTROL
        ]
        assert len(bf_recs) >= 1
        assert "disable" in bf_recs[0].title.lower() or "Disable" in bf_recs[0].title
