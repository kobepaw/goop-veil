"""MitigationAdvisor — combines detection results with strategies to produce ranked recommendations.

The advisor is the brain of the T5 mitigation layer. It takes a DetectionResult,
runs each WiFi privacy strategy, scores and ranks the recommendations, and
optionally auto-applies changes via a router adapter.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import TYPE_CHECKING

from goop_veil.mitigation.models import (
    MitigationCategory,
    MitigationDifficulty,
    MitigationPlan,
    MitigationRecommendation,
)
from goop_veil.mitigation.router.strategies import (
    BandSteeringStrategy,
    BandwidthStrategy,
    BeaconIntervalStrategy,
    BeamformingStrategy,
    ChannelStrategy,
    PMFStrategy,
    TxPowerStrategy,
)
from goop_veil.models import SensingCapability, ThreatLevel

if TYPE_CHECKING:
    from goop_veil.config import MitigationConfig
    from goop_veil.mitigation.models import RouterStatus
    from goop_veil.mitigation.router.base import BaseRouterAdapter
    from goop_veil.models import DetectionResult

logger = logging.getLogger(__name__)

# Effectiveness scores from empirical research
_EFFECTIVENESS = {
    "band_steering": 0.85,      # Doubles wall attenuation
    "tx_power_variation": 0.80,  # 93% misclassification (Wi-Spoof)
    "co_channel_traffic": 0.75,  # 47% detection rate (UChicago)
    "channel_hopping": 0.70,     # Breaks temporal coherence
    "bandwidth_widening": 0.65,  # Invalidates trained models
    "beamforming_disable": 0.60, # Eliminates BFI leak (LeakyBeam)
    "beacon_interval": 0.55,     # Reduces passive CSI samples
    "pmf_enablement": 0.40,      # Prevents forced disassociation
    "legal_action": 0.0,         # Remedy, not technical defense
}

# Difficulty-to-score mapping (higher = easier)
_DIFFICULTY_SCORE = {
    MitigationDifficulty.TRIVIAL: 1.0,
    MitigationDifficulty.EASY: 0.8,
    MitigationDifficulty.MODERATE: 0.5,
    MitigationDifficulty.HARD: 0.3,
    MitigationDifficulty.EXPERT: 0.1,
}

# Speed score: time_minutes -> score (lower time = higher score)
_MAX_TIME_MINUTES = 60.0


def _speed_score(time_minutes: int) -> float:
    """Convert estimated time to a 0-1 score (faster = higher)."""
    if time_minutes <= 0:
        return 1.0
    return max(0.0, 1.0 - time_minutes / _MAX_TIME_MINUTES)


def _rank_score(rec: MitigationRecommendation) -> float:
    """Compute composite ranking score for a recommendation.

    Score = 0.5*effectiveness + 0.2*ease + 0.2*speed + 0.1*auto_bonus
    """
    effectiveness = rec.effectiveness_score
    ease = _DIFFICULTY_SCORE.get(rec.difficulty, 0.5)
    speed = _speed_score(rec.estimated_time_minutes)
    auto_bonus = 1.0 if rec.auto_applicable else 0.0
    return 0.5 * effectiveness + 0.2 * ease + 0.2 * speed + 0.1 * auto_bonus


class MitigationAdvisor:
    """Combines detection results with WiFi strategies to produce ranked mitigation plans."""

    def __init__(
        self,
        config: MitigationConfig | None = None,
        router_adapter: BaseRouterAdapter | None = None,
    ) -> None:
        self._config = config
        self._router = router_adapter

        # Instantiate strategy objects
        self._channel_strategy = ChannelStrategy()
        self._bandwidth_strategy = BandwidthStrategy()
        self._tx_power_strategy = TxPowerStrategy()
        self._band_steering_strategy = BandSteeringStrategy()
        self._beacon_strategy = BeaconIntervalStrategy()
        self._pmf_strategy = PMFStrategy()
        self._beamforming_strategy = BeamformingStrategy()

    def _get_router_status(self) -> RouterStatus | None:
        """Get current router status if adapter is available."""
        if self._router is None:
            return None
        try:
            return self._router.get_status()
        except Exception:
            logger.warning("Failed to get router status", exc_info=True)
            return None

    def _build_recommendations(
        self,
        detection: DetectionResult,
        router_status: RouterStatus | None,
    ) -> list[MitigationRecommendation]:
        """Build all applicable recommendations from strategies."""
        recs: list[MitigationRecommendation] = []
        threat = detection.threat_level
        has_router = router_status is not None and router_status.connected

        # Determine attacker channels from device fingerprints
        attacker_channels: list[int] = []
        for dev in detection.devices:
            attacker_channels.extend(dev.channels_observed)

        # Determine detected capabilities for prioritization
        capabilities = set(detection.detected_capabilities)
        is_vitals_threat = bool(
            capabilities & {SensingCapability.BREATHING, SensingCapability.HEARTBEAT}
        )

        # --- Band steering (5 GHz) ---
        current_band = router_status.current_band if router_status else "2.4"
        recommended_band = self._band_steering_strategy.recommend(
            current_band or "2.4", 0, 0
        )
        if recommended_band != (current_band or "2.4"):
            recs.append(MitigationRecommendation(
                category=MitigationCategory.BAND_MIGRATION,
                title="Migrate to 5 GHz band",
                description=(
                    f"Switch from {current_band or '2.4'} GHz to {recommended_band} GHz. "
                    "Higher frequencies have ~2x wall attenuation, significantly "
                    "reducing signal leakage outside your premises."
                ),
                effectiveness_score=_EFFECTIVENESS["band_steering"],
                difficulty=MitigationDifficulty.EASY,
                auto_applicable=has_router,
                requires_router=True,
                estimated_time_minutes=2,
                priority=1,
                wifi_impact="brief_drop",
            ))

        # --- TX power variation ---
        current_power = router_status.tx_power_dbm if router_status and router_status.tx_power_dbm else 17.0
        min_power, max_power = self._tx_power_strategy.recommend(threat, current_power)
        recs.append(MitigationRecommendation(
            category=MitigationCategory.ROUTER_CONFIG,
            title="Enable TX power variation",
            description=(
                f"Vary transmission power between {min_power:.1f}–{max_power:.1f} dBm. "
                "Per Wi-Spoof research, TX power variation causes 93% misclassification "
                "in WiFi sensing models."
            ),
            effectiveness_score=_EFFECTIVENESS["tx_power_variation"],
            difficulty=MitigationDifficulty.MODERATE,
            auto_applicable=has_router,
            requires_router=True,
            estimated_time_minutes=1,
            priority=2 if is_vitals_threat else 3,
            wifi_impact="none",
        ))

        # --- Co-channel traffic / channel selection ---
        neighbor_aps = []
        if self._router and has_router:
            try:
                neighbor_aps = self._router.get_neighbor_aps()
            except Exception:
                pass
        recommended_channel = self._channel_strategy.recommend(
            attacker_channels or None, neighbor_aps or None
        )
        current_channel = router_status.current_channel if router_status else None
        if current_channel != recommended_channel:
            recs.append(MitigationRecommendation(
                category=MitigationCategory.CHANNEL_MANAGEMENT,
                title=f"Switch to channel {recommended_channel}",
                description=(
                    f"Move to channel {recommended_channel} to maximize co-channel "
                    "multipath complexity. Co-channel traffic reduces WiFi sensing "
                    "detection rates to ~47% per UChicago research."
                ),
                effectiveness_score=_EFFECTIVENESS["co_channel_traffic"],
                difficulty=MitigationDifficulty.EASY,
                auto_applicable=has_router,
                requires_router=True,
                estimated_time_minutes=1,
                priority=3,
                wifi_impact="brief_drop",
            ))

        # --- Bandwidth widening ---
        current_bw = router_status.current_bandwidth_mhz if router_status and router_status.current_bandwidth_mhz else 20
        band_for_bw = current_band or "2.4"
        recommended_bw = self._bandwidth_strategy.recommend(current_bw, band_for_bw)
        if recommended_bw > current_bw:
            recs.append(MitigationRecommendation(
                category=MitigationCategory.ROUTER_CONFIG,
                title=f"Widen bandwidth to {recommended_bw} MHz",
                description=(
                    f"Increase channel bandwidth from {current_bw} to {recommended_bw} MHz. "
                    "Wider bandwidth adds subcarrier diversity, invalidating attacker "
                    "models trained on narrower channel measurements."
                ),
                effectiveness_score=_EFFECTIVENESS["bandwidth_widening"],
                difficulty=MitigationDifficulty.EASY,
                auto_applicable=has_router,
                requires_router=True,
                estimated_time_minutes=2,
                priority=5,
                wifi_impact="brief_drop",
            ))

        # --- Beamforming control ---
        bf_keep = self._beamforming_strategy.recommend(threat)
        current_bf = router_status.beamforming_enabled if router_status else True
        if not bf_keep and current_bf:
            recs.append(MitigationRecommendation(
                category=MitigationCategory.BEAMFORMING_CONTROL,
                title="Disable beamforming",
                description=(
                    "Disable 802.11ac/ax beamforming to eliminate BFI (Beamforming "
                    "Feedback Information) plaintext leak. Per LeakyBeam (NDSS 2025), "
                    "BFI reveals spatial data even over encrypted connections."
                ),
                effectiveness_score=_EFFECTIVENESS["beamforming_disable"],
                difficulty=MitigationDifficulty.EASY,
                auto_applicable=has_router,
                requires_router=True,
                estimated_time_minutes=1,
                priority=4,
                wifi_impact="throughput_reduction",
            ))

        # --- Beacon interval increase ---
        current_beacon = 100  # Default; real adapters would report actual
        recommended_beacon = self._beacon_strategy.recommend(current_beacon)
        if recommended_beacon > current_beacon:
            recs.append(MitigationRecommendation(
                category=MitigationCategory.BEACON_MANAGEMENT,
                title=f"Increase beacon interval to {recommended_beacon} TU",
                description=(
                    f"Increase beacon interval from {current_beacon} to "
                    f"{recommended_beacon} TU. Each beacon frame is a free CSI sample; "
                    f"reducing beacon rate by {recommended_beacon // current_beacon}x "
                    "proportionally reduces passive collection rate."
                ),
                effectiveness_score=_EFFECTIVENESS["beacon_interval"],
                difficulty=MitigationDifficulty.MODERATE,
                auto_applicable=has_router,
                requires_router=True,
                estimated_time_minutes=1,
                priority=6,
                wifi_impact="none",
            ))

        # --- PMF enablement (always recommended) ---
        pmf_mode = self._pmf_strategy.recommend()
        pmf_enabled = router_status.pmf_enabled if router_status else False
        if not pmf_enabled:
            recs.append(MitigationRecommendation(
                category=MitigationCategory.PMF_ENABLEMENT,
                title=f"Enable 802.11w PMF ({pmf_mode})",
                description=(
                    "Enable Protected Management Frames to prevent forced "
                    "disassociation attacks. Attackers use deauth floods to force "
                    "client reconnections for CSI harvesting opportunities."
                ),
                effectiveness_score=_EFFECTIVENESS["pmf_enablement"],
                difficulty=MitigationDifficulty.EASY,
                auto_applicable=has_router,
                requires_router=True,
                estimated_time_minutes=1,
                priority=7,
                wifi_impact="none",
            ))

        # --- Legal action (always last) ---
        if threat in (ThreatLevel.HIGH, ThreatLevel.CONFIRMED):
            recs.append(MitigationRecommendation(
                category=MitigationCategory.LEGAL_ACTION,
                title="Document evidence for legal action",
                description=(
                    "Generate an evidence package with detection results, device "
                    "fingerprints, and timeline for potential legal proceedings. "
                    "Unauthorized WiFi sensing may violate federal wiretapping "
                    "laws (18 U.S.C. 2511) and state privacy statutes."
                ),
                effectiveness_score=_EFFECTIVENESS["legal_action"],
                difficulty=MitigationDifficulty.MODERATE,
                auto_applicable=False,
                requires_router=False,
                estimated_time_minutes=30,
                priority=99,
                wifi_impact="none",
            ))

        return recs

    def assess_and_recommend(
        self,
        detection_result: DetectionResult,
        home_network: dict | None = None,
    ) -> MitigationPlan:
        """Produce ranked mitigation recommendations based on detection results.

        Args:
            detection_result: T1 detection assessment.
            home_network: Optional dict with home network metadata.

        Returns:
            MitigationPlan with ranked recommendations.
        """
        router_status = self._get_router_status()
        recs = self._build_recommendations(detection_result, router_status)

        # Sort by composite ranking score (descending), but legal always last
        legal = [r for r in recs if r.category == MitigationCategory.LEGAL_ACTION]
        non_legal = [r for r in recs if r.category != MitigationCategory.LEGAL_ACTION]
        non_legal.sort(key=_rank_score, reverse=True)
        sorted_recs = non_legal + legal

        # Estimate overall effectiveness (weighted average of top-3 or all if fewer)
        top_n = sorted_recs[:3] if len(sorted_recs) >= 3 else sorted_recs
        if top_n:
            est_effectiveness = sum(r.effectiveness_score for r in top_n) / len(top_n)
        else:
            est_effectiveness = 0.0

        summary = self._build_summary(detection_result, sorted_recs)

        return MitigationPlan(
            timestamp=datetime.now(),
            detection_summary=detection_result.summary or f"Threat level: {detection_result.threat_level}",
            threat_level=detection_result.threat_level,
            recommendations=sorted_recs,
            auto_applied=[],
            estimated_effectiveness=round(est_effectiveness, 3),
            summary=summary,
        )

    def auto_apply(self, plan: MitigationPlan, dry_run: bool = True) -> list[str]:
        """Apply auto-applicable mitigations via the router adapter.

        Args:
            plan: MitigationPlan with recommendations.
            dry_run: If True (default), only log what would be applied.

        Returns:
            List of applied mitigation titles.
        """
        applied: list[str] = []

        if dry_run:
            logger.info("Dry run: no changes applied")
            return applied

        if self._router is None:
            logger.warning("No router adapter configured; cannot auto-apply")
            return applied

        for rec in plan.recommendations:
            if not rec.auto_applicable:
                continue

            try:
                success = self._apply_single(rec)
                if success:
                    applied.append(rec.title)
                    logger.info("Applied: %s", rec.title)
                else:
                    logger.warning("Failed to apply: %s", rec.title)
            except Exception:
                logger.warning("Error applying %s", rec.title, exc_info=True)

        return applied

    def _apply_single(self, rec: MitigationRecommendation) -> bool:
        """Apply a single recommendation via the router adapter."""
        if self._router is None:
            return False

        cat = rec.category

        if cat == MitigationCategory.BAND_MIGRATION:
            # Extract band from title/description
            for band in ("6", "5", "2.4"):
                if band in rec.title:
                    return self._router.set_band(band)  # type: ignore[arg-type]
            return self._router.set_band("5")

        if cat == MitigationCategory.CHANNEL_MANAGEMENT:
            # Extract channel from title
            parts = rec.title.split()
            for i, part in enumerate(parts):
                if part == "channel" and i + 1 < len(parts):
                    try:
                        ch = int(parts[i + 1])
                        return self._router.set_channel(ch)
                    except ValueError:
                        pass
            return False

        if cat == MitigationCategory.PMF_ENABLEMENT:
            if "required" in rec.title:
                return self._router.enable_pmf("required")
            return self._router.enable_pmf("optional")

        if cat == MitigationCategory.BEAMFORMING_CONTROL:
            return self._router.set_beamforming(enabled=False)

        if cat == MitigationCategory.BEACON_MANAGEMENT:
            # Extract interval from title
            parts = rec.title.split()
            for i, part in enumerate(parts):
                if part == "to" and i + 1 < len(parts):
                    try:
                        interval = int(parts[i + 1])
                        return self._router.set_beacon_interval(interval)
                    except ValueError:
                        pass
            return self._router.set_beacon_interval(500)

        if cat == MitigationCategory.ROUTER_CONFIG:
            # TX power or bandwidth changes
            if "bandwidth" in rec.title.lower():
                parts = rec.title.split()
                for i, part in enumerate(parts):
                    if part == "to" and i + 1 < len(parts):
                        try:
                            bw = int(parts[i + 1])
                            return self._router.set_bandwidth(bw)
                        except ValueError:
                            pass
            # TX power — set to max recommended
            if "power" in rec.title.lower():
                return self._router.set_tx_power(20.0)

        return False

    def _build_summary(
        self,
        detection: DetectionResult,
        recs: list[MitigationRecommendation],
    ) -> str:
        """Build a human-readable summary of the mitigation plan."""
        if not recs:
            return "No mitigations needed — no significant threats detected."

        tech_recs = [r for r in recs if r.category != MitigationCategory.LEGAL_ACTION]
        auto_count = sum(1 for r in tech_recs if r.auto_applicable)

        parts = [
            f"Generated {len(recs)} recommendation(s) for threat level "
            f"{detection.threat_level}.",
        ]
        if auto_count:
            parts.append(f"{auto_count} can be auto-applied via router adapter.")
        if tech_recs:
            top = tech_recs[0]
            parts.append(
                f"Top recommendation: {top.title} "
                f"(effectiveness: {top.effectiveness_score:.0%})."
            )
        return " ".join(parts)
