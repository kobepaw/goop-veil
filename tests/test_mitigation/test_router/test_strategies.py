"""Tests for WiFi privacy mitigation strategies.

Validates that each strategy produces correct recommendations based on
threat level, current configuration, and WiFi physical-layer properties.
"""

from __future__ import annotations

import pytest

from goop_veil.mitigation.router.strategies import (
    BandSteeringStrategy,
    BandwidthStrategy,
    BeaconIntervalStrategy,
    BeamformingStrategy,
    ChannelStrategy,
    PMFStrategy,
    TxPowerStrategy,
)
from goop_veil.models import ThreatLevel


# ---------------------------------------------------------------------------
# ChannelStrategy
# ---------------------------------------------------------------------------


class TestChannelStrategy:
    """ChannelStrategy recommends channel for co-channel multipath complexity."""

    def test_co_locates_with_attacker_channel(self):
        strategy = ChannelStrategy()
        result = strategy.recommend(attacker_channels=[11])
        assert result == 11

    def test_co_locates_with_most_common_attacker_channel(self):
        strategy = ChannelStrategy()
        result = strategy.recommend(attacker_channels=[1, 6, 6, 11])
        assert result == 6

    def test_without_attacker_recommends_congested_channel(self):
        strategy = ChannelStrategy()
        neighbors = [
            {"channel": 1},
            {"channel": 6},
            {"channel": 6},
            {"channel": 6},
            {"channel": 11},
        ]
        result = strategy.recommend(attacker_channels=None, neighbor_aps=neighbors)
        assert result == 6

    def test_no_info_defaults_to_channel_6(self):
        strategy = ChannelStrategy()
        result = strategy.recommend(attacker_channels=None, neighbor_aps=None)
        assert result == 6

    def test_empty_attacker_list_falls_through(self):
        strategy = ChannelStrategy()
        result = strategy.recommend(attacker_channels=[], neighbor_aps=None)
        assert result == 6

    def test_empty_neighbor_list_defaults(self):
        strategy = ChannelStrategy()
        result = strategy.recommend(attacker_channels=None, neighbor_aps=[])
        assert result == 6


# ---------------------------------------------------------------------------
# BandwidthStrategy
# ---------------------------------------------------------------------------


class TestBandwidthStrategy:
    """BandwidthStrategy recommends wider bandwidth."""

    def test_recommends_wider_24ghz(self):
        strategy = BandwidthStrategy()
        result = strategy.recommend(current_bw=20, band="2.4")
        assert result == 40

    def test_recommends_wider_5ghz(self):
        strategy = BandwidthStrategy()
        result = strategy.recommend(current_bw=40, band="5")
        assert result == 160

    def test_already_at_max_stays(self):
        strategy = BandwidthStrategy()
        result = strategy.recommend(current_bw=160, band="5")
        assert result == 160

    def test_6ghz_max_bandwidth(self):
        strategy = BandwidthStrategy()
        result = strategy.recommend(current_bw=80, band="6")
        assert result == 320


# ---------------------------------------------------------------------------
# TxPowerStrategy
# ---------------------------------------------------------------------------


class TestTxPowerStrategy:
    """TxPowerStrategy recommends power variation within FCC limits."""

    def test_high_threat_wide_variation(self):
        strategy = TxPowerStrategy()
        min_p, max_p = strategy.recommend(ThreatLevel.HIGH, 17.0)
        assert min_p < 17.0
        assert max_p <= 20.0
        # High threat = 6 dB variation range
        assert min_p == 11.0

    def test_confirmed_threat_wide_variation(self):
        strategy = TxPowerStrategy()
        min_p, max_p = strategy.recommend(ThreatLevel.CONFIRMED, 17.0)
        assert min_p == 11.0
        assert max_p == 20.0

    def test_fcc_max_not_exceeded(self):
        strategy = TxPowerStrategy()
        _, max_p = strategy.recommend(ThreatLevel.HIGH, 19.0)
        assert max_p <= 20.0

    def test_min_power_never_below_one(self):
        strategy = TxPowerStrategy()
        min_p, _ = strategy.recommend(ThreatLevel.HIGH, 3.0)
        assert min_p >= 1.0

    def test_low_threat_minimal_variation(self):
        strategy = TxPowerStrategy()
        min_p, max_p = strategy.recommend(ThreatLevel.LOW, 17.0)
        # Low threat = 1 dB variation
        assert min_p == 16.0
        assert max_p == 20.0

    def test_medium_threat_moderate_variation(self):
        strategy = TxPowerStrategy()
        min_p, max_p = strategy.recommend(ThreatLevel.MEDIUM, 17.0)
        assert min_p == 14.0
        assert max_p == 20.0


# ---------------------------------------------------------------------------
# BandSteeringStrategy
# ---------------------------------------------------------------------------


class TestBandSteeringStrategy:
    """BandSteeringStrategy recommends higher frequency bands."""

    def test_recommends_5ghz_from_24(self):
        strategy = BandSteeringStrategy()
        result = strategy.recommend("2.4", client_count_24=5, client_count_5=0)
        assert result == "5"

    def test_stays_on_5ghz(self):
        strategy = BandSteeringStrategy()
        result = strategy.recommend("5", client_count_24=0, client_count_5=5)
        assert result == "5"

    def test_stays_on_6ghz(self):
        strategy = BandSteeringStrategy()
        result = strategy.recommend("6", client_count_24=0, client_count_5=0)
        assert result == "6"


# ---------------------------------------------------------------------------
# BeaconIntervalStrategy
# ---------------------------------------------------------------------------


class TestBeaconIntervalStrategy:
    """BeaconIntervalStrategy recommends increased beacon interval."""

    def test_increases_from_default(self):
        strategy = BeaconIntervalStrategy()
        result = strategy.recommend(current_interval=100)
        assert result >= 500

    def test_already_high_stays(self):
        strategy = BeaconIntervalStrategy()
        result = strategy.recommend(current_interval=1000)
        assert result == 1000

    def test_recommends_at_least_500(self):
        strategy = BeaconIntervalStrategy()
        result = strategy.recommend(current_interval=200)
        assert result >= 500


# ---------------------------------------------------------------------------
# PMFStrategy
# ---------------------------------------------------------------------------


class TestPMFStrategy:
    """PMFStrategy always recommends enabling PMF."""

    def test_recommends_required(self):
        strategy = PMFStrategy()
        result = strategy.recommend()
        assert result in ("required", "optional")

    def test_result_is_string(self):
        strategy = PMFStrategy()
        result = strategy.recommend()
        assert isinstance(result, str)


# ---------------------------------------------------------------------------
# BeamformingStrategy
# ---------------------------------------------------------------------------


class TestBeamformingStrategy:
    """BeamformingStrategy recommends disabling beamforming under threat."""

    def test_high_threat_disables(self):
        strategy = BeamformingStrategy()
        result = strategy.recommend(ThreatLevel.HIGH)
        assert result is False  # Disable beamforming

    def test_confirmed_threat_disables(self):
        strategy = BeamformingStrategy()
        result = strategy.recommend(ThreatLevel.CONFIRMED)
        assert result is False

    def test_medium_threat_disables(self):
        strategy = BeamformingStrategy()
        result = strategy.recommend(ThreatLevel.MEDIUM)
        assert result is False

    def test_low_threat_keeps_enabled(self):
        strategy = BeamformingStrategy()
        result = strategy.recommend(ThreatLevel.LOW)
        assert result is True

    def test_no_threat_keeps_enabled(self):
        strategy = BeamformingStrategy()
        result = strategy.recommend(ThreatLevel.NONE)
        assert result is True
