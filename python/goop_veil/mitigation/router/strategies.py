"""WiFi privacy mitigation strategies — encapsulate RF physics knowledge.

Each strategy class produces a recommendation based on current network state,
detected threats, and WiFi physical-layer properties. All recommendations
are software-only router reconfigurations (no hardware required).

Terminology: Uses approved terms only (privacy enhancement, RF diversity,
multipath management, coverage optimization).
"""

from __future__ import annotations

import logging
from collections import Counter

from goop_veil.models import ThreatLevel

logger = logging.getLogger(__name__)

# FCC Part 15.247 / 15.407 conducted power limit (dBm)
_FCC_MAX_TX_POWER_DBM = 20.0

# Default beacon interval (Time Units, 1 TU = 1.024 ms)
_DEFAULT_BEACON_INTERVAL_TU = 100

# Maximum bandwidth per band (MHz)
_MAX_BANDWIDTH = {"2.4": 40, "5": 160, "6": 320}


class ChannelStrategy:
    """Recommend channel selection to maximize co-channel multipath complexity.

    Co-locating on the same channel as a detected attacker maximizes
    co-channel traffic, raising the noise floor for CSI extraction.
    Per UChicago research, co-channel traffic reduces detection to ~47%.
    """

    def recommend(
        self,
        attacker_channels: list[int] | None = None,
        neighbor_aps: list[dict] | None = None,
    ) -> int:
        """Return the recommended WiFi channel.

        Args:
            attacker_channels: Channels where attacker devices were detected.
            neighbor_aps: List of neighbor AP dicts with 'channel' key.

        Returns:
            Recommended channel number.
        """
        # If we know the attacker's channel(s), co-locate on the most common one
        if attacker_channels:
            counter = Counter(attacker_channels)
            return counter.most_common(1)[0][0]

        # Without attacker info, recommend the most congested channel
        # to maximize ambient multipath complexity
        if neighbor_aps:
            channel_counts = Counter(ap.get("channel", 0) for ap in neighbor_aps)
            # Filter out channel 0 (unknown)
            channel_counts.pop(0, None)
            if channel_counts:
                return channel_counts.most_common(1)[0][0]

        # Default: channel 6 (most commonly used, likely most congested)
        return 6


class BandwidthStrategy:
    """Recommend widest supported bandwidth for the band.

    Wider bandwidth = more subcarriers = more multipath diversity.
    Invalidates attacker models trained on narrower bandwidth CSI.
    """

    def recommend(self, current_bw: int, band: str) -> int:
        """Return the recommended bandwidth in MHz.

        Args:
            current_bw: Current bandwidth in MHz.
            band: Current band ("2.4", "5", "6").

        Returns:
            Recommended bandwidth in MHz.
        """
        max_bw = _MAX_BANDWIDTH.get(band, 20)
        if current_bw < max_bw:
            return max_bw
        return current_bw


class TxPowerStrategy:
    """Recommend TX power variation range within FCC limits.

    Higher power and power variation increase multipath complexity.
    Per Wi-Spoof (NDSS 2024), TX power variation causes 93%
    misclassification in WiFi sensing models.
    """

    def recommend(
        self,
        threat_level: ThreatLevel,
        current_power: float,
    ) -> tuple[float, float]:
        """Return (min_power, max_power) range for TX power variation.

        Args:
            threat_level: Current threat assessment.
            current_power: Current TX power in dBm.

        Returns:
            Tuple of (min_power_dbm, max_power_dbm) within FCC limits.
        """
        max_power = min(current_power + 3.0, _FCC_MAX_TX_POWER_DBM)

        if threat_level in (ThreatLevel.CONFIRMED, ThreatLevel.HIGH):
            # Wider variation range for higher threats
            min_power = max(current_power - 6.0, 1.0)
        elif threat_level == ThreatLevel.MEDIUM:
            min_power = max(current_power - 3.0, 1.0)
        else:
            # LOW/NONE — minimal variation
            min_power = max(current_power - 1.0, 1.0)

        return (min_power, max_power)


class BandSteeringStrategy:
    """Recommend frequency band for maximum wall attenuation.

    5 GHz has ~2x wall attenuation vs 2.4 GHz, reducing signal leakage.
    6 GHz (WiFi 6E/7) has even higher attenuation.
    """

    def recommend(
        self,
        current_band: str,
        client_count_24: int = 0,
        client_count_5: int = 0,
    ) -> str:
        """Return recommended band.

        Args:
            current_band: Current band ("2.4", "5", "6").
            client_count_24: Number of clients on 2.4 GHz.
            client_count_5: Number of clients on 5 GHz.

        Returns:
            Recommended band string ("2.4", "5", or "6").
        """
        # Always prefer higher bands for privacy (more wall attenuation)
        # 6 GHz > 5 GHz > 2.4 GHz
        if current_band == "6":
            return "6"  # Already on best band

        if current_band == "5":
            return "5"  # 5 GHz is good; 6 GHz would require explicit support check

        # On 2.4 GHz — recommend 5 GHz migration
        return "5"


class BeaconIntervalStrategy:
    """Recommend increased beacon interval to reduce passive CSI samples.

    Default 100 TU = ~10 beacons/sec — each is a free CSI sample.
    Increasing to 500+ TU reduces passive collection rate by 5x.
    """

    def recommend(self, current_interval: int) -> int:
        """Return recommended beacon interval in TU.

        Args:
            current_interval: Current beacon interval in TU.

        Returns:
            Recommended beacon interval in TU (at least 500).
        """
        target = 500
        if current_interval >= target:
            return current_interval
        return target


class PMFStrategy:
    """Recommend 802.11w Protected Management Frames.

    PMF prevents forced disassociation attacks (deauth floods) that
    can be used to force client reconnections for CSI harvesting.
    """

    def recommend(self) -> str:
        """Return recommended PMF mode.

        Returns:
            "required" for maximum protection, or "optional" for compatibility.
        """
        # Always recommend "required" for maximum protection.
        # Fall back to "optional" only if client compatibility is a concern,
        # but we default to "required" since most modern devices support it.
        return "required"


class BeamformingStrategy:
    """Recommend beamforming configuration for privacy.

    LeakyBeam (NDSS 2025) demonstrated that BFI (Beamforming Feedback
    Information) in 802.11ac/ax leaks plaintext spatial data even over
    encrypted connections. Disabling beamforming eliminates this leak.
    """

    def recommend(self, threat_level: ThreatLevel) -> bool:
        """Return whether beamforming should be kept enabled.

        Args:
            threat_level: Current threat assessment.

        Returns:
            True to keep beamforming enabled, False to disable it.
        """
        if threat_level in (ThreatLevel.CONFIRMED, ThreatLevel.HIGH):
            # Disable beamforming to eliminate BFI plaintext leak
            return False

        if threat_level == ThreatLevel.MEDIUM:
            # Disable as precaution
            return False

        # LOW/NONE — keep enabled for performance
        return True
