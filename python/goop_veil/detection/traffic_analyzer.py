"""Traffic analyzer — identifies WiFi sensing patterns in network traffic.

Detects sensing activity by analyzing:
- Frame type distribution (sensing uses high probe/null frame ratios)
- Traffic periodicity (sensing requires regular CSI collection)
- Unusual frame patterns (action frames, null data bursts)
"""

from __future__ import annotations

import logging
from pathlib import Path

from goop_veil._core import parse_pcap_bytes, parse_raw_frame
from goop_veil.models import ThreatLevel

logger = logging.getLogger(__name__)

#: Threshold for probe request ratio (sensing meshes send many probes)
PROBE_RATIO_THRESHOLD = 0.15

#: Threshold for null data frame ratio (used for CSI collection)
NULL_DATA_RATIO_THRESHOLD = 0.10

#: Threshold for action frame ratio (802.11bf uses action frames)
ACTION_FRAME_RATIO_THRESHOLD = 0.05


class TrafficStats:
    """Accumulated traffic statistics."""

    __slots__ = (
        "total_frames",
        "beacon_count",
        "probe_request_count",
        "probe_response_count",
        "data_count",
        "null_data_count",
        "action_count",
        "management_count",
        "control_count",
    )

    def __init__(self) -> None:
        self.total_frames = 0
        self.beacon_count = 0
        self.probe_request_count = 0
        self.probe_response_count = 0
        self.data_count = 0
        self.null_data_count = 0
        self.action_count = 0
        self.management_count = 0
        self.control_count = 0

    @property
    def probe_ratio(self) -> float:
        return self.probe_request_count / max(self.total_frames, 1)

    @property
    def null_data_ratio(self) -> float:
        return self.null_data_count / max(self.total_frames, 1)

    @property
    def action_ratio(self) -> float:
        return self.action_count / max(self.total_frames, 1)

    def to_dict(self) -> dict[str, int | float]:
        return {
            "total_frames": self.total_frames,
            "beacon_count": self.beacon_count,
            "probe_request_count": self.probe_request_count,
            "probe_response_count": self.probe_response_count,
            "data_count": self.data_count,
            "null_data_count": self.null_data_count,
            "action_count": self.action_count,
            "management_count": self.management_count,
            "control_count": self.control_count,
            "probe_ratio": self.probe_ratio,
            "null_data_ratio": self.null_data_ratio,
            "action_ratio": self.action_ratio,
        }


class TrafficAnalyzer:
    """Analyzes WiFi traffic patterns for sensing indicators."""

    def __init__(self) -> None:
        self._stats = TrafficStats()

    @property
    def stats(self) -> TrafficStats:
        return self._stats

    def analyze_pcap(self, pcap_path: str | Path) -> tuple[ThreatLevel, list[str]]:
        """Analyze a pcap file for sensing traffic patterns.

        Returns (threat_level, list of indicator descriptions).
        """
        pcap_data = Path(pcap_path).read_bytes()
        raw_frames = parse_pcap_bytes(pcap_data)

        self._stats = TrafficStats()
        indicators: list[str] = []

        for _timestamp_us, frame_bytes in raw_frames:
            try:
                frame = parse_raw_frame(frame_bytes)
            except (ValueError, Exception):
                continue

            self._accumulate(frame)

        # Evaluate indicators
        if self._stats.probe_ratio > PROBE_RATIO_THRESHOLD:
            indicators.append(
                f"High probe request ratio: {self._stats.probe_ratio:.1%} "
                f"(threshold: {PROBE_RATIO_THRESHOLD:.1%})"
            )

        if self._stats.null_data_ratio > NULL_DATA_RATIO_THRESHOLD:
            indicators.append(
                f"High null data frame ratio: {self._stats.null_data_ratio:.1%} "
                f"(threshold: {NULL_DATA_RATIO_THRESHOLD:.1%})"
            )

        if self._stats.action_ratio > ACTION_FRAME_RATIO_THRESHOLD:
            indicators.append(
                f"High action frame ratio: {self._stats.action_ratio:.1%} "
                f"(threshold: {ACTION_FRAME_RATIO_THRESHOLD:.1%})"
            )

        # Determine threat level
        threat_level = self._assess_threat(indicators)

        logger.info(
            "Traffic analysis: %d frames, threat=%s, %d indicators",
            self._stats.total_frames,
            threat_level,
            len(indicators),
        )
        return threat_level, indicators

    def analyze_frames(self, frame_bytes_list: list[bytes]) -> tuple[ThreatLevel, list[str]]:
        """Analyze a list of raw frame bytes."""
        self._stats = TrafficStats()
        indicators: list[str] = []

        for frame_bytes in frame_bytes_list:
            try:
                frame = parse_raw_frame(frame_bytes)
            except (ValueError, Exception):
                continue
            self._accumulate(frame)

        if self._stats.probe_ratio > PROBE_RATIO_THRESHOLD:
            indicators.append(f"High probe ratio: {self._stats.probe_ratio:.1%}")
        if self._stats.null_data_ratio > NULL_DATA_RATIO_THRESHOLD:
            indicators.append(f"High null data ratio: {self._stats.null_data_ratio:.1%}")
        if self._stats.action_ratio > ACTION_FRAME_RATIO_THRESHOLD:
            indicators.append(f"High action ratio: {self._stats.action_ratio:.1%}")

        return self._assess_threat(indicators), indicators

    def _accumulate(self, frame: object) -> None:
        """Accumulate frame into statistics."""
        self._stats.total_frames += 1

        ft = getattr(frame, "frame_type", "")
        if ft == "management":
            self._stats.management_count += 1
        elif ft == "control":
            self._stats.control_count += 1
        elif ft == "data":
            self._stats.data_count += 1

        if getattr(frame, "is_beacon", False):
            self._stats.beacon_count += 1
        if getattr(frame, "is_probe_request", False):
            self._stats.probe_request_count += 1
        if getattr(frame, "is_probe_response", False):
            self._stats.probe_response_count += 1
        if getattr(frame, "is_action", False):
            self._stats.action_count += 1

        # Null data: subtype "null" in data frames
        if ft == "data" and getattr(frame, "subtype", "") == "null":
            self._stats.null_data_count += 1

    @staticmethod
    def _assess_threat(indicators: list[str]) -> ThreatLevel:
        if len(indicators) >= 3:
            return ThreatLevel.HIGH
        elif len(indicators) >= 2:
            return ThreatLevel.MEDIUM
        elif len(indicators) >= 1:
            return ThreatLevel.LOW
        return ThreatLevel.NONE

    def reset(self) -> None:
        self._stats = TrafficStats()
