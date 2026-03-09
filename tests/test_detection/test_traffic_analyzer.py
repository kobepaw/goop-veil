"""Tests for TrafficAnalyzer — WiFi sensing traffic pattern detection.

Tests frame type distribution analysis and threat level assessment.
"""

from __future__ import annotations

import pytest

from goop_veil.detection.traffic_analyzer import (
    ACTION_FRAME_RATIO_THRESHOLD,
    NULL_DATA_RATIO_THRESHOLD,
    PROBE_RATIO_THRESHOLD,
    TrafficAnalyzer,
    TrafficStats,
)
from goop_veil.models import ThreatLevel


# ---------------------------------------------------------------------------
# Helper to build specific frame types
# ---------------------------------------------------------------------------

def _make_null_data_frame(mac: str = "aa:bb:cc:dd:ee:01") -> bytes:
    """Null data frame: type=2 (data), subtype=4 (null) -> FC byte0 = 0x48."""
    mac_bytes = bytes.fromhex(mac.replace(":", ""))
    frame = bytearray()
    # FC: type=2 (bits 2-3), subtype=4 (bits 4-7) -> 0b0100_1000 = 0x48
    frame.extend([0x48, 0x00])
    frame.extend([0x00, 0x00])  # Duration
    frame.extend([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])  # Addr1
    frame.extend(mac_bytes)  # Addr2
    frame.extend(mac_bytes)  # Addr3
    return bytes(frame)


def _make_action_frame(mac: str = "aa:bb:cc:dd:ee:01") -> bytes:
    """Action frame: type=0 (management), subtype=13 (action) -> FC byte0 = 0xD0."""
    mac_bytes = bytes.fromhex(mac.replace(":", ""))
    frame = bytearray()
    # FC: type=0 (management), subtype=13 (action) -> 0b1101_0000 = 0xD0
    frame.extend([0xD0, 0x00])
    frame.extend([0x00, 0x00])  # Duration
    frame.extend([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])  # Addr1
    frame.extend(mac_bytes)  # Addr2
    frame.extend(mac_bytes)  # Addr3
    frame.extend([0x00, 0x00])  # Seq ctrl
    frame.extend(bytes(10))  # Body
    return bytes(frame)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestNormalTraffic:
    """Normal traffic produces no anomalies."""

    def test_empty_frames(self):
        analyzer = TrafficAnalyzer()
        threat, indicators = analyzer.analyze_frames([])
        assert threat == ThreatLevel.NONE
        assert indicators == []

    def test_all_beacons(self, make_beacon):
        """A mix of normal beacons should show NONE threat."""
        frames = [make_beacon(ssid=f"Net{i}", mac=f"00:11:22:33:44:{i:02x}")
                  for i in range(20)]
        analyzer = TrafficAnalyzer()
        threat, indicators = analyzer.analyze_frames(frames)
        assert threat == ThreatLevel.NONE

    def test_mixed_normal(self, make_beacon, make_data_frame):
        """Normal mix of beacons + data should show NONE threat."""
        frames = (
            [make_beacon(ssid="Home", mac="00:11:22:33:44:55")] * 10
            + [make_data_frame()] * 10
        )
        analyzer = TrafficAnalyzer()
        threat, indicators = analyzer.analyze_frames(frames)
        assert threat == ThreatLevel.NONE


class TestHighProbeRatio:
    """High probe request ratio indicates sensing activity."""

    def test_high_probe_ratio(self, make_beacon, make_probe_request):
        # 5 beacons + 15 probe requests -> probe ratio = 15/20 = 0.75
        frames = (
            [make_beacon(ssid="Home", mac="00:11:22:33:44:55")] * 5
            + [make_probe_request(ssid="P", mac=f"aa:bb:cc:dd:ee:{i:02x}")
               for i in range(15)]
        )
        analyzer = TrafficAnalyzer()
        threat, indicators = analyzer.analyze_frames(frames)
        assert len(indicators) >= 1
        assert any("probe" in ind.lower() for ind in indicators)
        assert threat != ThreatLevel.NONE


class TestHighNullDataRatio:
    """High null data frame ratio indicates CSI collection."""

    def test_high_null_data_ratio(self, make_beacon):
        # 5 beacons + 15 null data -> null ratio = 15/20 = 0.75
        frames = (
            [make_beacon(ssid="Home", mac="00:11:22:33:44:55")] * 5
            + [_make_null_data_frame(f"aa:bb:cc:dd:ee:{i:02x}") for i in range(15)]
        )
        analyzer = TrafficAnalyzer()
        threat, indicators = analyzer.analyze_frames(frames)
        assert len(indicators) >= 1
        assert any("null" in ind.lower() for ind in indicators)


class TestHighActionFrameRatio:
    """High action frame ratio indicates 802.11bf sensing."""

    def test_high_action_ratio(self, make_beacon):
        # 10 beacons + 10 action frames -> action ratio = 10/20 = 0.50
        frames = (
            [make_beacon(ssid="Home", mac="00:11:22:33:44:55")] * 10
            + [_make_action_frame(f"aa:bb:cc:dd:ee:{i:02x}") for i in range(10)]
        )
        analyzer = TrafficAnalyzer()
        threat, indicators = analyzer.analyze_frames(frames)
        assert any("action" in ind.lower() for ind in indicators)


class TestThreatLevelAssessment:
    """Threat level depends on number of indicators."""

    def test_one_indicator_is_low(self, make_beacon, make_probe_request):
        # Only probe ratio above threshold (but not null/action)
        frames = (
            [make_beacon(ssid="Home", mac="00:11:22:33:44:55")] * 5
            + [make_probe_request(ssid="P", mac=f"aa:bb:cc:dd:ee:{i:02x}")
               for i in range(5)]
        )
        analyzer = TrafficAnalyzer()
        threat, indicators = analyzer.analyze_frames(frames)
        if len(indicators) == 1:
            assert threat == ThreatLevel.LOW

    def test_two_indicators_is_medium(self, make_beacon, make_probe_request):
        # High probe ratio AND high null data ratio
        frames = (
            [make_beacon(ssid="Home", mac="00:11:22:33:44:55")] * 2
            + [make_probe_request(ssid="P", mac="aa:bb:cc:dd:ee:01")] * 5
            + [_make_null_data_frame(f"aa:bb:cc:dd:ee:{i:02x}") for i in range(5)]
        )
        analyzer = TrafficAnalyzer()
        threat, indicators = analyzer.analyze_frames(frames)
        if len(indicators) == 2:
            assert threat == ThreatLevel.MEDIUM

    def test_three_indicators_is_high(self, make_beacon, make_probe_request):
        # All three indicators above threshold
        frames = (
            [make_beacon(ssid="H", mac="00:11:22:33:44:55")] * 2
            + [make_probe_request(ssid="P", mac="aa:bb:cc:dd:ee:01")] * 5
            + [_make_null_data_frame("aa:bb:cc:dd:ee:02")] * 5
            + [_make_action_frame("aa:bb:cc:dd:ee:03")] * 5
        )
        analyzer = TrafficAnalyzer()
        threat, indicators = analyzer.analyze_frames(frames)
        if len(indicators) >= 3:
            assert threat == ThreatLevel.HIGH


class TestAnalyzePcap:
    """Analyze from pcap file."""

    def test_analyze_pcap(self, make_beacon, tmp_pcap):
        frames = [make_beacon(ssid=f"N{i}", mac=f"00:11:22:33:44:{i:02x}")
                  for i in range(10)]
        pcap_path = tmp_pcap(frames)
        analyzer = TrafficAnalyzer()
        threat, indicators = analyzer.analyze_pcap(pcap_path)
        assert threat == ThreatLevel.NONE
        assert analyzer.stats.total_frames == 10
        assert analyzer.stats.beacon_count == 10


class TestReset:
    """Reset clears accumulated statistics."""

    def test_reset(self, make_beacon):
        analyzer = TrafficAnalyzer()
        analyzer.analyze_frames([make_beacon(ssid="T", mac="00:11:22:33:44:55")])
        assert analyzer.stats.total_frames > 0
        analyzer.reset()
        assert analyzer.stats.total_frames == 0
