"""Tests for ChannelHopDetector — rapid channel switching detection.

WiFi sensing systems rapidly hop channels to collect multi-band CSI.
This detector identifies such patterns.
"""

from __future__ import annotations

import pytest

from goop_veil.config import DetectionConfig
from goop_veil.detection.channel_hop_detector import ChannelHopDetector, ChannelHopEvent


MAC = "aa:bb:cc:dd:ee:01"


class TestSingleChannel:
    """Single channel observations produce no hops."""

    def test_no_hop_on_same_channel(self):
        detector = ChannelHopDetector()
        e1 = detector.observe(MAC, channel=6, timestamp_us=1_000_000)
        e2 = detector.observe(MAC, channel=6, timestamp_us=2_000_000)
        assert e1 is None
        assert e2 is None

    def test_no_rapid_hopping_single_channel(self):
        detector = ChannelHopDetector()
        for i in range(10):
            detector.observe(MAC, channel=6, timestamp_us=i * 1_000_000)
        anomalies = detector.detect_rapid_hopping()
        assert anomalies == []


class TestChannelHopDetection:
    """Channel change event detection."""

    def test_detects_single_hop(self):
        detector = ChannelHopDetector()
        detector.observe(MAC, channel=1, timestamp_us=1_000_000)
        event = detector.observe(MAC, channel=6, timestamp_us=2_000_000)
        assert event is not None
        assert isinstance(event, ChannelHopEvent)
        assert event.from_channel == 1
        assert event.to_channel == 6

    def test_hop_events_tracked(self):
        detector = ChannelHopDetector()
        detector.observe(MAC, channel=1, timestamp_us=1_000_000)
        detector.observe(MAC, channel=6, timestamp_us=2_000_000)
        detector.observe(MAC, channel=11, timestamp_us=3_000_000)
        assert len(detector.hop_events) == 2

    def test_returning_to_same_channel_is_hop(self):
        detector = ChannelHopDetector()
        detector.observe(MAC, channel=1, timestamp_us=1_000_000)
        detector.observe(MAC, channel=6, timestamp_us=2_000_000)
        event = detector.observe(MAC, channel=1, timestamp_us=3_000_000)
        assert event is not None
        assert event.to_channel == 1


class TestRapidHopping:
    """Rapid channel hopping above threshold detection."""

    def test_rapid_hopping_detected(self):
        """Cycling through 6 channels in 5 seconds should trigger (default threshold=5)."""
        config = DetectionConfig(channel_hop_threshold=5, channel_hop_window_sec=10.0)
        detector = ChannelHopDetector(config=config)

        channels = [1, 6, 11, 1, 6, 11, 1]
        for i, ch in enumerate(channels):
            detector.observe(MAC, channel=ch, timestamp_us=i * 1_000_000)

        anomalies = detector.detect_rapid_hopping()
        assert len(anomalies) == 1
        assert anomalies[0].anomaly_type == "rapid_channel_hop"
        assert anomalies[0].score >= 0.5

    def test_slow_hopping_not_detected(self):
        """Hopping slower than the window should not trigger."""
        config = DetectionConfig(channel_hop_threshold=5, channel_hop_window_sec=2.0)
        detector = ChannelHopDetector(config=config)

        # Each hop 3 seconds apart, window is 2 seconds -> max 1 hop per window
        channels = [1, 6, 11, 1, 6, 11]
        for i, ch in enumerate(channels):
            detector.observe(MAC, channel=ch, timestamp_us=i * 3_000_000)

        anomalies = detector.detect_rapid_hopping()
        assert len(anomalies) == 0

    def test_below_threshold_not_detected(self):
        """Fewer hops than threshold should not trigger."""
        config = DetectionConfig(channel_hop_threshold=10)
        detector = ChannelHopDetector(config=config)

        channels = [1, 6, 11, 1]
        for i, ch in enumerate(channels):
            detector.observe(MAC, channel=ch, timestamp_us=i * 1_000_000)

        anomalies = detector.detect_rapid_hopping()
        assert len(anomalies) == 0


class TestWindowBasedDetection:
    """Window-based sliding window detection."""

    def test_burst_in_window_detected(self):
        """Burst of hops within a short window followed by silence."""
        config = DetectionConfig(channel_hop_threshold=4, channel_hop_window_sec=5.0)
        detector = ChannelHopDetector(config=config)

        # Rapid burst at t=0..4s (5 hops)
        channels = [1, 6, 11, 1, 6, 11]
        for i, ch in enumerate(channels):
            detector.observe(MAC, channel=ch, timestamp_us=i * 500_000)

        # Long pause then normal
        detector.observe(MAC, channel=1, timestamp_us=20_000_000)

        anomalies = detector.detect_rapid_hopping()
        assert len(anomalies) == 1


class TestMultipleDevices:
    """Multiple devices tracked independently."""

    def test_independent_tracking(self):
        detector = ChannelHopDetector()
        mac_a = "aa:bb:cc:dd:ee:01"
        mac_b = "aa:bb:cc:dd:ee:02"

        detector.observe(mac_a, channel=1, timestamp_us=1_000_000)
        detector.observe(mac_b, channel=6, timestamp_us=1_000_000)

        event_a = detector.observe(mac_a, channel=6, timestamp_us=2_000_000)
        event_b = detector.observe(mac_b, channel=6, timestamp_us=2_000_000)

        assert event_a is not None  # mac_a changed channel
        assert event_b is None  # mac_b stayed on channel 6


class TestReset:
    """Reset clears all state."""

    def test_reset(self):
        detector = ChannelHopDetector()
        detector.observe(MAC, channel=1, timestamp_us=1_000_000)
        detector.observe(MAC, channel=6, timestamp_us=2_000_000)
        assert len(detector.hop_events) > 0
        detector.reset()
        assert len(detector.hop_events) == 0
