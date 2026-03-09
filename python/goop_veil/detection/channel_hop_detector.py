"""Channel hop detector — identifies rapid channel switching indicative of WiFi sensing.

WiFi sensing systems (especially RuView-style) rapidly hop across channels to
collect CSI from multiple frequency bands. Normal APs rarely change channels.
Detecting rapid channel hopping is a strong indicator of sensing activity.
"""

from __future__ import annotations

import logging
from collections import defaultdict

from goop_veil.config import DetectionConfig
from goop_veil.models import BeaconAnomaly, DeviceFingerprint

logger = logging.getLogger(__name__)


class ChannelHopEvent:
    """Single channel change observation."""

    __slots__ = ("mac", "from_channel", "to_channel", "timestamp_us")

    def __init__(self, mac: str, from_channel: int, to_channel: int, timestamp_us: int) -> None:
        self.mac = mac
        self.from_channel = from_channel
        self.to_channel = to_channel
        self.timestamp_us = timestamp_us


class ChannelHopDetector:
    """Detects rapid channel hopping patterns from beacon/probe observations.

    Tracks per-device channel history and flags devices that switch channels
    faster than normal AP behavior.
    """

    def __init__(self, config: DetectionConfig | None = None) -> None:
        self._config = config or DetectionConfig()
        # MAC -> list of (timestamp_us, channel)
        self._channel_history: dict[str, list[tuple[int, int]]] = defaultdict(list)
        self._hop_events: list[ChannelHopEvent] = []

    @property
    def hop_events(self) -> list[ChannelHopEvent]:
        return list(self._hop_events)

    def observe(self, mac: str, channel: int, timestamp_us: int) -> ChannelHopEvent | None:
        """Record a device observation on a channel.

        Returns a ChannelHopEvent if the device changed channels.
        """
        history = self._channel_history[mac]

        if history and history[-1][1] != channel:
            event = ChannelHopEvent(
                mac=mac,
                from_channel=history[-1][1],
                to_channel=channel,
                timestamp_us=timestamp_us,
            )
            self._hop_events.append(event)
            history.append((timestamp_us, channel))
            return event

        history.append((timestamp_us, channel))
        return None

    def detect_rapid_hopping(self) -> list[BeaconAnomaly]:
        """Check all tracked devices for rapid channel hopping.

        Returns anomalies for devices that exceed the hop threshold
        within the configured time window.
        """
        anomalies: list[BeaconAnomaly] = []
        window_us = int(self._config.channel_hop_window_sec * 1_000_000)

        for mac, history in self._channel_history.items():
            if len(history) < 2:
                continue

            # Count hops within sliding window
            max_hops = 0
            for i in range(len(history)):
                start_ts = history[i][0]
                hops = 0
                prev_ch = history[i][1]
                for j in range(i + 1, len(history)):
                    if history[j][0] - start_ts > window_us:
                        break
                    if history[j][1] != prev_ch:
                        hops += 1
                        prev_ch = history[j][1]
                max_hops = max(max_hops, hops)

            if max_hops >= self._config.channel_hop_threshold:
                unique_channels = sorted(set(ch for _, ch in history))
                score = min(1.0, 0.5 + 0.1 * max_hops)
                anomalies.append(
                    BeaconAnomaly(
                        device=DeviceFingerprint(mac_address=mac),
                        anomaly_type="rapid_channel_hop",
                        score=score,
                        description=(
                            f"Rapid channel hopping: {max_hops} hops in "
                            f"{self._config.channel_hop_window_sec}s window, "
                            f"channels: {unique_channels}"
                        ),
                    )
                )
                logger.warning(
                    "Rapid channel hopping detected: %s (%d hops, channels: %s)",
                    mac,
                    max_hops,
                    unique_channels,
                )

        return anomalies

    def reset(self) -> None:
        self._channel_history.clear()
        self._hop_events.clear()
