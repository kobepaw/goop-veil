"""Vitals spoofer — generates synthetic CSI patterns to mask real biometrics.

Creates WiFi traffic patterns that produce CSI variations mimicking
false vital signs (breathing, heartbeat) to confuse sensing systems.

All generated patterns use legitimate WiFi frames at FCC-compliant power
levels. The technique works by creating multipath variations that
overlay genuine biometric CSI signatures with synthetic ones.
"""

from __future__ import annotations

import logging
import math
import random

logger = logging.getLogger(__name__)


class SyntheticPattern:
    """A synthetic CSI pattern for masking real biometrics."""

    __slots__ = ("name", "frequency_hz", "amplitude", "phase_offset_rad", "waveform")

    def __init__(
        self,
        name: str,
        frequency_hz: float,
        amplitude: float,
        phase_offset_rad: float = 0.0,
        waveform: str = "sine",
    ) -> None:
        self.name = name
        self.frequency_hz = frequency_hz
        self.amplitude = amplitude
        self.phase_offset_rad = phase_offset_rad
        self.waveform = waveform

    def generate(self, duration_sec: float, sample_rate_hz: float) -> list[float]:
        """Generate the synthetic pattern as a time series."""
        n_samples = int(duration_sec * sample_rate_hz)
        samples = []
        for i in range(n_samples):
            t = i / sample_rate_hz
            phase = 2 * math.pi * self.frequency_hz * t + self.phase_offset_rad

            if self.waveform == "sine":
                val = self.amplitude * math.sin(phase)
            elif self.waveform == "triangle":
                val = self.amplitude * (2 / math.pi) * math.asin(math.sin(phase))
            else:
                val = self.amplitude * math.sin(phase)

            samples.append(val)
        return samples


class VitalsSpoofer:
    """Generates synthetic vital sign patterns for CSI masking.

    Creates patterns at randomized frequencies near (but not at) typical
    human vital sign frequencies, making it difficult for sensing systems
    to separate real signals from synthetic ones.
    """

    def __init__(self) -> None:
        self._patterns: list[SyntheticPattern] = []

    def generate_breathing_mask(self) -> SyntheticPattern:
        """Generate a synthetic breathing pattern.

        Real breathing: 0.15-0.5 Hz (9-30 breaths/min)
        Synthetic: randomized within the same band.
        """
        freq = random.uniform(0.15, 0.5)
        amplitude = random.uniform(0.5, 2.0)
        phase = random.uniform(0, 2 * math.pi)

        pattern = SyntheticPattern(
            name="synthetic_breathing",
            frequency_hz=round(freq, 3),
            amplitude=round(amplitude, 3),
            phase_offset_rad=round(phase, 3),
        )
        self._patterns.append(pattern)
        logger.debug("Generated breathing mask: %.3f Hz, amp=%.3f", freq, amplitude)
        return pattern

    def generate_heartbeat_mask(self) -> SyntheticPattern:
        """Generate a synthetic heartbeat pattern.

        Real heartbeat: 0.8-2.0 Hz (48-120 bpm)
        Synthetic: randomized within the same band.
        """
        freq = random.uniform(0.8, 2.0)
        amplitude = random.uniform(0.2, 1.0)
        phase = random.uniform(0, 2 * math.pi)

        pattern = SyntheticPattern(
            name="synthetic_heartbeat",
            frequency_hz=round(freq, 3),
            amplitude=round(amplitude, 3),
            phase_offset_rad=round(phase, 3),
        )
        self._patterns.append(pattern)
        logger.debug("Generated heartbeat mask: %.3f Hz, amp=%.3f", freq, amplitude)
        return pattern

    def generate_motion_mask(self) -> SyntheticPattern:
        """Generate a synthetic motion pattern."""
        freq = random.uniform(0.5, 2.0)
        amplitude = random.uniform(1.0, 5.0)
        phase = random.uniform(0, 2 * math.pi)

        pattern = SyntheticPattern(
            name="synthetic_motion",
            frequency_hz=round(freq, 3),
            amplitude=round(amplitude, 3),
            phase_offset_rad=round(phase, 3),
            waveform="triangle",
        )
        self._patterns.append(pattern)
        return pattern

    def generate_full_mask(self) -> list[SyntheticPattern]:
        """Generate a complete set of masking patterns for all vitals."""
        patterns = [
            self.generate_breathing_mask(),
            self.generate_heartbeat_mask(),
            self.generate_motion_mask(),
        ]
        # Add harmonics for more effective masking
        for p in list(patterns):
            harmonic = SyntheticPattern(
                name=f"{p.name}_harmonic",
                frequency_hz=round(p.frequency_hz * 2, 3),
                amplitude=round(p.amplitude * 0.3, 3),
                phase_offset_rad=round(p.phase_offset_rad + math.pi / 4, 3),
            )
            patterns.append(harmonic)

        return patterns

    @property
    def active_patterns(self) -> list[SyntheticPattern]:
        return list(self._patterns)

    def clear(self) -> None:
        self._patterns.clear()
