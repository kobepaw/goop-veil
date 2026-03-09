"""CSI signature analyzer — detects human activity patterns in CSI data.

Uses Rust core FFT and periodic signal detection to identify:
- Breathing patterns (0.15-0.5 Hz)
- Heartbeat patterns (0.8-2.0 Hz)
- Walking/motion patterns (0.5-2.0 Hz)
- Gesture patterns (1.0-5.0 Hz)

These periodic CSI variations are the mechanism by which WiFi sensing
systems track human activity through walls.
"""

from __future__ import annotations

import logging

from goop_veil._core import compute_csi_features, detect_periodic_signal
from goop_veil.config import DetectionConfig
from goop_veil.models import CSISignature, SensingCapability

logger = logging.getLogger(__name__)

#: Mapping from signal labels to sensing capabilities
LABEL_TO_CAPABILITY: dict[str, SensingCapability] = {
    "breathing": SensingCapability.BREATHING,
    "heartbeat": SensingCapability.HEARTBEAT,
    "walking": SensingCapability.MOTION,
    "gesture": SensingCapability.GESTURE,
}

#: Confidence mapping based on SNR
SNR_CONFIDENCE_THRESHOLDS: list[tuple[float, float]] = [
    (20.0, 0.95),  # >20 dB SNR = very high confidence
    (15.0, 0.85),
    (10.0, 0.70),
    (6.0, 0.50),
    (3.0, 0.30),
]


def snr_to_confidence(snr_db: float) -> float:
    """Convert SNR in dB to a confidence score (0-1)."""
    for threshold, confidence in SNR_CONFIDENCE_THRESHOLDS:
        if snr_db >= threshold:
            return confidence
    return 0.1


class CSISignatureAnalyzer:
    """Analyzes CSI amplitude/phase data for human activity signatures."""

    def __init__(self, config: DetectionConfig | None = None) -> None:
        self._config = config or DetectionConfig()

    def analyze(
        self,
        amplitudes: list[float],
        phases: list[float] | None = None,
        sample_rate_hz: float | None = None,
    ) -> list[CSISignature]:
        """Analyze CSI data for periodic human activity signatures.

        Args:
            amplitudes: CSI amplitude values over time.
            phases: CSI phase values over time (optional).
            sample_rate_hz: Sample rate in Hz (default from config).

        Returns:
            List of detected CSI signatures with confidence scores.
        """
        sr = sample_rate_hz or self._config.csi_sample_rate_hz

        if len(amplitudes) < 8:
            logger.debug("Too few CSI samples for analysis: %d", len(amplitudes))
            return []

        # Use Rust core for periodic signal detection
        detections = detect_periodic_signal(
            amplitudes,
            sr,
            self._config.csi_snr_threshold_db,
        )

        signatures: list[CSISignature] = []
        for freq_hz, magnitude, label in detections:
            # Calculate SNR for confidence
            noise_floor = sum(a * a for a in amplitudes) / len(amplitudes)
            if noise_floor > 0:
                snr_db = 10.0 * ((magnitude * magnitude / noise_floor) + 1e-15).__class__(
                    magnitude * magnitude / max(noise_floor, 1e-15)
                )
                # Simpler: use magnitude ratio
                mean_amp = sum(abs(a) for a in amplitudes) / len(amplitudes)
                snr_db = 20.0 * (magnitude / max(mean_amp, 1e-15)).__class__(
                    max(magnitude / max(mean_amp, 1e-15), 1e-15)
                )
            else:
                snr_db = 0.0

            # Use log10 properly
            import math

            mean_amp = sum(abs(a) for a in amplitudes) / len(amplitudes)
            ratio = magnitude / max(mean_amp, 1e-15)
            snr_db = 20.0 * math.log10(max(ratio, 1e-15))

            confidence = snr_to_confidence(snr_db)

            signatures.append(
                CSISignature(
                    frequency_hz=round(freq_hz, 4),
                    magnitude=round(magnitude, 6),
                    label=label,
                    snr_db=round(snr_db, 1),
                    confidence=round(confidence, 2),
                )
            )
            logger.info(
                "CSI signature: %s at %.2f Hz (SNR=%.1f dB, confidence=%.2f)",
                label,
                freq_hz,
                snr_db,
                confidence,
            )

        return signatures

    def get_features(
        self,
        amplitudes: list[float],
        phases: list[float] | None = None,
        sample_rate_hz: float | None = None,
    ) -> dict[str, float]:
        """Extract CSI feature vector using Rust core.

        Returns dict with: mean_amplitude, std_amplitude, mean_phase,
        std_phase, amplitude_range, dominant_freq_hz.
        """
        sr = sample_rate_hz or self._config.csi_sample_rate_hz
        ph = phases or [0.0] * len(amplitudes)

        mean_a, std_a, mean_p, std_p, range_a, dom_freq = compute_csi_features(
            amplitudes, ph, sr
        )
        return {
            "mean_amplitude": mean_a,
            "std_amplitude": std_a,
            "mean_phase": mean_p,
            "std_phase": std_p,
            "amplitude_range": range_a,
            "dominant_freq_hz": dom_freq,
        }

    def detected_capabilities(self, signatures: list[CSISignature]) -> list[SensingCapability]:
        """Map detected signatures to sensing capabilities."""
        caps: list[SensingCapability] = []
        for sig in signatures:
            cap = LABEL_TO_CAPABILITY.get(sig.label)
            if cap and cap not in caps:
                caps.append(cap)
        return caps
