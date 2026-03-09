"""Tests for CSISignatureAnalyzer — periodic human activity detection in CSI data.

Uses the Rust core FFT and periodic signal detection to identify breathing,
heartbeat, walking, and gesture patterns.
"""

from __future__ import annotations

import math

import pytest

from goop_veil.config import DetectionConfig
from goop_veil.detection.csi_signature import (
    CSISignatureAnalyzer,
    LABEL_TO_CAPABILITY,
    snr_to_confidence,
)
from goop_veil.models import SensingCapability


class TestBreathingSignal:
    """Detection of breathing-rate periodic components."""

    def test_strong_breathing_signal(self):
        """A clear 0.25 Hz sinusoid should be detected as breathing."""
        sample_rate = 10.0
        n = 512
        breathing_freq = 0.25
        amplitudes = [
            5.0 * math.sin(2 * math.pi * breathing_freq * i / sample_rate)
            + 10.0  # DC offset
            for i in range(n)
        ]
        analyzer = CSISignatureAnalyzer()
        sigs = analyzer.analyze(amplitudes, sample_rate_hz=sample_rate)
        labels = [s.label for s in sigs]
        assert "breathing" in labels

    def test_breathing_confidence_positive(self):
        sample_rate = 10.0
        n = 256
        amplitudes = [
            3.0 * math.sin(2 * math.pi * 0.3 * i / sample_rate) + 5.0
            for i in range(n)
        ]
        analyzer = CSISignatureAnalyzer()
        sigs = analyzer.analyze(amplitudes, sample_rate_hz=sample_rate)
        breathing_sigs = [s for s in sigs if s.label == "breathing"]
        if breathing_sigs:
            assert breathing_sigs[0].confidence > 0


class TestNoiseSignal:
    """No detections in pure noise."""

    def test_no_detection_in_noise(self):
        """Pseudo-random signal with very high SNR threshold should produce no detections."""
        import random
        rng = random.Random(42)
        amplitudes = [rng.gauss(0, 1) for _ in range(256)]
        config = DetectionConfig(csi_snr_threshold_db=30.0)
        analyzer = CSISignatureAnalyzer(config=config)
        sigs = analyzer.analyze(amplitudes, sample_rate_hz=10.0)
        assert len(sigs) == 0

    def test_too_few_samples(self):
        """Fewer than 8 samples should return empty."""
        analyzer = CSISignatureAnalyzer()
        sigs = analyzer.analyze([1.0, 2.0, 3.0])
        assert sigs == []


class TestGetFeatures:
    """CSI feature extraction."""

    def test_feature_keys(self):
        amplitudes = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0]
        analyzer = CSISignatureAnalyzer()
        features = analyzer.get_features(amplitudes)
        expected_keys = {
            "mean_amplitude",
            "std_amplitude",
            "mean_phase",
            "std_phase",
            "amplitude_range",
            "dominant_freq_hz",
        }
        assert set(features.keys()) == expected_keys

    def test_feature_values(self):
        amplitudes = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0]
        analyzer = CSISignatureAnalyzer()
        features = analyzer.get_features(amplitudes, sample_rate_hz=100.0)
        assert abs(features["mean_amplitude"] - 4.5) < 1e-6
        assert features["amplitude_range"] == pytest.approx(7.0, abs=1e-6)
        assert features["std_amplitude"] > 0

    def test_features_with_phases(self):
        amplitudes = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0]
        phases = [0.1, 0.2, 0.15, 0.25, 0.1, 0.2, 0.15, 0.25]
        analyzer = CSISignatureAnalyzer()
        features = analyzer.get_features(amplitudes, phases=phases, sample_rate_hz=100.0)
        assert features["mean_phase"] > 0
        assert features["std_phase"] > 0


class TestDetectedCapabilities:
    """Mapping from signature labels to sensing capabilities."""

    def test_breathing_maps_to_capability(self):
        from goop_veil.models import CSISignature

        sigs = [
            CSISignature(
                frequency_hz=0.25,
                magnitude=1.0,
                label="breathing",
                snr_db=15.0,
                confidence=0.85,
            ),
        ]
        analyzer = CSISignatureAnalyzer()
        caps = analyzer.detected_capabilities(sigs)
        assert SensingCapability.BREATHING in caps

    def test_multiple_capabilities(self):
        from goop_veil.models import CSISignature

        sigs = [
            CSISignature(
                frequency_hz=0.25, magnitude=1.0, label="breathing",
                snr_db=15.0, confidence=0.85,
            ),
            CSISignature(
                frequency_hz=1.0, magnitude=0.5, label="walking",
                snr_db=10.0, confidence=0.70,
            ),
        ]
        analyzer = CSISignatureAnalyzer()
        caps = analyzer.detected_capabilities(sigs)
        assert SensingCapability.BREATHING in caps
        assert SensingCapability.MOTION in caps

    def test_no_duplicates(self):
        from goop_veil.models import CSISignature

        sigs = [
            CSISignature(
                frequency_hz=0.2, magnitude=1.0, label="breathing",
                snr_db=15.0, confidence=0.8,
            ),
            CSISignature(
                frequency_hz=0.3, magnitude=0.8, label="breathing",
                snr_db=12.0, confidence=0.7,
            ),
        ]
        analyzer = CSISignatureAnalyzer()
        caps = analyzer.detected_capabilities(sigs)
        assert caps.count(SensingCapability.BREATHING) == 1


class TestSNRToConfidence:
    """SNR-to-confidence threshold mapping."""

    def test_high_snr(self):
        assert snr_to_confidence(25.0) == 0.95

    def test_medium_snr(self):
        assert snr_to_confidence(12.0) == 0.70

    def test_low_snr(self):
        assert snr_to_confidence(4.0) == 0.30

    def test_very_low_snr(self):
        assert snr_to_confidence(1.0) == 0.1
