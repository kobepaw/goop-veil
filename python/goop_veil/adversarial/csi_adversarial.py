"""CSI adversarial — ML-based adversarial CSI pattern generation.

Generates WiFi transmission timing patterns that produce adversarial
CSI perturbations designed to confuse ML-based sensing classifiers.

This is the most advanced defense tier, using BroRL feedback to
learn which perturbation strategies are most effective against
specific sensing system architectures.
"""

from __future__ import annotations

import logging
import math
import random

from goop_veil.adversarial.brorl_adapter import BroRLAdapter

logger = logging.getLogger(__name__)

#: Available adversarial techniques
TECHNIQUES: dict[str, str] = {
    "random_timing": "Randomize inter-frame timing to destroy periodicity",
    "frequency_spread": "Spread energy across multiple frequency bands",
    "phase_rotation": "Rotate carrier phase across transmissions",
    "amplitude_modulation": "Modulate TX power within FCC limits",
    "multipath_injection": "Create synthetic multipath via timed reflections",
    "subcarrier_scramble": "Vary active OFDM subcarriers per frame",
}


class AdversarialCSIGenerator:
    """Generates adversarial CSI perturbation strategies.

    Uses BroRL to learn which strategies are most effective against
    the detected sensing system.
    """

    def __init__(self, brorl: BroRLAdapter | None = None) -> None:
        self._brorl = brorl or BroRLAdapter()

    def select_technique(self) -> tuple[str, str]:
        """Select the best technique using BroRL Thompson sampling.

        Returns (technique_name, description).
        """
        ranked = self._brorl.rank_techniques(list(TECHNIQUES.keys()))
        best_name = ranked[0][0]
        return best_name, TECHNIQUES[best_name]

    def generate_timing_pattern(
        self,
        technique: str,
        duration_sec: float = 1.0,
        base_interval_ms: float = 10.0,
    ) -> list[float]:
        """Generate frame transmission timing (ms intervals) for a technique.

        Returns list of inter-frame delays in milliseconds.
        """
        n_frames = int(duration_sec * 1000 / base_interval_ms)

        if technique == "random_timing":
            return [random.expovariate(1.0 / base_interval_ms) for _ in range(n_frames)]

        elif technique == "frequency_spread":
            # Vary timing to spread spectral energy
            return [
                base_interval_ms * (1.0 + 0.5 * math.sin(2 * math.pi * i / 7))
                for i in range(n_frames)
            ]

        elif technique == "phase_rotation":
            # Consistent timing, phase rotation handled at RF level
            return [base_interval_ms] * n_frames

        elif technique == "amplitude_modulation":
            # Timing pattern that creates AM-like CSI variation
            return [
                base_interval_ms * (0.8 + 0.4 * abs(math.sin(math.pi * i / 13)))
                for i in range(n_frames)
            ]

        elif technique == "multipath_injection":
            # Pairs of frames with specific delay to create synthetic multipath
            pattern: list[float] = []
            for _ in range(n_frames // 2):
                pattern.append(base_interval_ms)
                pattern.append(random.uniform(0.1, 2.0))  # Short delay = multipath
            return pattern

        elif technique == "subcarrier_scramble":
            return [base_interval_ms] * n_frames

        else:
            return [base_interval_ms] * n_frames

    def record_effectiveness(self, technique: str, effective: bool) -> None:
        """Feed back effectiveness to BroRL for learning."""
        self._brorl.record_outcome(technique, effective)

    def get_technique_stats(self) -> dict:
        """Get current BroRL statistics for all techniques."""
        return self._brorl.get_stats()
