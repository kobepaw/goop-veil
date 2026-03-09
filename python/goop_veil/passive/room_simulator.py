"""Room simulator — simulates WiFi CSI propagation in a room for defense planning.

Models multi-path propagation, material effects, and human body presence
to estimate effectiveness of passive defense strategies.
"""

from __future__ import annotations

import logging
import math

from goop_veil._core import csi_perturbation_estimate, fresnel_radius, material_attenuation_db
from goop_veil.config import PassiveDefenseConfig

logger = logging.getLogger(__name__)


class RoomSimulator:
    """Simulates WiFi CSI propagation for defense planning."""

    def __init__(self, config: PassiveDefenseConfig | None = None) -> None:
        self._config = config or PassiveDefenseConfig()

    def simulate_sensing_effectiveness(
        self,
        room_length_m: float,
        room_width_m: float,
        tx_pos: tuple[float, float],
        rx_pos: tuple[float, float],
        body_pos: tuple[float, float],
        wall_materials: list[tuple[str, float]] | None = None,
        freq_mhz: float | None = None,
    ) -> dict[str, float]:
        """Simulate how effectively a TX/RX pair can sense a body in the room.

        Args:
            room_length_m: Room length.
            room_width_m: Room width.
            tx_pos: (x, y) position of transmitter.
            rx_pos: (x, y) position of receiver.
            body_pos: (x, y) position of the body to detect.
            wall_materials: List of (material_name, thickness_m) for walls between TX/RX.
            freq_mhz: Frequency in MHz.

        Returns:
            Dict with sensing effectiveness metrics.
        """
        freq = freq_mhz or self._config.default_freq_mhz

        # Distances
        d_tx = math.sqrt((body_pos[0] - tx_pos[0]) ** 2 + (body_pos[1] - tx_pos[1]) ** 2)
        d_rx = math.sqrt((body_pos[0] - rx_pos[0]) ** 2 + (body_pos[1] - rx_pos[1]) ** 2)
        d_tx = max(d_tx, 0.1)
        d_rx = max(d_rx, 0.1)

        # Fresnel zone at body position
        fz_r = fresnel_radius(freq, d_tx, d_rx, 1)

        # CSI perturbation from body
        amp_db, phase_rad = csi_perturbation_estimate(freq, d_tx, d_rx)

        # Wall attenuation (reduces signal strength and sensing ability)
        wall_atten_db = 0.0
        if wall_materials:
            for mat_name, thickness in wall_materials:
                wall_atten_db += material_attenuation_db(mat_name, thickness, freq)

        # Effective CSI change after wall attenuation
        # Higher wall attenuation means the body's CSI perturbation is harder to detect
        # SNR of body perturbation decreases with wall attenuation
        body_signal_db = abs(amp_db)
        effective_snr_db = body_signal_db - wall_atten_db * 0.3  # partial correlation

        # Sensing effectiveness: 1.0 = trivially detectable, 0.0 = undetectable
        if effective_snr_db <= 0:
            effectiveness = 0.0
        elif effective_snr_db >= 20:
            effectiveness = 1.0
        else:
            effectiveness = effective_snr_db / 20.0

        # Capability estimates
        can_detect_presence = effectiveness > 0.2
        can_detect_motion = effectiveness > 0.4
        can_detect_breathing = effectiveness > 0.6
        can_detect_heartbeat = effectiveness > 0.8

        return {
            "effectiveness": round(effectiveness, 3),
            "fresnel_radius_m": round(fz_r, 4),
            "body_perturbation_db": round(amp_db, 2),
            "body_phase_shift_rad": round(phase_rad, 4),
            "wall_attenuation_db": round(wall_atten_db, 2),
            "effective_snr_db": round(effective_snr_db, 2),
            "can_detect_presence": can_detect_presence,
            "can_detect_motion": can_detect_motion,
            "can_detect_breathing": can_detect_breathing,
            "can_detect_heartbeat": can_detect_heartbeat,
        }

    def compare_defense_strategies(
        self,
        room_length_m: float,
        room_width_m: float,
        strategies: list[dict],
        freq_mhz: float | None = None,
    ) -> list[dict]:
        """Compare multiple defense strategies for a room.

        Each strategy is a dict with:
        - name: Strategy name
        - wall_materials: List of (material, thickness) tuples

        Returns list of strategy results sorted by effectiveness (lower = better defense).
        """
        freq = freq_mhz or self._config.default_freq_mhz

        # Standard test positions
        tx_pos = (0.0, 0.0)
        rx_pos = (room_length_m, room_width_m)
        body_pos = (room_length_m / 2, room_width_m / 2)

        results = []
        for strategy in strategies:
            sim = self.simulate_sensing_effectiveness(
                room_length_m=room_length_m,
                room_width_m=room_width_m,
                tx_pos=tx_pos,
                rx_pos=rx_pos,
                body_pos=body_pos,
                wall_materials=strategy.get("wall_materials"),
                freq_mhz=freq,
            )
            results.append({
                "strategy": strategy["name"],
                "effectiveness": sim["effectiveness"],
                "wall_attenuation_db": sim["wall_attenuation_db"],
                "can_detect_heartbeat": sim["can_detect_heartbeat"],
                "can_detect_breathing": sim["can_detect_breathing"],
                "can_detect_motion": sim["can_detect_motion"],
                "can_detect_presence": sim["can_detect_presence"],
            })

        # Sort by effectiveness (lower = better defense)
        results.sort(key=lambda r: r["effectiveness"])
        return results
