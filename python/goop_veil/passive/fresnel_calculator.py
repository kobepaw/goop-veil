"""Fresnel calculator — thin Python wrapper over Rust core Fresnel zone physics.

Provides high-level room analysis using the fast Rust implementations of:
- Fresnel zone radius calculation
- Body intersection area estimation
- CSI perturbation magnitude estimation
"""

from __future__ import annotations

import logging

from goop_veil._core import (
    body_intersection_area,
    csi_perturbation_estimate,
    fresnel_radius,
    material_attenuation_db,
)
from goop_veil.config import PassiveDefenseConfig

logger = logging.getLogger(__name__)


class FresnelCalculator:
    """High-level Fresnel zone analysis for room vulnerability assessment."""

    def __init__(self, config: PassiveDefenseConfig | None = None) -> None:
        self._config = config or PassiveDefenseConfig()

    def zone_radius(
        self,
        d_tx_m: float,
        d_rx_m: float,
        freq_mhz: float | None = None,
        zone_n: int = 1,
    ) -> float:
        """Calculate nth Fresnel zone radius at a point between TX and RX."""
        freq = freq_mhz or self._config.default_freq_mhz
        return fresnel_radius(freq, d_tx_m, d_rx_m, zone_n)

    def body_impact(
        self,
        d_tx_m: float,
        d_rx_m: float,
        freq_mhz: float | None = None,
        body_width_m: float = 0.4,
        body_depth_m: float = 0.25,
    ) -> dict[str, float]:
        """Estimate impact of a human body on WiFi CSI at a given position.

        Returns dict with:
        - fresnel_radius_m: First Fresnel zone radius at body position
        - intersection_area_m2: Cross-section of body in Fresnel zone
        - blocked_fraction: Fraction of Fresnel zone blocked
        - amplitude_change_db: Expected signal amplitude change (negative)
        - phase_shift_rad: Expected phase shift (radians)
        """
        freq = freq_mhz or self._config.default_freq_mhz
        fz_r = fresnel_radius(freq, d_tx_m, d_rx_m, 1)
        intersect = body_intersection_area(fz_r, body_width_m, body_depth_m)
        import math

        fz_area = math.pi * fz_r * fz_r
        blocked = intersect / fz_area if fz_area > 0 else 0.0

        amp_db, phase_rad = csi_perturbation_estimate(
            freq, d_tx_m, d_rx_m, body_width_m, body_depth_m
        )

        return {
            "fresnel_radius_m": round(fz_r, 4),
            "intersection_area_m2": round(intersect, 6),
            "blocked_fraction": round(blocked, 4),
            "amplitude_change_db": round(amp_db, 2),
            "phase_shift_rad": round(phase_rad, 4),
        }

    def material_protection(
        self,
        material: str,
        thickness_m: float,
        freq_mhz: float | None = None,
    ) -> float:
        """Calculate attenuation provided by a material layer (dB)."""
        freq = freq_mhz or self._config.default_freq_mhz
        return material_attenuation_db(material, thickness_m, freq)

    def vulnerability_map(
        self,
        room_length_m: float | None = None,
        room_width_m: float | None = None,
        tx_positions: list[tuple[float, float]] | None = None,
        rx_positions: list[tuple[float, float]] | None = None,
        grid_resolution_m: float = 0.5,
        freq_mhz: float | None = None,
    ) -> list[dict[str, float]]:
        """Generate a vulnerability map showing CSI sensitivity across a room.

        Returns list of grid points with vulnerability scores.
        """
        length = room_length_m or self._config.default_room_length_m
        width = room_width_m or self._config.default_room_width_m
        freq = freq_mhz or self._config.default_freq_mhz

        # Default: TX and RX at opposite corners (worst case for whole-room sensing)
        if tx_positions is None:
            tx_positions = [(0.0, 0.0)]
        if rx_positions is None:
            rx_positions = [(length, width)]

        grid: list[dict[str, float]] = []
        x = grid_resolution_m / 2
        while x < length:
            y = grid_resolution_m / 2
            while y < width:
                max_blocked = 0.0
                for tx_x, tx_y in tx_positions:
                    for rx_x, rx_y in rx_positions:
                        d_tx = ((x - tx_x) ** 2 + (y - tx_y) ** 2) ** 0.5
                        d_rx = ((x - rx_x) ** 2 + (y - rx_y) ** 2) ** 0.5
                        # Avoid division by zero near endpoints
                        d_tx = max(d_tx, 0.1)
                        d_rx = max(d_rx, 0.1)
                        impact = self.body_impact(d_tx, d_rx, freq)
                        max_blocked = max(max_blocked, impact["blocked_fraction"])

                grid.append({
                    "x": round(x, 2),
                    "y": round(y, 2),
                    "vulnerability": round(max_blocked, 4),
                })
                y += grid_resolution_m
            x += grid_resolution_m

        return grid
