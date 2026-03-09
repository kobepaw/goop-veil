"""Placement optimizer — recommends optimal material placement for WiFi privacy.

Combines Fresnel zone analysis, material properties, and budget constraints
to produce actionable material placement recommendations.
"""

from __future__ import annotations

import logging
from typing import Any

from goop_veil._core import material_attenuation_db
from goop_veil.config import PassiveDefenseConfig
from goop_veil.models import MaterialRecommendation, RoomAssessment
from goop_veil.passive.fresnel_calculator import FresnelCalculator
from goop_veil.passive.material_database import (
    MaterialInfo,
    get_all_materials,
    get_materials_under_budget,
)

logger = logging.getLogger(__name__)


class PlacementOptimizer:
    """Optimizes material placement for maximum WiFi sensing attenuation."""

    def __init__(self, config: PassiveDefenseConfig | None = None) -> None:
        self._config = config or PassiveDefenseConfig()
        self._fresnel = FresnelCalculator(self._config)

    def assess_room(
        self,
        room_length_m: float | None = None,
        room_width_m: float | None = None,
        room_height_m: float | None = None,
        budget_usd: float | None = None,
        target: str = "hide_pose",
        existing_walls: list[dict[str, Any]] | None = None,
    ) -> RoomAssessment:
        """Assess room vulnerability and recommend material placements.

        Args:
            room_length_m: Room length in meters.
            room_width_m: Room width in meters.
            room_height_m: Room height in meters.
            budget_usd: Maximum budget in USD.
            target: Privacy target ("hide_heartbeat", "hide_breathing",
                    "hide_motion", "hide_pose", "hide_presence").
            existing_walls: List of existing wall materials and thicknesses.
        """
        length = room_length_m or self._config.default_room_length_m
        width = room_width_m or self._config.default_room_width_m
        height = room_height_m or self._config.default_room_height_m
        budget = budget_usd or self._config.max_budget_usd
        freq = self._config.default_freq_mhz

        # Target attenuation based on privacy goal
        target_db = self._target_attenuation(target)

        # Calculate current attenuation from existing walls
        current_db = 0.0
        if existing_walls:
            for wall in existing_walls:
                mat = wall.get("material", "drywall")
                thick = wall.get("thickness_m", 0.013)
                current_db += material_attenuation_db(mat, thick, freq)

        # Calculate vulnerability map
        vuln_map = self._fresnel.vulnerability_map(
            room_length_m=length,
            room_width_m=width,
            grid_resolution_m=0.5,
            freq_mhz=freq,
        )
        avg_vuln = sum(p["vulnerability"] for p in vuln_map) / max(len(vuln_map), 1)

        # Generate recommendations
        needed_db = max(0.0, target_db - current_db)
        recommendations = self._recommend_materials(
            needed_db=needed_db,
            room_area_m2=2 * (length * height + width * height),  # Wall area
            budget_usd=budget,
            freq_mhz=freq,
        )

        total_cost = sum(r.cost_usd for r in recommendations)
        achieved_db = current_db + sum(r.attenuation_db for r in recommendations)

        # Build Fresnel zone descriptions
        fz_info: list[dict[str, Any]] = []
        for i, pos in enumerate([(length / 2, 0.0), (0.0, width / 2)]):
            d_tx = (pos[0] ** 2 + pos[1] ** 2) ** 0.5
            d_rx = ((length - pos[0]) ** 2 + (width - pos[1]) ** 2) ** 0.5
            d_tx = max(d_tx, 0.1)
            d_rx = max(d_rx, 0.1)
            r = self._fresnel.zone_radius(d_tx, d_rx, freq)
            fz_info.append({
                "position": f"midpoint_{i}",
                "radius_m": round(r, 3),
                "d_tx_m": round(d_tx, 2),
                "d_rx_m": round(d_rx, 2),
            })

        summary_parts = [
            f"Room {length}x{width}x{height}m, avg vulnerability {avg_vuln:.0%}",
            f"Current attenuation: {current_db:.1f} dB, target: {target_db:.1f} dB",
        ]
        if recommendations:
            summary_parts.append(
                f"{len(recommendations)} material recommendations, "
                f"estimated cost: ${total_cost:.0f}"
            )
        else:
            summary_parts.append("Current walls already meet target attenuation")

        return RoomAssessment(
            room_dimensions_m=(length, width, height),
            frequency_mhz=freq,
            fresnel_zones=fz_info,
            vulnerability_score=round(avg_vuln, 2),
            current_attenuation_db=round(current_db, 1),
            target_attenuation_db=target_db,
            recommendations=recommendations,
            estimated_cost_usd=round(total_cost, 2),
            summary="; ".join(summary_parts),
        )

    def _recommend_materials(
        self,
        needed_db: float,
        room_area_m2: float,
        budget_usd: float,
        freq_mhz: float,
    ) -> list[MaterialRecommendation]:
        """Generate material recommendations to achieve target attenuation."""
        if needed_db <= 0:
            return []

        affordable = get_materials_under_budget(room_area_m2, budget_usd)
        if not affordable:
            affordable = get_all_materials()

        recommendations: list[MaterialRecommendation] = []
        remaining_db = needed_db
        remaining_budget = budget_usd
        priority = 1

        # Sort by cost-effectiveness (dB per dollar)
        def effectiveness(m: MaterialInfo) -> float:
            atten = material_attenuation_db(m.material_key, m.typical_thickness_m, freq_mhz)
            cost = m.cost_per_m2_usd * room_area_m2
            return atten / max(cost, 0.01)

        sorted_materials = sorted(affordable, key=effectiveness, reverse=True)

        for mat in sorted_materials:
            if remaining_db <= 0 or remaining_budget <= 0:
                break

            atten = material_attenuation_db(mat.material_key, mat.typical_thickness_m, freq_mhz)
            cost = mat.cost_per_m2_usd * room_area_m2

            if cost > remaining_budget:
                continue

            # Determine location based on material type
            location = self._suggest_location(mat)

            recommendations.append(
                MaterialRecommendation(
                    material=mat.display_name,
                    thickness_m=mat.typical_thickness_m,
                    area_m2=round(room_area_m2, 1),
                    attenuation_db=round(atten, 1),
                    cost_usd=round(cost, 2),
                    location=location,
                    priority=priority,
                )
            )
            remaining_db -= atten
            remaining_budget -= cost
            priority += 1

        return recommendations

    @staticmethod
    def _target_attenuation(target: str) -> float:
        """Get target attenuation in dB for a privacy goal."""
        targets = {
            "hide_heartbeat": 25.0,  # Most difficult to mask
            "hide_breathing": 20.0,
            "hide_motion": 15.0,
            "hide_pose": 12.0,
            "hide_presence": 10.0,
        }
        return targets.get(target, 15.0)

    @staticmethod
    def _suggest_location(material: MaterialInfo) -> str:
        """Suggest installation location based on material type."""
        if "window" in material.name or "film" in material.name:
            return "windows"
        elif "foil" in material.name or "mesh" in material.name:
            return "wall_interior"
        elif "paint" in material.name:
            return "wall_surface"
        elif "water" in material.name:
            return "room_center"
        elif "insulation" in material.name:
            return "wall_cavity"
        return "walls"
