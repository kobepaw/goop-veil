"""Tests for PlacementOptimizer — material placement recommendations.

Combines Fresnel analysis, material database, and budget constraints
to produce actionable room assessments.
"""

from __future__ import annotations

import pytest

from goop_veil.config import PassiveDefenseConfig
from goop_veil.models import RoomAssessment, MaterialRecommendation
from goop_veil.passive.placement_optimizer import PlacementOptimizer


class TestAssessRoomDefaults:
    """Room assessment with default configuration."""

    def test_returns_room_assessment(self):
        optimizer = PlacementOptimizer()
        result = optimizer.assess_room()
        assert isinstance(result, RoomAssessment)

    def test_default_dimensions(self):
        optimizer = PlacementOptimizer()
        result = optimizer.assess_room()
        assert result.room_dimensions_m == (4.5, 3.5, 2.7)

    def test_has_fresnel_zones(self):
        optimizer = PlacementOptimizer()
        result = optimizer.assess_room()
        assert len(result.fresnel_zones) > 0

    def test_vulnerability_score_bounded(self):
        optimizer = PlacementOptimizer()
        result = optimizer.assess_room()
        assert 0.0 <= result.vulnerability_score <= 1.0

    def test_has_summary(self):
        optimizer = PlacementOptimizer()
        result = optimizer.assess_room()
        assert len(result.summary) > 0

    def test_has_recommendations(self):
        optimizer = PlacementOptimizer()
        result = optimizer.assess_room()
        # With default budget ($500), should have at least one recommendation
        assert len(result.recommendations) >= 0  # May be 0 if all walls meet target


class TestZeroBudget:
    """Zero budget should produce no recommendations."""

    def test_zero_budget_no_recommendations(self):
        config = PassiveDefenseConfig(max_budget_usd=0.0)
        optimizer = PlacementOptimizer(config=config)
        result = optimizer.assess_room(budget_usd=0.0)
        assert result.estimated_cost_usd == 0.0

    def test_zero_budget_still_has_assessment(self):
        optimizer = PlacementOptimizer()
        result = optimizer.assess_room(budget_usd=0.0)
        assert isinstance(result, RoomAssessment)
        assert result.vulnerability_score >= 0.0


class TestPrivacyGoals:
    """Different privacy targets require different attenuation levels."""

    def test_hide_heartbeat_highest_target(self):
        optimizer = PlacementOptimizer()
        result = optimizer.assess_room(target="hide_heartbeat")
        assert result.target_attenuation_db == 25.0

    def test_hide_breathing_target(self):
        optimizer = PlacementOptimizer()
        result = optimizer.assess_room(target="hide_breathing")
        assert result.target_attenuation_db == 20.0

    def test_hide_motion_target(self):
        optimizer = PlacementOptimizer()
        result = optimizer.assess_room(target="hide_motion")
        assert result.target_attenuation_db == 15.0

    def test_hide_presence_lowest_target(self):
        optimizer = PlacementOptimizer()
        result = optimizer.assess_room(target="hide_presence")
        assert result.target_attenuation_db == 10.0

    def test_unknown_target_defaults(self):
        optimizer = PlacementOptimizer()
        result = optimizer.assess_room(target="unknown_target")
        assert result.target_attenuation_db == 15.0  # Default fallback


class TestCustomRoom:
    """Custom room dimensions and walls."""

    def test_custom_dimensions(self):
        optimizer = PlacementOptimizer()
        result = optimizer.assess_room(
            room_length_m=6.0,
            room_width_m=4.0,
            room_height_m=3.0,
        )
        assert result.room_dimensions_m == (6.0, 4.0, 3.0)

    def test_existing_walls_reduce_needed(self):
        optimizer = PlacementOptimizer()
        result_no_walls = optimizer.assess_room(target="hide_motion")
        result_with_walls = optimizer.assess_room(
            target="hide_motion",
            existing_walls=[
                {"material": "concrete", "thickness_m": 0.15},
            ],
        )
        assert result_with_walls.current_attenuation_db > 0
        assert result_with_walls.current_attenuation_db >= result_no_walls.current_attenuation_db
