"""Tests for FresnelCalculator — Fresnel zone physics for room vulnerability.

Wraps Rust core functions for zone radius, body impact, material protection,
and vulnerability map generation.
"""

from __future__ import annotations

import math

import pytest

from goop_veil.config import PassiveDefenseConfig
from goop_veil.passive.fresnel_calculator import FresnelCalculator


class TestZoneRadius:
    """Fresnel zone radius calculation."""

    def test_basic_radius(self):
        calc = FresnelCalculator()
        r = calc.zone_radius(d_tx_m=5.0, d_rx_m=5.0)
        # At 2437 MHz, 5m each -> r ~ 0.55m
        assert 0.45 < r < 0.65

    def test_asymmetric_smaller_near_endpoint(self):
        calc = FresnelCalculator()
        r_mid = calc.zone_radius(d_tx_m=5.0, d_rx_m=5.0)
        r_near = calc.zone_radius(d_tx_m=1.0, d_rx_m=9.0)
        assert r_mid > r_near

    def test_higher_freq_smaller_radius(self):
        calc = FresnelCalculator()
        r_24 = calc.zone_radius(d_tx_m=5.0, d_rx_m=5.0, freq_mhz=2437.0)
        r_50 = calc.zone_radius(d_tx_m=5.0, d_rx_m=5.0, freq_mhz=5200.0)
        assert r_50 < r_24

    def test_uses_config_default_freq(self):
        config = PassiveDefenseConfig(default_freq_mhz=5200.0)
        calc = FresnelCalculator(config=config)
        r = calc.zone_radius(d_tx_m=5.0, d_rx_m=5.0)
        r_explicit = calc.zone_radius(d_tx_m=5.0, d_rx_m=5.0, freq_mhz=5200.0)
        assert abs(r - r_explicit) < 1e-10

    def test_second_zone_larger(self):
        calc = FresnelCalculator()
        r1 = calc.zone_radius(d_tx_m=5.0, d_rx_m=5.0, zone_n=1)
        r2 = calc.zone_radius(d_tx_m=5.0, d_rx_m=5.0, zone_n=2)
        assert r2 > r1


class TestBodyImpact:
    """Body impact estimation."""

    def test_returns_correct_keys(self):
        calc = FresnelCalculator()
        impact = calc.body_impact(d_tx_m=3.0, d_rx_m=3.0)
        expected_keys = {
            "fresnel_radius_m",
            "intersection_area_m2",
            "blocked_fraction",
            "amplitude_change_db",
            "phase_shift_rad",
        }
        assert set(impact.keys()) == expected_keys

    def test_amplitude_negative(self):
        calc = FresnelCalculator()
        impact = calc.body_impact(d_tx_m=3.0, d_rx_m=3.0)
        assert impact["amplitude_change_db"] < 0

    def test_phase_shift_positive(self):
        calc = FresnelCalculator()
        impact = calc.body_impact(d_tx_m=3.0, d_rx_m=3.0)
        assert impact["phase_shift_rad"] > 0

    def test_blocked_fraction_between_0_and_1(self):
        calc = FresnelCalculator()
        impact = calc.body_impact(d_tx_m=3.0, d_rx_m=3.0)
        assert 0.0 <= impact["blocked_fraction"] <= 1.0


class TestMaterialProtection:
    """Material attenuation calculation."""

    def test_concrete_more_than_drywall(self):
        calc = FresnelCalculator()
        concrete = calc.material_protection("concrete", 0.15)
        drywall = calc.material_protection("drywall", 0.013)
        assert concrete > drywall

    def test_metal_high_attenuation(self):
        calc = FresnelCalculator()
        metal = calc.material_protection("metal", 0.001)
        assert metal > 0.01

    def test_zero_thickness_zero_attenuation(self):
        calc = FresnelCalculator()
        atten = calc.material_protection("drywall", 0.0)
        assert atten == 0.0


class TestVulnerabilityMap:
    """Grid-based vulnerability map generation."""

    def test_map_has_points(self):
        calc = FresnelCalculator()
        grid = calc.vulnerability_map(
            room_length_m=4.0,
            room_width_m=3.0,
            grid_resolution_m=1.0,
        )
        assert len(grid) > 0

    def test_grid_point_keys(self):
        calc = FresnelCalculator()
        grid = calc.vulnerability_map(
            room_length_m=4.0,
            room_width_m=3.0,
            grid_resolution_m=1.0,
        )
        for point in grid:
            assert "x" in point
            assert "y" in point
            assert "vulnerability" in point

    def test_vulnerability_bounded(self):
        calc = FresnelCalculator()
        grid = calc.vulnerability_map(
            room_length_m=4.0,
            room_width_m=3.0,
            grid_resolution_m=1.0,
        )
        for point in grid:
            assert 0.0 <= point["vulnerability"] <= 1.0

    def test_finer_grid_more_points(self):
        calc = FresnelCalculator()
        coarse = calc.vulnerability_map(room_length_m=4.0, room_width_m=3.0,
                                        grid_resolution_m=2.0)
        fine = calc.vulnerability_map(room_length_m=4.0, room_width_m=3.0,
                                      grid_resolution_m=0.5)
        assert len(fine) > len(coarse)
