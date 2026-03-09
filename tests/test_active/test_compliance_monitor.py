"""Tests for ComplianceMonitor — real-time FCC compliance verification.

Validates power checks, channel checks, utilization limits, frame type
restrictions, emergency shutdown, and alert generation.
"""

from __future__ import annotations

import pytest

from goop_veil.active.compliance_monitor import ComplianceMonitor, ComplianceViolation
from goop_veil.compliance import (
    HARDWARE_PA_CUTOFF_DBM,
    MAX_CHANNEL_UTILIZATION_PCT,
    MAX_CONDUCTED_POWER_DBM,
    US_ALLOWED_CHANNELS,
)
from goop_veil.hardware.esp32_hal import MockESP32HAL
from goop_veil.models import AlertSeverity


class TestPowerCheck:
    """Conducted power verification."""

    def test_power_within_limit(self):
        monitor = ComplianceMonitor()
        assert monitor.check_power(15.0) is True
        assert monitor.is_compliant is True

    def test_power_at_limit(self):
        monitor = ComplianceMonitor()
        assert monitor.check_power(MAX_CONDUCTED_POWER_DBM) is True

    def test_power_exceeds_limit(self):
        monitor = ComplianceMonitor()
        assert monitor.check_power(22.0) is False
        assert monitor.is_compliant is False
        assert len(monitor.violations) >= 1

    def test_power_exceeds_pa_cutoff(self):
        monitor = ComplianceMonitor()
        assert monitor.check_power(HARDWARE_PA_CUTOFF_DBM + 1.0) is False

    def test_power_between_conducted_and_pa(self):
        """Power above 20 dBm triggers violation even if below PA cutoff."""
        monitor = ComplianceMonitor()
        assert monitor.check_power(20.5) is False


class TestChannelCheck:
    """Channel validation."""

    def test_valid_channels_pass(self):
        for ch in US_ALLOWED_CHANNELS:
            monitor = ComplianceMonitor()
            assert monitor.check_channel(ch) is True

    def test_channel_12_fails(self):
        monitor = ComplianceMonitor()
        assert monitor.check_channel(12) is False
        assert monitor.is_compliant is False

    def test_channel_13_fails(self):
        monitor = ComplianceMonitor()
        assert monitor.check_channel(13) is False

    def test_channel_0_fails(self):
        monitor = ComplianceMonitor()
        assert monitor.check_channel(0) is False


class TestUtilizationCheck:
    """Channel utilization verification."""

    def test_utilization_within_limit(self):
        monitor = ComplianceMonitor()
        assert monitor.check_utilization(5.0) is True

    def test_utilization_at_limit(self):
        monitor = ComplianceMonitor()
        assert monitor.check_utilization(MAX_CHANNEL_UTILIZATION_PCT) is True

    def test_utilization_exceeds_limit(self):
        monitor = ComplianceMonitor()
        assert monitor.check_utilization(10.0) is False
        assert len(monitor.violations) == 1


class TestFrameTypeCheck:
    """Frame type compliance (no deauth/disassoc to non-own BSS)."""

    def test_normal_data_frame_passes(self):
        monitor = ComplianceMonitor()
        assert monitor.check_frame_type(2, 0, "11:22:33:44:55:66") is True

    def test_deauth_to_unicast_fails(self):
        """Deauth (management type=0, subtype=12) to unicast is a violation."""
        monitor = ComplianceMonitor()
        assert monitor.check_frame_type(0, 12, "11:22:33:44:55:66") is False
        assert len(monitor.violations) == 1

    def test_disassoc_to_unicast_fails(self):
        """Disassoc (management type=0, subtype=10) to unicast is a violation."""
        monitor = ComplianceMonitor()
        assert monitor.check_frame_type(0, 10, "11:22:33:44:55:66") is False

    def test_deauth_to_broadcast_passes(self):
        """Deauth to broadcast (own BSS management) is allowed."""
        monitor = ComplianceMonitor()
        assert monitor.check_frame_type(0, 12, "ff:ff:ff:ff:ff:ff") is True

    def test_beacon_frame_passes(self):
        """Beacon frame (type=0, subtype=8) always passes."""
        monitor = ComplianceMonitor()
        assert monitor.check_frame_type(0, 8, "ff:ff:ff:ff:ff:ff") is True


class TestEmergencyShutdown:
    """Emergency shutdown on violation."""

    def test_power_violation_calls_hal_stop(self):
        hal = MockESP32HAL()
        monitor = ComplianceMonitor(hal=hal)
        monitor.check_power(25.0)
        stop_cmds = [c for c in hal.commands if c["cmd"] == "stop"]
        assert len(stop_cmds) >= 1

    def test_channel_violation_calls_hal_stop(self):
        hal = MockESP32HAL()
        monitor = ComplianceMonitor(hal=hal)
        monitor.check_channel(12)
        stop_cmds = [c for c in hal.commands if c["cmd"] == "stop"]
        assert len(stop_cmds) >= 1


class TestAlertGeneration:
    """Compliance violations generate alerts."""

    def test_no_violation_no_alert(self):
        monitor = ComplianceMonitor()
        assert monitor.to_alert() is None

    def test_power_violation_alert(self):
        monitor = ComplianceMonitor()
        monitor.check_power(25.0)
        alert = monitor.to_alert()
        assert alert is not None
        assert alert.severity == AlertSeverity.CRITICAL
        assert alert.category == "compliance"
        assert "max_conducted_power" in alert.title

    def test_alert_has_metadata(self):
        monitor = ComplianceMonitor()
        monitor.check_power(22.0)
        alert = monitor.to_alert()
        assert alert is not None
        assert alert.metadata["rule"] == "max_conducted_power"
        assert alert.metadata["measured"] == 22.0


class TestReset:
    """Reset clears all violations."""

    def test_reset_clears_violations(self):
        monitor = ComplianceMonitor()
        monitor.check_power(25.0)
        assert not monitor.is_compliant
        monitor.reset()
        assert monitor.is_compliant
        assert len(monitor.violations) == 0
