"""Tests for PrivacyEnhancer — ESP32 active defense controller.

Validates FCC compliance enforcement, mode management, HAL integration,
and status reporting.
"""

from __future__ import annotations

import pytest

from goop_veil.active.privacy_enhancer import PrivacyEnhancer, MODE_TARGETS
from goop_veil.compliance import MAX_CONDUCTED_POWER_DBM, US_ALLOWED_CHANNELS
from goop_veil.config import ActiveDefenseConfig
from goop_veil.hardware.esp32_hal import MockESP32HAL
from goop_veil.models import ActiveDefenseStatus, DefenseMode


class TestActivateValid:
    """Activation with valid parameters."""

    def test_activate_defaults(self):
        enhancer = PrivacyEnhancer()
        status = enhancer.activate()
        assert enhancer.is_active is True
        assert isinstance(status, ActiveDefenseStatus)

    def test_activate_returns_status(self, mock_hal):
        enhancer = PrivacyEnhancer(hal=mock_hal)
        status = enhancer.activate()
        assert status.mode == DefenseMode.VITALS_PRIVACY
        assert status.compliant is True

    def test_activate_custom_mode(self, mock_hal):
        enhancer = PrivacyEnhancer(hal=mock_hal)
        status = enhancer.activate(mode="full_privacy")
        assert enhancer.mode == DefenseMode.FULL_PRIVACY

    def test_activate_custom_power(self, mock_hal):
        enhancer = PrivacyEnhancer(hal=mock_hal)
        status = enhancer.activate(power_dbm=18.0)
        assert enhancer.is_active is True

    def test_activate_custom_channel(self, mock_hal):
        enhancer = PrivacyEnhancer(hal=mock_hal)
        status = enhancer.activate(channel=11)
        assert enhancer.is_active is True


class TestFCCPowerLimits:
    """FCC power limit enforcement."""

    def test_reject_above_20_dbm(self, mock_hal):
        enhancer = PrivacyEnhancer(hal=mock_hal)
        with pytest.raises(ValueError, match="exceeds FCC limit"):
            enhancer.activate(power_dbm=21.0)

    def test_reject_well_above_limit(self, mock_hal):
        enhancer = PrivacyEnhancer(hal=mock_hal)
        with pytest.raises(ValueError):
            enhancer.activate(power_dbm=30.0)

    def test_accept_at_limit(self, mock_hal):
        enhancer = PrivacyEnhancer(hal=mock_hal)
        status = enhancer.activate(power_dbm=20.0)
        assert enhancer.is_active is True

    def test_accept_below_limit(self, mock_hal):
        enhancer = PrivacyEnhancer(hal=mock_hal)
        status = enhancer.activate(power_dbm=5.0)
        assert enhancer.is_active is True


class TestChannelValidation:
    """US channel enforcement."""

    def test_reject_channel_12(self, mock_hal):
        enhancer = PrivacyEnhancer(hal=mock_hal)
        with pytest.raises(ValueError, match="not in US allowed"):
            enhancer.activate(channel=12)

    def test_reject_channel_13(self, mock_hal):
        enhancer = PrivacyEnhancer(hal=mock_hal)
        with pytest.raises(ValueError):
            enhancer.activate(channel=13)

    def test_reject_channel_0(self, mock_hal):
        config = ActiveDefenseConfig(channel=1)  # Valid default
        enhancer = PrivacyEnhancer(config=config, hal=mock_hal)
        with pytest.raises(ValueError):
            enhancer.activate(channel=0)

    def test_accept_all_us_channels(self, mock_hal):
        for ch in US_ALLOWED_CHANNELS:
            config = ActiveDefenseConfig(channel=ch)
            enhancer = PrivacyEnhancer(config=config, hal=mock_hal)
            status = enhancer.activate()
            assert enhancer.is_active is True


class TestDeactivate:
    """Deactivation stops the defense."""

    def test_deactivate(self, mock_hal):
        enhancer = PrivacyEnhancer(hal=mock_hal)
        enhancer.activate()
        assert enhancer.is_active is True
        status = enhancer.deactivate()
        assert enhancer.is_active is False
        assert isinstance(status, ActiveDefenseStatus)

    def test_deactivate_calls_hal_stop(self, mock_hal):
        enhancer = PrivacyEnhancer(hal=mock_hal)
        enhancer.activate()
        enhancer.deactivate()
        stop_cmds = [c for c in mock_hal.commands if c["cmd"] == "stop"]
        assert len(stop_cmds) >= 1


class TestStatusReporting:
    """Status reflects current state."""

    def test_status_inactive(self):
        enhancer = PrivacyEnhancer()
        status = enhancer.status()
        assert status.mesh_ap_active is False
        assert status.sensors_active is False
        assert status.uptime_sec == 0.0

    def test_status_active(self, mock_hal):
        enhancer = PrivacyEnhancer(hal=mock_hal)
        enhancer.activate()
        status = enhancer.status()
        assert status.mesh_ap_active is True
        assert status.sensors_active is True
        assert status.positioning_active is True


class TestMockHALIntegration:
    """HAL receives correct commands."""

    def test_configure_called(self, mock_hal):
        enhancer = PrivacyEnhancer(hal=mock_hal)
        enhancer.activate(power_dbm=15.0, channel=6)
        config_cmds = [c for c in mock_hal.commands if c["cmd"] == "configure"]
        assert len(config_cmds) == 1
        assert config_cmds[0]["power_dbm"] == 15.0
        assert config_cmds[0]["channel"] == 6

    def test_set_mode_called(self, mock_hal):
        enhancer = PrivacyEnhancer(hal=mock_hal)
        enhancer.activate(mode="motion_privacy")
        mode_cmds = [c for c in mock_hal.commands if c["cmd"] == "set_mode"]
        assert len(mode_cmds) == 1
        assert mode_cmds[0]["mode"] == "motion_privacy"

    def test_legitimate_functions_enabled(self, mock_hal):
        enhancer = PrivacyEnhancer(hal=mock_hal)
        enhancer.activate()
        func_cmds = [c for c in mock_hal.commands if c["cmd"] == "enable_function"]
        # Should enable at least ap_beacon, client_data, mesh_peering, ack, sensor_data, ftm
        assert len(func_cmds) >= 4

    def test_start_called(self, mock_hal):
        enhancer = PrivacyEnhancer(hal=mock_hal)
        enhancer.activate()
        start_cmds = [c for c in mock_hal.commands if c["cmd"] == "start"]
        assert len(start_cmds) == 1
