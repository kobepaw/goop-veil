"""Tests for VeilConfig and sub-configuration models.

Validates frozen behavior, extra="forbid", field validation, defaults,
and file loading. Follows goop ecosystem ConfigDict pattern.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest
from pydantic import ValidationError

from goop_veil.config import (
    ActiveDefenseConfig,
    AdversarialConfig,
    DetectionConfig,
    PassiveDefenseConfig,
    VeilConfig,
)


# ---------------------------------------------------------------------------
# VeilConfig defaults and structure
# ---------------------------------------------------------------------------


class TestVeilConfigDefaults:
    """VeilConfig creation with default values."""

    def test_default_creation(self):
        cfg = VeilConfig()
        assert cfg.log_level == "INFO"
        assert cfg.data_dir == "data"

    def test_has_all_subsections(self):
        cfg = VeilConfig()
        assert isinstance(cfg.detection, DetectionConfig)
        assert isinstance(cfg.passive, PassiveDefenseConfig)
        assert isinstance(cfg.active, ActiveDefenseConfig)
        assert isinstance(cfg.adversarial, AdversarialConfig)

    def test_default_detection_values(self):
        cfg = VeilConfig()
        assert cfg.detection.beacon_anomaly_threshold == 0.7
        assert cfg.detection.espressif_device_threshold == 2
        assert cfg.detection.channel_hop_window_sec == 10.0
        assert cfg.detection.channel_hop_threshold == 5
        assert cfg.detection.csi_snr_threshold_db == 6.0
        assert cfg.detection.csi_sample_rate_hz == 100.0

    def test_default_active_values(self):
        cfg = VeilConfig()
        assert cfg.active.default_power_dbm == 15.0
        assert cfg.active.channel == 6
        assert cfg.active.max_utilization_pct == 7.5
        assert cfg.active.mode == "vitals_privacy"


# ---------------------------------------------------------------------------
# Frozen (immutable) behavior
# ---------------------------------------------------------------------------


class TestFrozenBehavior:
    """Models must be immutable after creation."""

    def test_veil_config_frozen(self):
        cfg = VeilConfig()
        with pytest.raises(ValidationError):
            cfg.log_level = "DEBUG"

    def test_detection_config_frozen(self):
        cfg = DetectionConfig()
        with pytest.raises(ValidationError):
            cfg.beacon_anomaly_threshold = 0.5

    def test_passive_config_frozen(self):
        cfg = PassiveDefenseConfig()
        with pytest.raises(ValidationError):
            cfg.default_freq_mhz = 5000.0

    def test_active_config_frozen(self):
        cfg = ActiveDefenseConfig()
        with pytest.raises(ValidationError):
            cfg.channel = 11


# ---------------------------------------------------------------------------
# Extra="forbid" behavior
# ---------------------------------------------------------------------------


class TestExtraForbid:
    """Unknown fields must be rejected."""

    def test_veil_config_extra_forbidden(self):
        with pytest.raises(ValidationError, match="extra"):
            VeilConfig(unknown_field="value")

    def test_detection_config_extra_forbidden(self):
        with pytest.raises(ValidationError, match="extra"):
            DetectionConfig(nonexistent_param=42)

    def test_active_config_extra_forbidden(self):
        with pytest.raises(ValidationError, match="extra"):
            ActiveDefenseConfig(turbo_mode=True)


# ---------------------------------------------------------------------------
# Field validation
# ---------------------------------------------------------------------------


class TestFieldValidation:
    """Pydantic field constraints are enforced."""

    def test_power_limit_upper(self):
        with pytest.raises(ValidationError):
            ActiveDefenseConfig(default_power_dbm=25.0)

    def test_power_limit_lower(self):
        with pytest.raises(ValidationError):
            ActiveDefenseConfig(default_power_dbm=-1.0)

    def test_channel_range_upper(self):
        with pytest.raises(ValidationError):
            ActiveDefenseConfig(channel=12)

    def test_channel_range_lower(self):
        with pytest.raises(ValidationError):
            ActiveDefenseConfig(channel=0)

    def test_beacon_threshold_above_one(self):
        with pytest.raises(ValidationError):
            DetectionConfig(beacon_anomaly_threshold=1.5)

    def test_beacon_threshold_below_zero(self):
        with pytest.raises(ValidationError):
            DetectionConfig(beacon_anomaly_threshold=-0.1)

    def test_brorl_learning_rate_above_one(self):
        with pytest.raises(ValidationError):
            AdversarialConfig(brorl_learning_rate=2.0)

    def test_brorl_learning_rate_zero(self):
        with pytest.raises(ValidationError):
            AdversarialConfig(brorl_learning_rate=0.0)

    def test_valid_custom_values(self):
        cfg = ActiveDefenseConfig(
            default_power_dbm=18.0,
            channel=11,
            max_utilization_pct=5.0,
        )
        assert cfg.default_power_dbm == 18.0
        assert cfg.channel == 11
        assert cfg.max_utilization_pct == 5.0


# ---------------------------------------------------------------------------
# from_file loading
# ---------------------------------------------------------------------------


class TestFromFile:
    """VeilConfig.from_file() loads JSON configuration."""

    def test_from_file_defaults(self, tmp_path):
        cfg_path = tmp_path / "config.json"
        cfg_path.write_text(json.dumps({}))
        cfg = VeilConfig.from_file(cfg_path)
        assert cfg.log_level == "INFO"

    def test_from_file_custom(self, tmp_path):
        cfg_path = tmp_path / "config.json"
        cfg_path.write_text(json.dumps({
            "log_level": "DEBUG",
            "detection": {"beacon_anomaly_threshold": 0.5},
        }))
        cfg = VeilConfig.from_file(cfg_path)
        assert cfg.log_level == "DEBUG"
        assert cfg.detection.beacon_anomaly_threshold == 0.5

    def test_from_file_invalid_rejects(self, tmp_path):
        cfg_path = tmp_path / "bad.json"
        cfg_path.write_text(json.dumps({"active": {"channel": 99}}))
        with pytest.raises(ValidationError):
            VeilConfig.from_file(cfg_path)
