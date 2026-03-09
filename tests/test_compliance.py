"""Tests for FCC compliance constants and terminology enforcement.

Validates FCC Part 15.247 constants, channel lists, privacy targets,
legitimate functions, and prohibited term detection.
"""

from __future__ import annotations

import pytest

from goop_veil.compliance import (
    APPROVED_TERMINOLOGY,
    AUDIT_BLOCK_SIZE,
    AUDIT_FIELDS,
    AUDIT_RETENTION_DAYS,
    FIRMWARE_RULES,
    HARDWARE_PA_CUTOFF_DBM,
    MAX_CHANNEL_UTILIZATION_PCT,
    MAX_CONDUCTED_POWER_DBM,
    MAX_EIRP_DBM,
    PROHIBITED_TERMS,
    TARGET_MIN_POWER_DBM,
    TARGET_SAFETY_MARGIN_DB,
    US_ALLOWED_CHANNELS,
    LegitimateFunction,
    PrivacyTarget,
    check_term_compliance,
)


# ---------------------------------------------------------------------------
# FCC Constants
# ---------------------------------------------------------------------------


class TestFCCConstants:
    """FCC Part 15.247 power and channel limits."""

    def test_max_eirp(self):
        assert MAX_EIRP_DBM == 36.0

    def test_max_conducted_power(self):
        assert MAX_CONDUCTED_POWER_DBM == 20.0

    def test_hardware_pa_cutoff(self):
        assert HARDWARE_PA_CUTOFF_DBM == 21.0

    def test_max_channel_utilization(self):
        assert MAX_CHANNEL_UTILIZATION_PCT == 7.5

    def test_conducted_below_eirp(self):
        assert MAX_CONDUCTED_POWER_DBM < MAX_EIRP_DBM

    def test_pa_cutoff_above_conducted(self):
        assert HARDWARE_PA_CUTOFF_DBM > MAX_CONDUCTED_POWER_DBM


# ---------------------------------------------------------------------------
# US Allowed Channels
# ---------------------------------------------------------------------------


class TestUSAllowedChannels:
    """US 2.4 GHz channel restrictions."""

    def test_channels_are_1_through_11(self):
        assert US_ALLOWED_CHANNELS == (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11)

    def test_channel_count(self):
        assert len(US_ALLOWED_CHANNELS) == 11

    def test_no_channel_12(self):
        assert 12 not in US_ALLOWED_CHANNELS

    def test_no_channel_13(self):
        assert 13 not in US_ALLOWED_CHANNELS

    def test_no_channel_14(self):
        assert 14 not in US_ALLOWED_CHANNELS


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class TestPrivacyTarget:
    """PrivacyTarget enum values."""

    def test_values(self):
        assert PrivacyTarget.HEARTBEAT == "heartbeat"
        assert PrivacyTarget.BREATHING == "breathing"
        assert PrivacyTarget.MOTION == "motion"
        assert PrivacyTarget.PRESENCE == "presence"

    def test_count(self):
        assert len(PrivacyTarget) == 4

    def test_min_power_mapping(self):
        """Each privacy target has an associated minimum power."""
        for target in PrivacyTarget:
            assert target in TARGET_MIN_POWER_DBM
            assert TARGET_MIN_POWER_DBM[target] <= MAX_CONDUCTED_POWER_DBM

    def test_safety_margin_mapping(self):
        for target in PrivacyTarget:
            assert target in TARGET_SAFETY_MARGIN_DB
            assert TARGET_SAFETY_MARGIN_DB[target] > 0


class TestLegitimateFunction:
    """LegitimateFunction enum values."""

    def test_ap_beacon(self):
        assert LegitimateFunction.AP_BEACON == "ap_beacon"

    def test_ftm_positioning(self):
        assert LegitimateFunction.FTM_POSITIONING == "ftm_positioning"

    def test_sensor_data(self):
        assert LegitimateFunction.SENSOR_DATA == "sensor_data"

    def test_all_values_are_strings(self):
        for func in LegitimateFunction:
            assert isinstance(func.value, str)


# ---------------------------------------------------------------------------
# check_term_compliance
# ---------------------------------------------------------------------------


class TestCheckTermCompliance:
    """Prohibited terminology detection."""

    def test_clean_text_passes(self):
        text = "This is a WiFi mesh access point for privacy enhancement."
        violations = check_term_compliance(text)
        assert violations == []

    def test_detects_jammer(self):
        violations = check_term_compliance("This is a jammer device")
        assert len(violations) >= 1
        assert any("jammer" in v.lower() for v in violations)

    def test_detects_jamming(self):
        violations = check_term_compliance("Used for jamming signals")
        assert len(violations) >= 1

    def test_detects_blocker(self):
        violations = check_term_compliance("Signal blocker installed")
        assert len(violations) >= 1

    def test_detects_interfere(self):
        violations = check_term_compliance("Will interfere with signals")
        assert len(violations) >= 1
        # "interfere" and "interference" are both in prohibited list;
        # "interfere" is a substring of "interference" so both may match
        assert any("interfere" in v.lower() for v in violations)

    def test_case_insensitive(self):
        violations = check_term_compliance("This is a JAMMER")
        assert len(violations) >= 1

    def test_detects_signal_disruptor(self):
        violations = check_term_compliance("Using a signal disruptor")
        assert len(violations) >= 1

    def test_detects_csi_countermeasure(self):
        violations = check_term_compliance("Deploy CSI countermeasure")
        assert len(violations) >= 1

    def test_multiple_violations(self):
        text = "This jammer device creates interference and disruption"
        violations = check_term_compliance(text)
        assert len(violations) >= 3

    def test_approved_terminology_exists(self):
        assert len(APPROVED_TERMINOLOGY) > 0
        assert "device" in APPROVED_TERMINOLOGY
