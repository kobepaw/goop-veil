"""FCC compliance constants, approved terminology, and regulatory framework.

All terminology follows the federal compliance design specification.
This module enforces compliant language across the entire codebase.

Legal basis:
- FCC 47 CFR 15.5(b): No harmful interference
- FCC 47 CFR 15.247: ISM band power limits
- 47 USC 333: Protects "radio communications" (not sensing/CSI)
- FCC 47 CFR 15.3(m): "Harmful interference" protects communication, NOT sensing
"""

from __future__ import annotations

from enum import StrEnum
from typing import Final


# =============================================================================
# FCC Part 15.247 Power Limits (ISM 2.4 GHz)
# =============================================================================

#: Maximum EIRP (Effective Isotropic Radiated Power) in dBm — FCC Part 15.247
MAX_EIRP_DBM: Final[float] = 36.0  # 4 Watts

#: Maximum conducted power in dBm — firmware hardware cutoff
MAX_CONDUCTED_POWER_DBM: Final[float] = 20.0  # 100 mW

#: Hardware PA cutoff (1 dB above max to prevent accidental overshoot)
HARDWARE_PA_CUTOFF_DBM: Final[float] = 21.0

#: Maximum aggregate channel utilization (percentage)
MAX_CHANNEL_UTILIZATION_PCT: Final[float] = 7.5

#: US 2.4 GHz channels (1-11 only)
US_ALLOWED_CHANNELS: Final[tuple[int, ...]] = (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11)


# =============================================================================
# Defense Power Requirements (dBm) and Safety Margins
# =============================================================================

class PrivacyTarget(StrEnum):
    """Privacy enhancement targets with required power levels."""

    HEARTBEAT = "heartbeat"
    BREATHING = "breathing"
    MOTION = "motion"
    PRESENCE = "presence"


#: Minimum power (dBm) needed per privacy target
TARGET_MIN_POWER_DBM: Final[dict[str, float]] = {
    PrivacyTarget.HEARTBEAT: 5.0,   # 3.2 mW — 31 dB margin below FCC max
    PrivacyTarget.BREATHING: 10.0,  # 10 mW — 26 dB margin
    PrivacyTarget.MOTION: 15.0,     # 32 mW — 21 dB margin
    PrivacyTarget.PRESENCE: 18.0,   # 63 mW — 18 dB margin
}

#: Safety margin in dB below FCC maximum per target
TARGET_SAFETY_MARGIN_DB: Final[dict[str, float]] = {
    PrivacyTarget.HEARTBEAT: 31.0,
    PrivacyTarget.BREATHING: 26.0,
    PrivacyTarget.MOTION: 21.0,
    PrivacyTarget.PRESENCE: 18.0,
}


# =============================================================================
# Legitimate Functions (FCC-compliant primary purposes)
# =============================================================================

class LegitimateFunction(StrEnum):
    """Primary legitimate functions of the WiFi mesh access point."""

    AP_BEACON = "ap_beacon"
    CLIENT_DATA = "client_data"
    MESH_PEERING = "mesh_peering"
    SENSOR_DATA = "sensor_data"         # BME280 temp/humidity/pressure
    FTM_POSITIONING = "ftm_positioning"  # 802.11mc Fine Timing Measurement
    SITE_SURVEY = "site_survey"
    OCCUPANCY_COUNTING = "occupancy_counting"  # WiFi-based occupancy for HVAC
    ACK = "ack"


# =============================================================================
# Compliance Audit Trail
# =============================================================================

#: Audit log retention period in days
AUDIT_RETENTION_DAYS: Final[int] = 30

#: Number of entries per signed audit block
AUDIT_BLOCK_SIZE: Final[int] = 100

#: Required audit log fields per transmission
AUDIT_FIELDS: Final[tuple[str, ...]] = (
    "timestamp_us",         # NTP-synced, microsecond precision
    "measured_power_dbm",   # ADC measurement, not software setpoint
    "channel",
    "frame_type",
    "frame_subtype",
    "frame_length",
    "legitimate_purpose",   # LegitimateFunction tag
    "block_signature",      # Ed25519 per AUDIT_BLOCK_SIZE entries
)


# =============================================================================
# Firmware Compliance Rules
# =============================================================================

FIRMWARE_RULES: Final[tuple[str, ...]] = (
    "Never send deauth/disassoc to non-own devices",
    "Never exceed 20 dBm conducted power",
    "Never transmit outside channels 1-11 (US)",
    "Never use non-standard modulation",
    "Never transmit continuous wave (CW)",
    "Never address frames to third-party devices",
    "Never adapt power in response to detected sensing",
)


# =============================================================================
# Approved Terminology (Section 5 of compliance design)
# =============================================================================

#: Terms that MUST NEVER appear in source code, comments, docs, or UI
PROHIBITED_TERMS: Final[tuple[str, ...]] = (
    "jammer",
    "jamming",
    "blocker",
    "blocking",
    "signal disruptor",
    "anti-surveillance device",
    "defeats wifi sensing",
    "csi countermeasure",
    "interfere",
    "interference",
    "disrupt",
    "disruption",
)

#: Approved replacements for prohibited terms
APPROVED_TERMINOLOGY: Final[dict[str, str]] = {
    # What we call the device
    "device": "WiFi mesh access point",
    "system": "privacy-aware networking system",
    # What it does
    "action": "RF environment management",
    "function": "smart home sensor hub",
    "purpose": "enhanced WiFi coverage",
    # Technical terms
    "positioning": "indoor positioning system",
    "coverage": "multipath-enhanced coverage",
}

#: Approved variable/function name fragments
APPROVED_CODE_TERMS: Final[tuple[str, ...]] = (
    "privacy_enhancement",
    "rf_diversity",
    "multipath_management",
    "coverage_optimization",
    "environment_management",
)


def check_term_compliance(text: str) -> list[str]:
    """Check text for prohibited terminology.

    Returns list of violations found (empty = compliant).
    """
    violations = []
    lower = text.lower()
    for term in PROHIBITED_TERMS:
        if term in lower:
            violations.append(f"Prohibited term found: '{term}'")
    return violations
