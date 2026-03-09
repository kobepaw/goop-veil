"""Compliance monitor — verifies all active defense operations meet FCC requirements.

Validates power levels, channel usage, frame types, and channel utilization
in real-time. Any violation triggers immediate shutdown.
"""

from __future__ import annotations

import logging
from datetime import datetime

from goop_veil.compliance import (
    FIRMWARE_RULES,
    HARDWARE_PA_CUTOFF_DBM,
    MAX_CHANNEL_UTILIZATION_PCT,
    MAX_CONDUCTED_POWER_DBM,
    US_ALLOWED_CHANNELS,
)
from goop_veil.models import AlertSeverity, VeilAlert

logger = logging.getLogger(__name__)


class ComplianceViolation:
    """A detected compliance violation."""

    __slots__ = ("rule", "measured_value", "limit_value", "timestamp", "description")

    def __init__(
        self,
        rule: str,
        measured_value: float,
        limit_value: float,
        description: str,
    ) -> None:
        self.rule = rule
        self.measured_value = measured_value
        self.limit_value = limit_value
        self.timestamp = datetime.now()
        self.description = description


class ComplianceMonitor:
    """Monitors active defense for FCC compliance violations."""

    def __init__(self, hal: object | None = None) -> None:
        self._hal = hal
        self._violations: list[ComplianceViolation] = []
        self._check_count = 0

    @property
    def violations(self) -> list[ComplianceViolation]:
        return list(self._violations)

    @property
    def is_compliant(self) -> bool:
        return len(self._violations) == 0

    def check_power(self, measured_power_dbm: float) -> bool:
        """Verify transmitted power is within FCC limits.

        Returns True if compliant.
        """
        self._check_count += 1

        if measured_power_dbm > MAX_CONDUCTED_POWER_DBM:
            violation = ComplianceViolation(
                rule="max_conducted_power",
                measured_value=measured_power_dbm,
                limit_value=MAX_CONDUCTED_POWER_DBM,
                description=(
                    f"Conducted power {measured_power_dbm:.1f} dBm exceeds "
                    f"FCC limit of {MAX_CONDUCTED_POWER_DBM:.1f} dBm"
                ),
            )
            self._violations.append(violation)
            logger.critical("COMPLIANCE VIOLATION: %s", violation.description)
            self._emergency_shutdown()
            return False

        if measured_power_dbm > HARDWARE_PA_CUTOFF_DBM:
            violation = ComplianceViolation(
                rule="hardware_pa_cutoff",
                measured_value=measured_power_dbm,
                limit_value=HARDWARE_PA_CUTOFF_DBM,
                description=(
                    f"Power {measured_power_dbm:.1f} dBm exceeds "
                    f"hardware PA cutoff of {HARDWARE_PA_CUTOFF_DBM:.1f} dBm"
                ),
            )
            self._violations.append(violation)
            logger.critical("COMPLIANCE VIOLATION: %s", violation.description)
            self._emergency_shutdown()
            return False

        return True

    def check_channel(self, channel: int) -> bool:
        """Verify transmission is on a US-allowed channel."""
        self._check_count += 1

        if channel not in US_ALLOWED_CHANNELS:
            violation = ComplianceViolation(
                rule="allowed_channels",
                measured_value=float(channel),
                limit_value=11.0,
                description=f"Channel {channel} not in US allowed set {US_ALLOWED_CHANNELS}",
            )
            self._violations.append(violation)
            logger.critical("COMPLIANCE VIOLATION: %s", violation.description)
            self._emergency_shutdown()
            return False

        return True

    def check_utilization(self, utilization_pct: float) -> bool:
        """Verify channel utilization is within acceptable limits."""
        self._check_count += 1

        if utilization_pct > MAX_CHANNEL_UTILIZATION_PCT:
            violation = ComplianceViolation(
                rule="max_utilization",
                measured_value=utilization_pct,
                limit_value=MAX_CHANNEL_UTILIZATION_PCT,
                description=(
                    f"Channel utilization {utilization_pct:.1f}% exceeds "
                    f"limit of {MAX_CHANNEL_UTILIZATION_PCT:.1f}%"
                ),
            )
            self._violations.append(violation)
            logger.warning("COMPLIANCE WARNING: %s", violation.description)
            return False

        return True

    def check_frame_type(self, frame_type: int, frame_subtype: int, dest_mac: str) -> bool:
        """Verify frame type compliance (no deauth/disassoc to non-own BSS)."""
        self._check_count += 1

        # Management frame type = 0, deauth subtype = 12, disassoc subtype = 10
        is_deauth = frame_type == 0 and frame_subtype == 12
        is_disassoc = frame_type == 0 and frame_subtype == 10
        is_broadcast = dest_mac == "ff:ff:ff:ff:ff:ff"

        if (is_deauth or is_disassoc) and not is_broadcast:
            violation = ComplianceViolation(
                rule="no_deauth_to_others",
                measured_value=float(frame_subtype),
                limit_value=0.0,
                description=(
                    f"Deauth/disassoc frame (subtype={frame_subtype}) "
                    f"directed to {dest_mac}"
                ),
            )
            self._violations.append(violation)
            logger.critical("COMPLIANCE VIOLATION: %s", violation.description)
            self._emergency_shutdown()
            return False

        return True

    def to_alert(self) -> VeilAlert | None:
        """Convert most recent violation to a VeilAlert."""
        if not self._violations:
            return None
        v = self._violations[-1]
        return VeilAlert(
            severity=AlertSeverity.CRITICAL,
            category="compliance",
            title=f"FCC compliance violation: {v.rule}",
            description=v.description,
            source="compliance_monitor",
            metadata={
                "rule": v.rule,
                "measured": v.measured_value,
                "limit": v.limit_value,
            },
        )

    def _emergency_shutdown(self) -> None:
        """Immediately shut down all transmissions."""
        logger.critical("EMERGENCY SHUTDOWN — compliance violation detected")
        if self._hal is not None:
            try:
                self._hal.stop()
            except Exception:
                logger.exception("Failed to stop HAL during emergency shutdown")

    def reset(self) -> None:
        self._violations.clear()
        self._check_count = 0
