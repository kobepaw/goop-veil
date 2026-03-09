"""Self-test — verifies privacy enhancement effectiveness via own CSI measurement.

Periodically tests whether the active defense is successfully degrading
WiFi sensing accuracy by measuring CSI from the veil's own transmissions.
"""

from __future__ import annotations

import logging
from datetime import datetime

from goop_veil.config import AdversarialConfig
from goop_veil.models import AlertSeverity, ThreatLevel, VeilAlert

logger = logging.getLogger(__name__)


class SelfTestResult:
    """Result of a self-test cycle."""

    __slots__ = (
        "timestamp",
        "baseline_snr_db",
        "active_snr_db",
        "degradation_db",
        "passed",
        "description",
    )

    def __init__(
        self,
        baseline_snr_db: float,
        active_snr_db: float,
        degradation_db: float,
        passed: bool,
        description: str,
    ) -> None:
        self.timestamp = datetime.now()
        self.baseline_snr_db = baseline_snr_db
        self.active_snr_db = active_snr_db
        self.degradation_db = degradation_db
        self.passed = passed
        self.description = description

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp.isoformat(),
            "baseline_snr_db": self.baseline_snr_db,
            "active_snr_db": self.active_snr_db,
            "degradation_db": self.degradation_db,
            "passed": self.passed,
            "description": self.description,
        }


class SelfTester:
    """Runs periodic self-tests to verify defense effectiveness."""

    #: Minimum SNR degradation (dB) for a passing self-test
    MIN_DEGRADATION_DB = 6.0

    def __init__(self, config: AdversarialConfig | None = None) -> None:
        self._config = config or AdversarialConfig()
        self._results: list[SelfTestResult] = []
        self._baseline_snr: float | None = None

    @property
    def results(self) -> list[SelfTestResult]:
        return list(self._results)

    @property
    def last_result(self) -> SelfTestResult | None:
        return self._results[-1] if self._results else None

    def set_baseline(self, snr_db: float) -> None:
        """Set baseline CSI SNR (measured without defense active)."""
        self._baseline_snr = snr_db
        logger.info("Self-test baseline set: %.1f dB SNR", snr_db)

    def run_test(self, measured_snr_db: float) -> SelfTestResult:
        """Run a self-test with the given CSI SNR measurement.

        Args:
            measured_snr_db: CSI SNR measured while defense is active.

        Returns:
            SelfTestResult indicating pass/fail and degradation achieved.
        """
        baseline = self._baseline_snr or 20.0  # Default baseline if not set
        degradation = baseline - measured_snr_db

        passed = degradation >= self.MIN_DEGRADATION_DB

        if passed:
            description = (
                f"Privacy enhancement effective: {degradation:.1f} dB degradation "
                f"(baseline={baseline:.1f}, active={measured_snr_db:.1f})"
            )
        else:
            description = (
                f"Privacy enhancement INSUFFICIENT: {degradation:.1f} dB degradation "
                f"(need {self.MIN_DEGRADATION_DB:.1f} dB, "
                f"baseline={baseline:.1f}, active={measured_snr_db:.1f})"
            )

        result = SelfTestResult(
            baseline_snr_db=baseline,
            active_snr_db=measured_snr_db,
            degradation_db=degradation,
            passed=passed,
            description=description,
        )
        self._results.append(result)

        if passed:
            logger.info("Self-test PASSED: %s", description)
        else:
            logger.warning("Self-test FAILED: %s", description)

        return result

    def to_alert(self) -> VeilAlert | None:
        """Generate an alert if the last self-test failed."""
        result = self.last_result
        if result is None or result.passed:
            return None

        return VeilAlert(
            severity=AlertSeverity.WARNING,
            category="self_test",
            title="Privacy enhancement self-test failed",
            description=result.description,
            source="self_tester",
            metadata=result.to_dict(),
        )
