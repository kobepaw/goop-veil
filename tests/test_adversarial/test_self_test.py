"""Tests for SelfTester — privacy enhancement effectiveness verification.

Validates pass/fail logic, degradation measurement, result tracking,
and alert generation.
"""

from __future__ import annotations

import pytest

from goop_veil.adversarial.self_test import SelfTester, SelfTestResult
from goop_veil.models import AlertSeverity, VeilAlert


class TestPassingSelfTest:
    """Self-tests that achieve sufficient degradation."""

    def test_good_degradation_passes(self):
        tester = SelfTester()
        tester.set_baseline(20.0)
        result = tester.run_test(measured_snr_db=10.0)
        # Degradation = 20 - 10 = 10 dB, minimum is 6 dB
        assert result.passed is True
        assert result.degradation_db == pytest.approx(10.0)

    def test_exact_threshold_passes(self):
        tester = SelfTester()
        tester.set_baseline(20.0)
        result = tester.run_test(measured_snr_db=14.0)
        # Degradation = 6.0 dB = exactly MIN_DEGRADATION_DB
        assert result.passed is True

    def test_result_tracked(self):
        tester = SelfTester()
        tester.set_baseline(20.0)
        tester.run_test(measured_snr_db=10.0)
        assert len(tester.results) == 1
        assert tester.last_result is not None
        assert tester.last_result.passed is True

    def test_description_mentions_effective(self):
        tester = SelfTester()
        tester.set_baseline(20.0)
        result = tester.run_test(measured_snr_db=10.0)
        assert "effective" in result.description.lower()


class TestFailingSelfTest:
    """Self-tests with insufficient degradation."""

    def test_insufficient_degradation_fails(self):
        tester = SelfTester()
        tester.set_baseline(20.0)
        result = tester.run_test(measured_snr_db=18.0)
        # Degradation = 2.0 dB < 6.0 dB minimum
        assert result.passed is False
        assert result.degradation_db == pytest.approx(2.0)

    def test_no_degradation_fails(self):
        tester = SelfTester()
        tester.set_baseline(15.0)
        result = tester.run_test(measured_snr_db=15.0)
        assert result.passed is False
        assert result.degradation_db == pytest.approx(0.0)

    def test_negative_degradation_fails(self):
        """If SNR increases (defense making things worse), should fail."""
        tester = SelfTester()
        tester.set_baseline(10.0)
        result = tester.run_test(measured_snr_db=15.0)
        assert result.passed is False
        assert result.degradation_db < 0

    def test_description_mentions_insufficient(self):
        tester = SelfTester()
        tester.set_baseline(20.0)
        result = tester.run_test(measured_snr_db=18.0)
        assert "insufficient" in result.description.lower()


class TestAlertGeneration:
    """Alert generation for failed self-tests."""

    def test_failed_test_generates_alert(self):
        tester = SelfTester()
        tester.set_baseline(20.0)
        tester.run_test(measured_snr_db=18.0)
        alert = tester.to_alert()
        assert alert is not None
        assert isinstance(alert, VeilAlert)
        assert alert.severity == AlertSeverity.WARNING
        assert alert.category == "self_test"

    def test_passed_test_no_alert(self):
        tester = SelfTester()
        tester.set_baseline(20.0)
        tester.run_test(measured_snr_db=10.0)
        assert tester.to_alert() is None

    def test_no_tests_no_alert(self):
        tester = SelfTester()
        assert tester.to_alert() is None

    def test_alert_metadata(self):
        tester = SelfTester()
        tester.set_baseline(20.0)
        tester.run_test(measured_snr_db=18.0)
        alert = tester.to_alert()
        assert alert is not None
        assert "baseline_snr_db" in alert.metadata
        assert "active_snr_db" in alert.metadata
        assert "passed" in alert.metadata
        assert alert.metadata["passed"] is False


class TestDefaultBaseline:
    """Default baseline when not explicitly set."""

    def test_default_baseline_used(self):
        tester = SelfTester()
        # No set_baseline call -> defaults to 20.0
        result = tester.run_test(measured_snr_db=10.0)
        assert result.baseline_snr_db == 20.0
        assert result.passed is True


class TestToDict:
    """SelfTestResult serialization."""

    def test_to_dict(self):
        tester = SelfTester()
        tester.set_baseline(20.0)
        result = tester.run_test(measured_snr_db=12.0)
        d = result.to_dict()
        assert "timestamp" in d
        assert d["baseline_snr_db"] == 20.0
        assert d["active_snr_db"] == 12.0
        assert d["degradation_db"] == pytest.approx(8.0)
        assert d["passed"] is True
