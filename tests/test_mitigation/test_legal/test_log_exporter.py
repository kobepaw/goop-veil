"""Tests for timestamped log exporter with HMAC integrity signatures."""

from __future__ import annotations

import base64
import json
import os
from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from goop_veil.mitigation.legal.log_exporter import TimestampedLogExporter
from goop_veil.models import (
    AlertSeverity,
    DetectionResult,
    DeviceFingerprint,
    SensingCapability,
    ThreatLevel,
    VeilAlert,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def signing_key() -> bytes:
    return b"test-signing-key-32-bytes-long!!"


@pytest.fixture
def exporter(signing_key) -> TimestampedLogExporter:
    return TimestampedLogExporter(signing_key=signing_key)


@pytest.fixture
def sample_alert() -> VeilAlert:
    return VeilAlert(
        timestamp=datetime(2026, 3, 1, 8, 0, 0, tzinfo=timezone.utc),
        severity=AlertSeverity.CRITICAL,
        category="detection",
        title="Espressif mesh detected",
        description="Two coordinated ESP32 devices found on channels 1, 6, 11.",
        source="beacon_analyzer",
    )


@pytest.fixture
def sample_detection() -> DetectionResult:
    return DetectionResult(
        timestamp=datetime(2026, 3, 1, 8, 0, 0, tzinfo=timezone.utc),
        threat_level=ThreatLevel.HIGH,
        detected_capabilities=[SensingCapability.BREATHING, SensingCapability.PRESENCE],
        devices=[
            DeviceFingerprint(
                mac_address="24:0A:C4:00:11:22",
                vendor="Espressif",
                is_espressif=True,
                channels_observed=[1, 6, 11],
                frame_count=4200,
            ),
        ],
        channel_hop_detected=True,
        espressif_mesh_detected=True,
        confidence=0.92,
        summary="High-confidence WiFi sensing mesh detected.",
    )


# ---------------------------------------------------------------------------
# Export tests
# ---------------------------------------------------------------------------

class TestExport:

    def test_creates_valid_json_file(self, exporter, sample_alert, sample_detection, tmp_path):
        output = tmp_path / "log.json"
        exporter.export([sample_alert], [sample_detection], output)

        assert output.exists()
        data = json.loads(output.read_text())
        assert "exported_at" in data
        assert "version" in data
        assert data["version"] == "1.0"
        assert "alerts" in data
        assert "detections" in data
        assert "hmac" in data

    def test_export_returns_hmac(self, exporter, sample_alert, sample_detection, tmp_path):
        output = tmp_path / "log.json"
        hmac_hex = exporter.export([sample_alert], [sample_detection], output)

        assert isinstance(hmac_hex, str)
        assert len(hmac_hex) == 64  # SHA-256 hex digest is 64 chars

    def test_hmac_stored_in_file(self, exporter, sample_alert, sample_detection, tmp_path):
        output = tmp_path / "log.json"
        hmac_hex = exporter.export([sample_alert], [sample_detection], output)

        data = json.loads(output.read_text())
        assert data["hmac"] == hmac_hex

    def test_export_creates_parent_dirs(self, exporter, sample_alert, sample_detection, tmp_path):
        output = tmp_path / "deep" / "nested" / "dir" / "log.json"
        exporter.export([sample_alert], [sample_detection], output)
        assert output.exists()

    def test_export_with_empty_alerts_and_results(self, exporter, tmp_path):
        output = tmp_path / "empty.json"
        hmac_hex = exporter.export([], [], output)

        assert output.exists()
        data = json.loads(output.read_text())
        assert data["alerts"] == []
        assert data["detections"] == []
        assert len(hmac_hex) == 64

    def test_export_with_multiple_items(self, exporter, sample_alert, sample_detection, tmp_path):
        alerts = [sample_alert, sample_alert]
        detections = [sample_detection, sample_detection]
        output = tmp_path / "multi.json"
        exporter.export(alerts, detections, output)

        data = json.loads(output.read_text())
        assert len(data["alerts"]) == 2
        assert len(data["detections"]) == 2


# ---------------------------------------------------------------------------
# Verify tests
# ---------------------------------------------------------------------------

class TestVerify:

    def test_verify_correct_hmac_returns_true(
        self, exporter, sample_alert, sample_detection, tmp_path,
    ):
        output = tmp_path / "log.json"
        hmac_hex = exporter.export([sample_alert], [sample_detection], output)

        assert exporter.verify(output, hmac_hex) is True

    def test_verify_tampered_data_returns_false(
        self, exporter, sample_alert, sample_detection, tmp_path,
    ):
        output = tmp_path / "log.json"
        hmac_hex = exporter.export([sample_alert], [sample_detection], output)

        # Tamper with the file
        data = json.loads(output.read_text())
        data["alerts"][0]["title"] = "TAMPERED"
        output.write_text(json.dumps(data, sort_keys=True))

        assert exporter.verify(output, hmac_hex) is False

    def test_verify_wrong_key_returns_false(
        self, exporter, sample_alert, sample_detection, tmp_path,
    ):
        output = tmp_path / "log.json"
        hmac_hex = exporter.export([sample_alert], [sample_detection], output)

        # Create a new exporter with a different key
        wrong_exporter = TimestampedLogExporter(signing_key=b"wrong-key-also-32-bytes-long!!!!")
        assert wrong_exporter.verify(output, hmac_hex) is False

    def test_verify_empty_log(self, exporter, tmp_path):
        output = tmp_path / "empty.json"
        hmac_hex = exporter.export([], [], output)
        assert exporter.verify(output, hmac_hex) is True


# ---------------------------------------------------------------------------
# Key management tests
# ---------------------------------------------------------------------------

class TestKeyManagement:

    def test_random_key_generated_with_warning(self):
        with patch.dict(os.environ, {}, clear=True):
            # Ensure env var is not set
            os.environ.pop("VEIL_LOG_SIGNING_KEY", None)
            with pytest.warns(UserWarning, match="random key"):
                exp = TimestampedLogExporter()
            assert len(exp.signing_key) == 32

    def test_env_var_signing_key(self):
        test_key = b"env-var-test-key-32-bytes-long!!"
        encoded = base64.b64encode(test_key).decode()
        with patch.dict(os.environ, {"VEIL_LOG_SIGNING_KEY": encoded}):
            exp = TimestampedLogExporter()
            assert exp.signing_key == test_key

    def test_explicit_key_takes_precedence(self):
        explicit_key = b"explicit-key-32-bytes-long!!!!!!"
        env_key = base64.b64encode(b"env-key-32-bytes-long!!!!!!!!!!").decode()
        with patch.dict(os.environ, {"VEIL_LOG_SIGNING_KEY": env_key}):
            exp = TimestampedLogExporter(signing_key=explicit_key)
            assert exp.signing_key == explicit_key

    def test_invalid_base64_env_var_raises(self):
        with patch.dict(os.environ, {"VEIL_LOG_SIGNING_KEY": "not-valid-base64!!!"}):
            with pytest.raises(ValueError, match="Failed to decode"):
                TimestampedLogExporter()
