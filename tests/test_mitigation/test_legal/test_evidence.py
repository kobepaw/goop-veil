"""Tests for the evidence package generator."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from goop_veil.mitigation.legal.evidence import EvidencePackageGenerator, LegalConfig
from goop_veil.mitigation.legal.log_exporter import MissingSigningKeyError
from goop_veil.mitigation.legal.templates import DISCLAIMER
from goop_veil.mitigation.models import EvidencePackage
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
def legal_config(tmp_path) -> LegalConfig:
    return LegalConfig(
        output_dir=str(tmp_path / "evidence"),
        allow_temporary_signing=True,
    )


@pytest.fixture
def generator(legal_config) -> EvidencePackageGenerator:
    return EvidencePackageGenerator(config=legal_config)


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


@pytest.fixture
def sample_detection_low() -> DetectionResult:
    return DetectionResult(
        timestamp=datetime(2026, 3, 1, 6, 0, 0, tzinfo=timezone.utc),
        threat_level=ThreatLevel.LOW,
        detected_capabilities=[SensingCapability.PRESENCE],
        devices=[
            DeviceFingerprint(
                mac_address="AA:BB:CC:DD:EE:FF",
                vendor="Unknown",
                is_espressif=False,
                frame_count=100,
            ),
        ],
        confidence=0.35,
        summary="Low-confidence anomaly.",
    )


@pytest.fixture
def sample_alert() -> VeilAlert:
    return VeilAlert(
        timestamp=datetime(2026, 3, 1, 8, 0, 0, tzinfo=timezone.utc),
        severity=AlertSeverity.CRITICAL,
        category="detection",
        title="Espressif mesh detected",
        description="Coordinated ESP32 devices found.",
        source="beacon_analyzer",
    )


# ---------------------------------------------------------------------------
# Output directory tests
# ---------------------------------------------------------------------------

class TestOutputDirectory:

    def test_generate_creates_output_directory(self, generator, sample_detection, legal_config):
        out_dir = Path(legal_config.output_dir)
        assert not out_dir.exists()

        generator.generate([sample_detection])
        assert out_dir.exists()
        assert out_dir.is_dir()

    def test_generate_with_custom_output_dir(self, generator, sample_detection, tmp_path):
        custom_dir = tmp_path / "custom_evidence"
        generator.generate([sample_detection], output_dir=custom_dir)
        assert custom_dir.exists()


# ---------------------------------------------------------------------------
# File creation tests
# ---------------------------------------------------------------------------

class TestFileCreation:

    def test_creates_evidence_report_file(self, generator, sample_detection, legal_config):
        pkg = generator.generate([sample_detection])
        out_dir = Path(legal_config.output_dir)
        md_files = list(out_dir.glob("evidence_report_*.md"))
        assert len(md_files) == 1

    def test_creates_signed_log_file(self, generator, sample_detection, legal_config):
        generator.generate([sample_detection])
        out_dir = Path(legal_config.output_dir)
        json_files = list(out_dir.glob("detection_log_*.json"))
        assert len(json_files) == 1

        # Verify it's valid JSON with HMAC and explicit verification metadata.
        data = json.loads(json_files[0].read_text())
        assert "hmac" in data
        assert "detections" in data
        assert data["verification"]["mode"] == "temporary_signed"

    def test_creates_fcc_complaint_when_requested(self, generator, sample_detection, legal_config):
        generator.generate([sample_detection], include_fcc_complaint=True)
        out_dir = Path(legal_config.output_dir)
        fcc_files = list(out_dir.glob("fcc_complaint_template.md"))
        assert len(fcc_files) == 1

    def test_creates_cease_desist_when_requested(self, generator, sample_detection, legal_config):
        generator.generate([sample_detection], include_cease_desist=True)
        out_dir = Path(legal_config.output_dir)
        cd_files = list(out_dir.glob("cease_and_desist_template.md"))
        assert len(cd_files) == 1

    def test_creates_incident_report_when_requested(self, generator, sample_detection, legal_config):
        generator.generate([sample_detection], include_incident_report=True)
        out_dir = Path(legal_config.output_dir)
        ir_files = list(out_dir.glob("incident_report_template.md"))
        assert len(ir_files) == 1

    def test_skips_fcc_when_not_requested(self, generator, sample_detection, legal_config):
        generator.generate(
            [sample_detection],
            include_fcc_complaint=False,
            include_cease_desist=False,
            include_incident_report=False,
        )
        out_dir = Path(legal_config.output_dir)
        assert not list(out_dir.glob("fcc_complaint_template.md"))
        assert not list(out_dir.glob("cease_and_desist_template.md"))
        assert not list(out_dir.glob("incident_report_template.md"))

    def test_skips_templates_when_all_false(self, generator, sample_detection, legal_config):
        generator.generate(
            [sample_detection],
            include_fcc_complaint=False,
            include_cease_desist=False,
            include_incident_report=False,
        )
        out_dir = Path(legal_config.output_dir)
        # Should only have the evidence report and detection log
        all_files = list(out_dir.iterdir())
        assert len(all_files) == 2


# ---------------------------------------------------------------------------
# EvidencePackage model tests
# ---------------------------------------------------------------------------

class TestEvidencePackageModel:

    def test_has_correct_report_hash(self, generator, sample_detection, legal_config):
        import hashlib

        pkg = generator.generate([sample_detection])
        out_dir = Path(legal_config.output_dir)
        report_files = list(out_dir.glob("evidence_report_*.md"))
        assert len(report_files) == 1

        # Recompute hash
        sha256 = hashlib.sha256()
        sha256.update(report_files[0].read_bytes())
        expected_hash = sha256.hexdigest()
        assert pkg.report_hash == expected_hash

    def test_has_disclaimer(self, generator, sample_detection):
        pkg = generator.generate([sample_detection])
        assert pkg.disclaimer == DISCLAIMER

    def test_disclaimer_omitted_when_config_false(self, sample_detection, tmp_path):
        config = LegalConfig(
            output_dir=str(tmp_path / "no_disc"),
            include_disclaimer=False,
            allow_temporary_signing=True,
        )
        gen = EvidencePackageGenerator(config=config)
        pkg = gen.generate([sample_detection])
        assert pkg.disclaimer == ""

    def test_returns_evidence_package_type(self, generator, sample_detection):
        pkg = generator.generate([sample_detection])
        assert isinstance(pkg, EvidencePackage)

    def test_detection_results_in_package(self, generator, sample_detection):
        pkg = generator.generate([sample_detection])
        assert len(pkg.detection_results) == 1
        assert pkg.detection_results[0]["threat_level"] == "high"

    def test_device_fingerprints_in_package(self, generator, sample_detection):
        pkg = generator.generate([sample_detection])
        assert len(pkg.device_fingerprints) == 1
        assert pkg.device_fingerprints[0]["mac_address"] == "24:0A:C4:xx:xx:xx"

    def test_redaction_can_be_disabled(self, generator, sample_detection):
        pkg = generator.generate([sample_detection], redact_sensitive=False)
        assert pkg.device_fingerprints[0]["mac_address"] == "24:0A:C4:00:11:22"

    def test_output_path_set(self, generator, sample_detection, legal_config):
        pkg = generator.generate([sample_detection])
        assert pkg.output_path == legal_config.output_dir


# ---------------------------------------------------------------------------
# Timeline tests
# ---------------------------------------------------------------------------

class TestTimeline:

    def test_build_timeline_chronological_order(
        self, generator, sample_detection, sample_detection_low,
    ):
        # sample_detection_low is at 06:00, sample_detection is at 08:00
        pkg = generator.generate([sample_detection, sample_detection_low])
        timestamps = [e["timestamp"] for e in pkg.timeline]
        assert timestamps == sorted(timestamps)

    def test_timeline_includes_capability_events(self, generator, sample_detection):
        pkg = generator.generate([sample_detection])
        events = [e["event"] for e in pkg.timeline]
        cap_events = [e for e in events if "Capability detected" in e]
        # sample_detection has 2 capabilities: breathing, presence
        assert len(cap_events) == 2

    def test_timeline_empty_for_no_results(self, generator):
        pkg = generator.generate([])
        assert pkg.timeline == []


class TestThreatSummaryOrdering:

    def test_summary_uses_enum_severity_order_not_lexicographic(self, generator, sample_detection):
        medium = DetectionResult(
            timestamp=datetime(2026, 3, 1, 7, 0, 0, tzinfo=timezone.utc),
            threat_level=ThreatLevel.MEDIUM,
        )
        confirmed = DetectionResult(
            timestamp=datetime(2026, 3, 1, 9, 0, 0, tzinfo=timezone.utc),
            threat_level=ThreatLevel.CONFIRMED,
        )
        summary = generator._build_detection_summary([medium, sample_detection, confirmed])
        assert "Highest threat level: confirmed" in summary


# ---------------------------------------------------------------------------
# Edge case tests
# ---------------------------------------------------------------------------

class TestEdgeCases:

    def test_missing_signing_key_fails_closed_outside_temporary_mode(self, sample_detection, tmp_path):
        config = LegalConfig(output_dir=str(tmp_path / "strict"))
        with pytest.raises(MissingSigningKeyError, match="Refusing to create"):
            EvidencePackageGenerator(config=config).generate([sample_detection])

    def test_with_empty_detection_results(self, generator, legal_config):
        pkg = generator.generate([])
        assert pkg.detection_results == []
        assert pkg.device_fingerprints == []
        assert pkg.timeline == []

        # Files should still be created
        out_dir = Path(legal_config.output_dir)
        assert out_dir.exists()
        md_files = list(out_dir.glob("evidence_report_*.md"))
        assert len(md_files) == 1

    def test_with_multiple_detection_results(
        self, generator, sample_detection, sample_detection_low,
    ):
        pkg = generator.generate([sample_detection, sample_detection_low])
        assert len(pkg.detection_results) == 2
        # Devices should be deduplicated
        assert len(pkg.device_fingerprints) == 2  # Different MAC addresses

    def test_with_alerts(self, generator, sample_detection, sample_alert, legal_config):
        pkg = generator.generate(
            [sample_detection],
            alerts=[sample_alert],
        )
        out_dir = Path(legal_config.output_dir)
        json_files = list(out_dir.glob("detection_log_*.json"))
        data = json.loads(json_files[0].read_text())
        assert len(data["alerts"]) == 1
        assert data["alerts"][0]["title"] == "Espressif mesh detected"

    def test_evidence_report_contains_disclaimer(self, generator, sample_detection, legal_config):
        generator.generate([sample_detection])
        out_dir = Path(legal_config.output_dir)
        report = list(out_dir.glob("evidence_report_*.md"))[0].read_text()
        assert DISCLAIMER in report
