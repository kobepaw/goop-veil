"""Tests for reporting templates.

Validates FCC complaint, cease-and-desist, and incident report templates
produce well-formed Markdown with required sections and disclaimers.
"""

from __future__ import annotations

import pytest

from goop_veil.compliance import PROHIBITED_TERMS
from goop_veil.mitigation.reporting.templates import (
    DISCLAIMER,
    CeaseAndDesistTemplate,
    FCCComplaintTemplate,
    IncidentReportTemplate,
)


# ---------------------------------------------------------------------------
# Sample data fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_devices() -> list[dict]:
    return [
        {
            "mac_address": "24:0A:C4:00:11:22",
            "vendor": "Espressif",
            "first_seen": "2026-03-01T08:00:00",
            "last_seen": "2026-03-01T10:30:00",
            "channels_observed": [1, 6, 11],
            "frame_count": 4200,
        },
        {
            "mac_address": "24:0A:C4:00:33:44",
            "vendor": "Espressif",
            "first_seen": "2026-03-01T08:05:00",
            "last_seen": "2026-03-01T10:28:00",
            "channels_observed": [1, 6],
            "frame_count": 3100,
        },
    ]


@pytest.fixture
def sample_timeline() -> list[dict]:
    return [
        {
            "timestamp": "2026-03-01T08:00:00",
            "event": "Espressif mesh detected",
            "severity": "high",
            "details": "2 coordinated ESP32 devices on channels 1, 6, 11",
        },
        {
            "timestamp": "2026-03-01T08:15:00",
            "event": "CSI sensing signature detected",
            "severity": "confirmed",
            "details": "Breathing-rate periodicity found at 0.27 Hz",
        },
    ]


# ---------------------------------------------------------------------------
# FCC Complaint Template tests
# ---------------------------------------------------------------------------

class TestFCCComplaintTemplate:

    def test_renders_valid_markdown(self):
        tpl = FCCComplaintTemplate()
        result = tpl.render()
        assert isinstance(result, str)
        assert len(result) > 100
        # Markdown heading present
        assert "# FCC Complaint" in result

    def test_includes_disclaimer(self):
        tpl = FCCComplaintTemplate()
        result = tpl.render()
        assert DISCLAIMER in result

    def test_includes_all_required_sections(self):
        tpl = FCCComplaintTemplate()
        result = tpl.render()
        required_sections = [
            "## 1. Complainant Information",
            "## 2. Subject of Complaint",
            "## 3. Nature of Complaint",
            "## 4. Rules Believed Violated",
            "## 5. Evidence Summary",
            "## 6. Requested Action",
            "## 7. Declaration",
        ]
        for section in required_sections:
            assert section in result, f"Missing section: {section}"

    def test_includes_fcc_citations(self):
        tpl = FCCComplaintTemplate()
        result = tpl.render()
        assert "47 CFR Part 15" in result
        assert "47 USC 333" in result

    def test_with_devices_and_timeline(self, sample_devices, sample_timeline):
        tpl = FCCComplaintTemplate()
        result = tpl.render(
            complainant_name="Jane Doe",
            complainant_address="123 Main St, Springfield, IL",
            suspect_address="125 Main St, Springfield, IL",
            detection_summary="Two ESP32 devices detected running CSI mesh.",
            devices=sample_devices,
            timeline=sample_timeline,
        )
        assert "Jane Doe" in result
        assert "24:0A:C4:00:11:22" in result
        assert "Espressif" in result
        assert "Two ESP32 devices" in result
        assert "Detected Devices" in result
        assert "Detection Timeline" in result

    def test_placeholder_values_work(self):
        tpl = FCCComplaintTemplate()
        result = tpl.render()
        assert "[YOUR NAME]" in result
        assert "[YOUR ADDRESS]" in result
        assert "[SUSPECTED OPERATOR ADDRESS]" in result


# ---------------------------------------------------------------------------
# Cease and Desist Template tests
# ---------------------------------------------------------------------------

class TestCeaseAndDesistTemplate:

    def test_renders_valid_markdown(self):
        tpl = CeaseAndDesistTemplate()
        result = tpl.render()
        assert isinstance(result, str)
        assert len(result) > 100
        assert "# Cease and Desist" in result

    def test_includes_disclaimer(self):
        tpl = CeaseAndDesistTemplate()
        result = tpl.render()
        assert DISCLAIMER in result

    def test_includes_state_and_common_law_citations(self):
        tpl = CeaseAndDesistTemplate()
        result = tpl.render()
        # Common law always present
        assert "Intrusion Upon Seclusion" in result
        assert "Kyllo v. United States" in result
        assert "State Wiretap" in result

    def test_illinois_bipa_cited(self):
        tpl = CeaseAndDesistTemplate()
        result = tpl.render(state="illinois")
        assert "BIPA" in result
        assert "740 ILCS 14" in result
        assert "$1,000" in result
        assert "$5,000" in result

    def test_california_ccpa_cited(self):
        tpl = CeaseAndDesistTemplate()
        result = tpl.render(state="california")
        assert "CCPA" in result or "CPRA" in result
        assert "Cal. Civ. Code" in result or "Cal. Penal Code" in result

    def test_includes_preservation_demand(self):
        tpl = CeaseAndDesistTemplate()
        result = tpl.render()
        assert "Evidence Preservation" in result
        assert "spoliation" in result

    def test_placeholder_values_work(self):
        tpl = CeaseAndDesistTemplate()
        result = tpl.render()
        assert "[YOUR NAME]" in result
        assert "[RECIPIENT NAME]" in result


# ---------------------------------------------------------------------------
# Incident Report Template tests
# ---------------------------------------------------------------------------

class TestIncidentReportTemplate:

    def test_renders_valid_markdown(self):
        tpl = IncidentReportTemplate()
        result = tpl.render()
        assert isinstance(result, str)
        assert len(result) > 100
        assert "# Incident Report" in result

    def test_includes_disclaimer(self):
        tpl = IncidentReportTemplate()
        result = tpl.render()
        assert DISCLAIMER in result

    def test_includes_impact_statement(self):
        tpl = IncidentReportTemplate()
        result = tpl.render()
        assert "## 4. Impact Statement" in result
        assert "Breathing" in result
        assert "Heartbeat" in result

    def test_with_devices_and_timeline(self, sample_devices, sample_timeline):
        tpl = IncidentReportTemplate()
        result = tpl.render(
            reporter_name="John Smith",
            reporter_address="456 Oak Ave, Sacramento, CA",
            detection_summary="Unauthorized through-wall monitoring detected.",
            devices=sample_devices,
            timeline=sample_timeline,
        )
        assert "John Smith" in result
        assert "24:0A:C4:00:11:22" in result
        assert "Unauthorized through-wall monitoring" in result
        assert "Event Timeline" in result


# ---------------------------------------------------------------------------
# Cross-template compliance tests
# ---------------------------------------------------------------------------

class TestTemplateCompliance:

    @pytest.mark.parametrize("template_cls", [
        FCCComplaintTemplate,
        CeaseAndDesistTemplate,
        IncidentReportTemplate,
    ])
    def test_no_prohibited_terms(self, template_cls):
        """Verify templates never use prohibited terminology."""
        tpl = template_cls()
        # Render with default args
        if template_cls is CeaseAndDesistTemplate:
            result = tpl.render(state="illinois")
        elif template_cls is FCCComplaintTemplate:
            result = tpl.render(
                devices=[{"mac_address": "AA:BB:CC:DD:EE:FF", "vendor": "TestVendor"}],
                timeline=[{"timestamp": "2026-01-01", "event": "test", "details": "test"}],
            )
        else:
            result = tpl.render(
                devices=[{"mac_address": "AA:BB:CC:DD:EE:FF", "vendor": "TestVendor"}],
                timeline=[{"timestamp": "2026-01-01", "event": "test", "severity": "high", "details": "test"}],
            )
        lower = result.lower()
        for term in PROHIBITED_TERMS:
            assert term not in lower, (
                f"Prohibited term '{term}' found in {template_cls.__name__} output"
            )
