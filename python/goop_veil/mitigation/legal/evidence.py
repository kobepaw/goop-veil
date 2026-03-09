"""Evidence package generator for WiFi privacy defense.

Assembles detection results, device fingerprints, and alert data into a
structured evidence package with HMAC-signed logs and legal document templates.
This is the main entry point for the legal documentation module.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from goop_veil.mitigation.legal.log_exporter import TimestampedLogExporter
from goop_veil.mitigation.legal.templates import (
    DISCLAIMER,
    CeaseAndDesistTemplate,
    FCCComplaintTemplate,
    IncidentReportTemplate,
)
from goop_veil.mitigation.models import EvidencePackage
from goop_veil.models import DetectionResult, ThreatLevel, VeilAlert

logger = logging.getLogger(__name__)
_THREAT_RANK = {
    ThreatLevel.NONE: 0,
    ThreatLevel.LOW: 1,
    ThreatLevel.MEDIUM: 2,
    ThreatLevel.HIGH: 3,
    ThreatLevel.CONFIRMED: 4,
}


def _mask_mac(mac: str | None) -> str:
    if not mac:
        return "Unknown"
    parts = mac.split(":")
    if len(parts) != 6:
        return mac
    return ":".join(parts[:3] + ["xx", "xx", "xx"])


class LegalConfig(BaseModel):
    """Configuration for legal evidence generation."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    output_dir: str = "data/legal"
    include_disclaimer: bool = True


class EvidencePackageGenerator:
    """Generates legal-grade evidence packages from detection results.

    Creates a directory of files including HMAC-signed detection logs,
    an evidence report, and optional legal document templates (FCC complaint,
    cease-and-desist, incident report).
    """

    def __init__(self, config: LegalConfig | None = None) -> None:
        """Initialize the evidence package generator.

        Args:
            config: Legal configuration. Uses defaults if not provided.
        """
        self._config = config or LegalConfig()
        self._log_exporter = TimestampedLogExporter()
        self._fcc_template = FCCComplaintTemplate()
        self._cd_template = CeaseAndDesistTemplate()
        self._incident_template = IncidentReportTemplate()

    def generate(
        self,
        detection_results: list[DetectionResult],
        alerts: list[VeilAlert] | None = None,
        output_dir: str | Path | None = None,
        include_fcc_complaint: bool = True,
        include_cease_desist: bool = True,
        include_incident_report: bool = False,
        redact_sensitive: bool = True,
    ) -> EvidencePackage:
        """Generate complete evidence package.

        Creates the following files in the output directory:
            1. evidence_report_{timestamp}.md - Summary of all detections.
            2. detection_log_{timestamp}.json - HMAC-signed raw detection data.
            3. fcc_complaint_template.md (if requested).
            4. cease_and_desist_template.md (if requested).
            5. incident_report_template.md (if requested).

        Args:
            detection_results: Detection results to include in the package.
            alerts: Optional alerts to include. Defaults to empty list.
            output_dir: Override output directory. Uses config default if None.
            include_fcc_complaint: Generate FCC complaint template.
            include_cease_desist: Generate cease-and-desist template.
            include_incident_report: Generate incident report template.
            redact_sensitive: Redact sensitive identifiers in exported artifacts.

        Returns:
            EvidencePackage model with metadata about the generated package.
        """
        alerts = alerts or []
        now = datetime.now(timezone.utc)
        ts_str = now.strftime("%Y%m%d_%H%M%S")

        # 1. Create output directory
        out_dir = Path(output_dir or self._config.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        # 2. Build timeline from detection results
        timeline = self._build_timeline(detection_results)

        # 3. Build device inventory
        devices = self._extract_devices(detection_results)
        exported_devices = (
            self._redact_devices(devices) if redact_sensitive else devices
        )

        # 4. Export HMAC-signed detection log
        log_path = out_dir / f"detection_log_{ts_str}.json"
        log_hmac = self._log_exporter.export(
            alerts, detection_results, log_path, redact_sensitive=redact_sensitive
        )
        logger.info("Signed detection log: %s", log_path)

        # 5. Render and write evidence report
        report_md = self._render_evidence_report(
            detection_results,
            timeline,
            redact_sensitive=redact_sensitive,
        )
        report_path = out_dir / f"evidence_report_{ts_str}.md"
        report_path.write_text(report_md, encoding="utf-8")
        logger.info("Evidence report: %s", report_path)

        # 6. Compute SHA-256 hash of evidence report
        report_hash = self._hash_file(report_path)

        # 7. Generate requested legal templates
        detection_summary = self._build_detection_summary(detection_results)
        device_dicts = [d for d in exported_devices]

        if include_fcc_complaint:
            fcc_md = self._fcc_template.render(
                detection_summary=detection_summary,
                devices=device_dicts,
                timeline=timeline,
            )
            fcc_path = out_dir / "fcc_complaint_template.md"
            fcc_path.write_text(fcc_md, encoding="utf-8")
            logger.info("FCC complaint template: %s", fcc_path)

        if include_cease_desist:
            cd_md = self._cd_template.render(
                detection_summary=detection_summary,
            )
            cd_path = out_dir / "cease_and_desist_template.md"
            cd_path.write_text(cd_md, encoding="utf-8")
            logger.info("Cease-and-desist template: %s", cd_path)

        if include_incident_report:
            ir_md = self._incident_template.render(
                detection_summary=detection_summary,
                devices=device_dicts,
                timeline=timeline,
            )
            ir_path = out_dir / "incident_report_template.md"
            ir_path.write_text(ir_md, encoding="utf-8")
            logger.info("Incident report template: %s", ir_path)

        # 8. Build and return EvidencePackage
        return EvidencePackage(
            timestamp=now,
            detection_results=[d.model_dump(mode="json") for d in detection_results],
            device_fingerprints=exported_devices,
            timeline=timeline,
            output_path=str(out_dir),
            report_hash=report_hash,
            disclaimer=DISCLAIMER if self._config.include_disclaimer else "",
        )

    def _build_timeline(self, results: list[DetectionResult]) -> list[dict]:
        """Build chronological timeline from detection results.

        Each detection result becomes one or more timeline entries sorted
        by timestamp.

        Args:
            results: Detection results to convert into timeline events.

        Returns:
            List of timeline event dicts sorted chronologically.
        """
        events: list[dict] = []
        for result in results:
            event: dict = {
                "timestamp": result.timestamp.isoformat(),
                "event": f"Detection: {result.threat_level.value}",
                "severity": result.threat_level.value,
                "details": result.summary or f"Confidence: {result.confidence:.2f}",
            }
            events.append(event)

            # Add sub-events for specific capabilities detected
            for cap in result.detected_capabilities:
                events.append({
                    "timestamp": result.timestamp.isoformat(),
                    "event": f"Capability detected: {cap.value}",
                    "severity": result.threat_level.value,
                    "details": f"WiFi CSI sensing capability: {cap.value}",
                })

        # Sort chronologically
        events.sort(key=lambda e: e["timestamp"])
        return events

    def _extract_devices(self, results: list[DetectionResult]) -> list[dict]:
        """Extract unique device fingerprints from detection results.

        Args:
            results: Detection results containing device fingerprints.

        Returns:
            List of device dicts (deduplicated by MAC address).
        """
        seen_macs: set[str] = set()
        devices: list[dict] = []
        for result in results:
            for dev in result.devices:
                if dev.mac_address not in seen_macs:
                    seen_macs.add(dev.mac_address)
                    devices.append(dev.model_dump(mode="json"))
        return devices

    def _build_detection_summary(self, results: list[DetectionResult]) -> str:
        """Build a concise summary string from detection results.

        Args:
            results: Detection results to summarize.

        Returns:
            Summary string suitable for embedding in legal templates.
        """
        if not results:
            return "No detections recorded."

        highest_level = max(results, key=lambda r: _THREAT_RANK[r.threat_level]).threat_level.value
        all_caps: set[str] = set()
        for r in results:
            for c in r.detected_capabilities:
                all_caps.add(c.value)

        total_devices = sum(len(r.devices) for r in results)
        caps_str = ", ".join(sorted(all_caps)) if all_caps else "none"

        return (
            f"{len(results)} detection(s) recorded. Highest threat level: {highest_level}. "
            f"Sensing capabilities detected: {caps_str}. "
            f"Total suspicious devices: {total_devices}."
        )

    def _render_evidence_report(
        self,
        results: list[DetectionResult],
        timeline: list[dict],
        redact_sensitive: bool = True,
    ) -> str:
        """Render the main evidence report as Markdown.

        Args:
            results: Detection results to include.
            timeline: Pre-built chronological timeline.

        Returns:
            Markdown-formatted evidence report.
        """
        lines: list[str] = []

        if self._config.include_disclaimer:
            lines.append(f"> {DISCLAIMER}")
            lines.append("")

        lines.append("# WiFi Surveillance Detection — Evidence Report")
        lines.append("")
        lines.append(
            f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"
        )
        lines.append("")

        # Executive Summary
        lines.append("## Executive Summary")
        lines.append("")
        lines.append(self._build_detection_summary(results))
        lines.append("")

        # Detection Timeline
        lines.append("## Detection Timeline")
        lines.append("")
        if timeline:
            lines.append("| Timestamp | Event | Severity | Details |")
            lines.append("|---|---|---|---|")
            for event in timeline:
                ts = event.get("timestamp", "N/A")
                evt = event.get("event", "N/A")
                sev = event.get("severity", "N/A")
                details = event.get("details", "")
                lines.append(f"| {ts} | {evt} | {sev} | {details} |")
            lines.append("")
        else:
            lines.append("*No timeline events recorded.*")
            lines.append("")

        # Device Inventory
        lines.append("## Device Inventory")
        lines.append("")
        devices = self._extract_devices(results)
        if redact_sensitive:
            devices = self._redact_devices(devices)
        if devices:
            lines.append("| MAC Address | Vendor | Espressif | Channels | Frames |")
            lines.append("|---|---|---|---|---|")
            for dev in devices:
                mac = dev.get("mac_address", "Unknown")
                vendor = dev.get("vendor", "Unknown")
                is_esp = "Yes" if dev.get("is_espressif") else "No"
                channels = dev.get("channels_observed", [])
                ch_str = ", ".join(str(c) for c in channels) if channels else "N/A"
                frames = dev.get("frame_count", 0)
                lines.append(f"| {mac} | {vendor} | {is_esp} | {ch_str} | {frames} |")
            lines.append("")
        else:
            lines.append("*No devices identified.*")
            lines.append("")

        # Threat Assessment
        lines.append("## Threat Assessment")
        lines.append("")
        for i, result in enumerate(results, 1):
            lines.append(f"### Detection #{i}")
            lines.append("")
            lines.append(f"- **Threat Level:** {result.threat_level.value}")
            lines.append(f"- **Confidence:** {result.confidence:.2f}")
            lines.append(f"- **Channel Hopping Detected:** {'Yes' if result.channel_hop_detected else 'No'}")
            lines.append(f"- **Espressif Mesh Detected:** {'Yes' if result.espressif_mesh_detected else 'No'}")
            if result.detected_capabilities:
                caps = ", ".join(c.value for c in result.detected_capabilities)
                lines.append(f"- **Sensing Capabilities:** {caps}")
            if result.summary:
                lines.append(f"- **Summary:** {result.summary}")
            lines.append("")

        if not results:
            lines.append("*No detections to assess.*")
            lines.append("")

        # Technical Analysis
        lines.append("## Technical Analysis")
        lines.append("")
        lines.append(
            "WiFi Channel State Information (CSI) sensing is a technique that "
            "exploits the physical-layer characteristics of WiFi signals to detect "
            "human presence, motion, breathing, and heartbeat through walls. "
            "The detection system monitors for telltale indicators of this "
            "technology, including:"
        )
        lines.append("")
        lines.append("- Coordinated Espressif (ESP32/ESP8266) device deployments forming mesh networks.")
        lines.append("- Anomalous beacon intervals inconsistent with standard WiFi access points.")
        lines.append("- Rapid channel hopping patterns used for multi-frequency CSI collection.")
        lines.append("- Periodic signal components in CSI data matching human vital sign frequencies.")
        lines.append("")

        # Appendix
        lines.append("## Appendix")
        lines.append("")
        lines.append(
            "Raw detection data is preserved in the accompanying HMAC-signed "
            "JSON log file. The HMAC-SHA256 signature ensures that any tampering "
            "with the log data can be detected."
        )
        lines.append("")
        lines.append(
            "For questions about this report or the underlying detection technology, "
            "consult a qualified technical expert and licensed attorney."
        )
        lines.append("")

        return "\n".join(lines)

    @staticmethod
    def _redact_devices(devices: list[dict]) -> list[dict]:
        redacted: list[dict] = []
        for dev in devices:
            clone = dict(dev)
            clone["mac_address"] = _mask_mac(clone.get("mac_address"))
            if clone.get("ssid"):
                clone["ssid"] = "[REDACTED]"
            if clone.get("vendor") == "Unknown":
                clone["vendor"] = "Unknown"
            redacted.append(clone)
        return redacted

    def _hash_file(self, path: Path) -> str:
        """Compute SHA-256 hash of a file.

        Args:
            path: Path to the file to hash.

        Returns:
            Hex-encoded SHA-256 digest.
        """
        sha256 = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
