"""goop-veil MCP server — exposes WiFi privacy defense tools via FastMCP.

Follows goop-face MCP pattern: stderr logging, JSON returns, lazy init,
asyncio.to_thread for synchronous operations.

Tools:
- detect_wifi_sensing: Analyze pcap for WiFi sensing activity
- assess_room_vulnerability: Assess room and recommend materials
- activate_veil: Activate ESP32 privacy enhancement
- deploy_countermeasures: Select and deploy adaptive countermeasures
- share_sensing_signature: Share detection signatures with federation
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from pathlib import Path

# CRITICAL: stdout reserved for JSON-RPC — all logging to stderr
logging.basicConfig(
    stream=sys.stderr,
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("goop_veil.mcp")

# Lazy-init globals
_config = None
_beacon_scanner = None
_traffic_analyzer = None
_csi_analyzer = None
_alert_engine = None
_placement_optimizer = None
_privacy_enhancer = None
_brorl_adapter = None


def _init():
    """Lazily initialize all components."""
    global _config, _beacon_scanner, _traffic_analyzer, _csi_analyzer
    global _alert_engine, _placement_optimizer, _privacy_enhancer, _brorl_adapter

    if _config is not None:
        return

    from goop_veil.config import VeilConfig

    _config = VeilConfig()

    from goop_veil.detection.beacon_scanner import BeaconScanner
    from goop_veil.detection.traffic_analyzer import TrafficAnalyzer
    from goop_veil.detection.csi_signature import CSISignatureAnalyzer
    from goop_veil.detection.alert_engine import AlertEngine

    _beacon_scanner = BeaconScanner(_config.detection)
    _traffic_analyzer = TrafficAnalyzer()
    _csi_analyzer = CSISignatureAnalyzer(_config.detection)
    _alert_engine = AlertEngine(_config.detection)

    from goop_veil.passive.placement_optimizer import PlacementOptimizer

    _placement_optimizer = PlacementOptimizer(_config.passive)

    from goop_veil.adversarial.brorl_adapter import BroRLAdapter

    _brorl_adapter = BroRLAdapter(_config.adversarial)

    logger.info("goop-veil components initialized")


def _create_mcp_server():
    """Create the FastMCP server (deferred to allow import without mcp installed)."""
    from mcp.server.fastmcp import FastMCP

    mcp_server = FastMCP(
        "goop-veil",
        instructions=(
            "WiFi privacy defense system. Detects WiFi CSI-based surveillance, "
            "recommends passive shielding materials, and controls active privacy "
            "enhancement via ESP32 mesh access points. All operations comply with "
            "FCC Part 15.247."
        ),
    )

    @mcp_server.tool()
    async def detect_wifi_sensing(pcap_path: str) -> str:
        """Analyze a pcap file for WiFi sensing activity.

        Detects Espressif mesh networks, rapid channel hopping, suspicious
        traffic patterns, and CSI signatures indicating human activity monitoring.

        Args:
            pcap_path: Path to a pcap file containing captured WiFi traffic.
        """
        _init()
        path = Path(pcap_path)
        if not path.exists():
            return json.dumps({"error": f"File not found: {pcap_path}"})

        def _detect():
            anomalies = _beacon_scanner.scan_pcap(path)
            threat_level, indicators = _traffic_analyzer.analyze_pcap(path)
            result = _alert_engine.assess(
                devices=list(_beacon_scanner.devices.values()),
                beacon_anomalies=anomalies,
                traffic_indicators=indicators,
                traffic_threat=threat_level,
            )
            return result

        result = await asyncio.to_thread(_detect)

        return json.dumps({
            "threat_level": result.threat_level.value,
            "confidence": result.confidence,
            "devices_found": len(result.devices),
            "espressif_mesh_detected": result.espressif_mesh_detected,
            "channel_hop_detected": result.channel_hop_detected,
            "capabilities": [c.value for c in result.detected_capabilities],
            "anomaly_count": len(result.beacon_anomalies),
            "summary": result.summary,
        })

    @mcp_server.tool()
    async def assess_room_vulnerability(
        room_length: float = 4.5,
        room_width: float = 3.5,
        room_height: float = 2.7,
        budget: float = 100.0,
        goal: str = "hide_pose",
    ) -> str:
        """Assess a room's vulnerability to WiFi sensing and recommend materials.

        Calculates Fresnel zones, estimates sensing effectiveness, and recommends
        cost-effective materials to place for privacy protection.

        Args:
            room_length: Room length in meters.
            room_width: Room width in meters.
            room_height: Room height in meters.
            budget: Maximum budget in USD for material recommendations.
            goal: Privacy goal (hide_heartbeat, hide_breathing, hide_motion,
                  hide_pose, hide_presence).
        """
        _init()

        def _assess():
            return _placement_optimizer.assess_room(
                room_length_m=room_length,
                room_width_m=room_width,
                room_height_m=room_height,
                budget_usd=budget,
                target=goal,
            )

        assessment = await asyncio.to_thread(_assess)

        return json.dumps({
            "room": f"{room_length}x{room_width}x{room_height}m",
            "vulnerability_score": assessment.vulnerability_score,
            "current_attenuation_db": assessment.current_attenuation_db,
            "target_attenuation_db": assessment.target_attenuation_db,
            "recommendations": [
                {
                    "material": r.material,
                    "location": r.location,
                    "attenuation_db": r.attenuation_db,
                    "cost_usd": r.cost_usd,
                    "priority": r.priority,
                }
                for r in assessment.recommendations
            ],
            "estimated_cost_usd": assessment.estimated_cost_usd,
            "summary": assessment.summary,
        })

    @mcp_server.tool()
    async def activate_veil(
        mode: str = "vitals_privacy",
        power: float = 15.0,
        channel: int = 6,
    ) -> str:
        """Activate WiFi privacy enhancement via ESP32 mesh access point.

        Starts legitimate WiFi services (mesh AP, sensors, positioning) that
        provide privacy as a secondary benefit of normal RF activity.
        All operations comply with FCC Part 15.247 power limits.

        Args:
            mode: Privacy mode (vitals_privacy, motion_privacy, full_privacy).
            power: Transmission power in dBm (max 20, must comply with FCC).
            channel: WiFi channel (1-11 for US).
        """
        _init()

        global _privacy_enhancer
        if _privacy_enhancer is None:
            from goop_veil.active.privacy_enhancer import PrivacyEnhancer
            from goop_veil.hardware.esp32_hal import MockESP32HAL

            _privacy_enhancer = PrivacyEnhancer(
                config=_config.active,
                hal=MockESP32HAL(),
            )

        def _activate():
            return _privacy_enhancer.activate(mode=mode, power_dbm=power, channel=channel)

        status = await asyncio.to_thread(_activate)

        return json.dumps({
            "mode": status.mode.value,
            "power_dbm": status.power_dbm,
            "channel": status.channel,
            "mesh_ap_active": status.mesh_ap_active,
            "sensors_active": status.sensors_active,
            "positioning_active": status.positioning_active,
            "compliant": status.compliant,
        })

    @mcp_server.tool()
    async def deploy_countermeasures(pcap_path: str | None = None) -> str:
        """Select and deploy adaptive countermeasures using BroRL.

        Uses Thompson sampling to select the most effective adversarial
        technique based on learned effectiveness against the detected
        sensing system.

        Args:
            pcap_path: Optional pcap file to analyze for technique selection.
        """
        _init()

        from goop_veil.adversarial.csi_adversarial import AdversarialCSIGenerator

        generator = AdversarialCSIGenerator(_brorl_adapter)

        def _deploy():
            technique, description = generator.select_technique()
            timing = generator.generate_timing_pattern(technique)
            stats = generator.get_technique_stats()
            return technique, description, len(timing), stats

        technique, description, n_frames, stats = await asyncio.to_thread(_deploy)

        return json.dumps({
            "selected_technique": technique,
            "description": description,
            "timing_pattern_frames": n_frames,
            "technique_stats": stats,
        })

    @mcp_server.tool()
    async def share_sensing_signature(pcap_path: str) -> str:
        """Extract and share WiFi sensing signatures with the federation.

        Analyzes a pcap file, extracts device fingerprints and sensing
        patterns, and shares them via goop-net (or stores locally).

        Args:
            pcap_path: Path to pcap file with detected sensing activity.
        """
        _init()

        from goop_veil.integration.net_sharing import NetSharingBridge

        bridge = NetSharingBridge(_config.data_dir)

        def _share():
            anomalies = _beacon_scanner.scan_pcap(Path(pcap_path))
            threat_level, indicators = _traffic_analyzer.analyze_pcap(Path(pcap_path))
            result = _alert_engine.assess(
                devices=list(_beacon_scanner.devices.values()),
                beacon_anomalies=anomalies,
                traffic_indicators=indicators,
                traffic_threat=threat_level,
            )
            signatures = bridge.extract_signatures(result)
            shared = bridge.share(signatures)
            return len(signatures), shared

        n_sigs, shared = await asyncio.to_thread(_share)

        return json.dumps({
            "signatures_extracted": n_sigs,
            "shared": shared,
            "total_known": len(bridge.known_signatures),
        })

    @mcp_server.tool()
    async def mitigate_wifi_sensing(
        pcap_path: str | None = None,
        auto_apply: bool = False,
        router_host: str | None = None,
        router_type: str | None = None,
    ) -> str:
        """Analyze WiFi sensing threats and recommend software-only mitigations.

        Recommends ranked mitigations: router reconfiguration (channel, bandwidth,
        TX power, PMF, band steering), traffic orchestration, and legal documentation.
        Optionally auto-applies safe router changes with user confirmation.

        Args:
            pcap_path: Path to pcap file to analyze (or None for scan-only).
            auto_apply: If True, apply safe router changes (dry-run by default).
            router_host: Router hostname/IP for auto-apply.
            router_type: Router type (openwrt/unifi/tplink).
        """
        _init()

        def _mitigate():
            from goop_veil.mitigation.advisor import MitigationAdvisor
            from goop_veil.mitigation.router.base import create_router_adapter

            # Get detection result
            detection_result = None
            if pcap_path:
                path = Path(pcap_path)
                if path.exists():
                    anomalies = _beacon_scanner.scan_pcap(path)
                    threat_level, indicators = _traffic_analyzer.analyze_pcap(path)
                    detection_result = _alert_engine.assess(
                        devices=list(_beacon_scanner.devices.values()),
                        beacon_anomalies=anomalies,
                        traffic_indicators=indicators,
                        traffic_threat=threat_level,
                    )

            if detection_result is None:
                from goop_veil.models import DetectionResult, ThreatLevel
                detection_result = DetectionResult(threat_level=ThreatLevel.MEDIUM)

            # Set up router adapter if configured
            router_adapter = None
            if router_host and router_type:
                from goop_veil.config import RouterConfig
                rc = RouterConfig(
                    adapter_type=router_type,
                    host=router_host,
                    apply_changes=auto_apply,
                )
                router_adapter = create_router_adapter(rc)
                if router_adapter:
                    router_adapter.connect()

            advisor = MitigationAdvisor(
                config=_config.mitigation,
                router_adapter=router_adapter,
            )
            plan = advisor.assess_and_recommend(detection_result)

            applied = []
            if auto_apply and router_adapter:
                applied = advisor.auto_apply(plan, dry_run=False)

            return plan, applied

        plan, applied = await asyncio.to_thread(_mitigate)

        return json.dumps({
            "threat_level": plan.threat_level.value,
            "recommendations": [
                {
                    "priority": r.priority,
                    "title": r.title,
                    "category": r.category.value,
                    "effectiveness": r.effectiveness_score,
                    "difficulty": r.difficulty.value,
                    "auto_applicable": r.auto_applicable,
                    "wifi_impact": r.wifi_impact,
                }
                for r in plan.recommendations
            ],
            "auto_applied": applied,
            "estimated_effectiveness": plan.estimated_effectiveness,
            "summary": plan.summary,
        })

    @mcp_server.tool()
    async def generate_evidence_report(
        pcap_path: str | None = None,
        output_dir: str = "data/legal",
        include_fcc_complaint: bool = True,
        include_cease_desist: bool = True,
    ) -> str:
        """Generate a legal evidence package from WiFi sensing detection results.

        Creates timestamped, HMAC-signed documentation suitable for filing
        FCC complaints, cease-and-desist letters, or law enforcement reports.
        All documents include a disclaimer that they are not legal advice.

        Args:
            pcap_path: Path to pcap file with detection data.
            output_dir: Directory for generated documents.
            include_fcc_complaint: Generate FCC complaint template.
            include_cease_desist: Generate cease-and-desist template.
        """
        _init()

        def _generate():
            from goop_veil.mitigation.legal.evidence import EvidencePackageGenerator

            # Get detection results
            results = []
            alerts = list(_alert_engine.alerts) if _alert_engine else []

            if pcap_path:
                path = Path(pcap_path)
                if path.exists():
                    anomalies = _beacon_scanner.scan_pcap(path)
                    threat_level, indicators = _traffic_analyzer.analyze_pcap(path)
                    result = _alert_engine.assess(
                        devices=list(_beacon_scanner.devices.values()),
                        beacon_anomalies=anomalies,
                        traffic_indicators=indicators,
                        traffic_threat=threat_level,
                    )
                    results.append(result)
                    alerts = list(_alert_engine.alerts)

            from goop_veil.config import LegalConfig
            legal_config = LegalConfig(output_dir=output_dir)
            generator = EvidencePackageGenerator(config=legal_config)

            package = generator.generate(
                detection_results=results,
                alerts=alerts,
                output_dir=output_dir,
                include_fcc_complaint=include_fcc_complaint,
                include_cease_desist=include_cease_desist,
            )
            return package

        package = await asyncio.to_thread(_generate)

        return json.dumps({
            "output_path": package.output_path,
            "report_hash": package.report_hash,
            "device_fingerprints": len(package.device_fingerprints),
            "timeline_events": len(package.timeline),
            "disclaimer": package.disclaimer[:100] + "...",
        })

    return mcp_server


def main() -> None:
    """Run the goop-veil MCP server on stdio transport."""
    logger.info("Starting goop-veil MCP server")
    mcp_server = _create_mcp_server()
    mcp_server.run(transport="stdio")


if __name__ == "__main__":
    main()
