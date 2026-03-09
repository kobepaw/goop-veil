"""Tests for BeaconScanner — WiFi sensing mesh detection via beacon analysis.

Uses conftest fixtures to generate valid 802.11 beacon frames compatible
with the Rust parser.
"""

from __future__ import annotations

import pytest

from goop_veil.config import DetectionConfig
from goop_veil.detection.beacon_scanner import BeaconScanner, SENSING_SSID_PATTERNS


# Espressif OUI prefix (24:0A:C4) — recognized by the Rust is_espressif_oui()
ESPRESSIF_MAC_1 = "24:0a:c4:00:11:01"
ESPRESSIF_MAC_2 = "24:0a:c4:00:11:02"
ESPRESSIF_MAC_3 = "30:ae:a4:00:22:03"

# Non-Espressif MAC
GENERIC_MAC = "00:11:22:33:44:55"


class TestBeaconScannerBasic:
    """Basic scanning with individual frames."""

    def test_scan_empty_list(self, make_beacon):
        scanner = BeaconScanner()
        anomalies = scanner.scan_frames([])
        assert anomalies == []
        assert scanner.devices == {}

    def test_scan_non_espressif_beacon(self, make_beacon):
        frame = make_beacon(ssid="HomeNetwork", mac=GENERIC_MAC)
        scanner = BeaconScanner()
        anomalies = scanner.scan_frames([frame])
        # Non-Espressif device with normal SSID should not produce espressif anomaly
        assert all(a.anomaly_type != "espressif_device" for a in anomalies)

    def test_scan_espressif_beacon(self, make_beacon):
        frame = make_beacon(ssid="MyNetwork", mac=ESPRESSIF_MAC_1)
        scanner = BeaconScanner()
        anomalies = scanner.scan_frames([frame])
        # Should detect espressif_device anomaly
        espressif_anomalies = [a for a in anomalies if a.anomaly_type == "espressif_device"]
        assert len(espressif_anomalies) >= 1
        assert espressif_anomalies[0].score == 0.4

    def test_device_tracking(self, make_beacon):
        frame = make_beacon(ssid="TestNet", mac=ESPRESSIF_MAC_1)
        scanner = BeaconScanner()
        scanner.scan_frames([frame])
        devices = scanner.devices
        assert ESPRESSIF_MAC_1 in devices
        assert devices[ESPRESSIF_MAC_1].is_espressif is True
        assert devices[ESPRESSIF_MAC_1].vendor == "Espressif"


class TestHiddenSSID:
    """Hidden SSID detection."""

    def test_hidden_ssid_detected(self, make_beacon):
        frame = make_beacon(ssid="", mac=GENERIC_MAC)
        scanner = BeaconScanner()
        anomalies = scanner.scan_frames([frame])
        hidden_anomalies = [a for a in anomalies if a.anomaly_type == "hidden_ssid"]
        assert len(hidden_anomalies) == 1
        assert hidden_anomalies[0].score == 0.3

    def test_normal_ssid_not_hidden(self, make_beacon):
        frame = make_beacon(ssid="VisibleNetwork", mac=GENERIC_MAC)
        scanner = BeaconScanner()
        anomalies = scanner.scan_frames([frame])
        hidden_anomalies = [a for a in anomalies if a.anomaly_type == "hidden_ssid"]
        assert len(hidden_anomalies) == 0


class TestSuspiciousSSID:
    """Suspicious SSID pattern detection."""

    def test_sensing_ssid_detected(self, make_beacon):
        frame = make_beacon(ssid="RuView_Mesh", mac=GENERIC_MAC)
        scanner = BeaconScanner()
        anomalies = scanner.scan_frames([frame])
        suspicious = [a for a in anomalies if a.anomaly_type == "suspicious_ssid"]
        assert len(suspicious) == 1
        assert suspicious[0].score == 0.8

    def test_esp_mesh_ssid_detected(self, make_beacon):
        frame = make_beacon(ssid="esp_mesh_network", mac=GENERIC_MAC)
        scanner = BeaconScanner()
        anomalies = scanner.scan_frames([frame])
        suspicious = [a for a in anomalies if a.anomaly_type == "suspicious_ssid"]
        assert len(suspicious) == 1

    def test_wifi_csi_ssid_detected(self, make_beacon):
        frame = make_beacon(ssid="wifi_csi_test", mac=GENERIC_MAC)
        scanner = BeaconScanner()
        anomalies = scanner.scan_frames([frame])
        suspicious = [a for a in anomalies if a.anomaly_type == "suspicious_ssid"]
        assert len(suspicious) == 1

    def test_normal_ssid_not_suspicious(self, make_beacon):
        frame = make_beacon(ssid="Starbucks_WiFi", mac=GENERIC_MAC)
        scanner = BeaconScanner()
        anomalies = scanner.scan_frames([frame])
        suspicious = [a for a in anomalies if a.anomaly_type == "suspicious_ssid"]
        assert len(suspicious) == 0


class TestMeshPattern:
    """Multiple Espressif devices forming a mesh pattern."""

    def test_mesh_detected_with_threshold(self, make_beacon):
        """Two Espressif devices should trigger mesh detection (default threshold=2)."""
        frames = [
            make_beacon(ssid="Net1", mac=ESPRESSIF_MAC_1),
            make_beacon(ssid="Net2", mac=ESPRESSIF_MAC_2),
        ]
        scanner = BeaconScanner()
        anomalies = scanner.scan_frames(frames)
        mesh_anomalies = [a for a in anomalies if a.anomaly_type == "espressif_mesh"]
        assert len(mesh_anomalies) == 1
        assert mesh_anomalies[0].score >= 0.7

    def test_no_mesh_below_threshold(self, make_beacon):
        """Single Espressif device should not trigger mesh detection."""
        frames = [make_beacon(ssid="Net1", mac=ESPRESSIF_MAC_1)]
        scanner = BeaconScanner()
        anomalies = scanner.scan_frames(frames)
        mesh_anomalies = [a for a in anomalies if a.anomaly_type == "espressif_mesh"]
        assert len(mesh_anomalies) == 0

    def test_custom_threshold(self, make_beacon):
        """Higher threshold requires more devices."""
        config = DetectionConfig(espressif_device_threshold=3)
        frames = [
            make_beacon(ssid="Net1", mac=ESPRESSIF_MAC_1),
            make_beacon(ssid="Net2", mac=ESPRESSIF_MAC_2),
        ]
        scanner = BeaconScanner(config=config)
        anomalies = scanner.scan_frames(frames)
        mesh_anomalies = [a for a in anomalies if a.anomaly_type == "espressif_mesh"]
        assert len(mesh_anomalies) == 0


class TestMixedFrames:
    """Scanning with mixed frame types."""

    def test_non_beacon_frames_ignored(self, make_beacon, make_data_frame, make_probe_request):
        """Non-beacon frames should not be counted as beacon anomalies."""
        frames = [
            make_data_frame(src_mac=ESPRESSIF_MAC_1, dst_mac="11:22:33:44:55:66"),
            make_probe_request(ssid="Probe", mac=ESPRESSIF_MAC_2),
            make_beacon(ssid="BeaconNet", mac=ESPRESSIF_MAC_1),
        ]
        scanner = BeaconScanner()
        anomalies = scanner.scan_frames(frames)
        # Only the beacon should produce espressif_device anomaly
        espressif_anomalies = [a for a in anomalies if a.anomaly_type == "espressif_device"]
        assert len(espressif_anomalies) == 1


class TestScanReset:
    """Scanner reset clears state."""

    def test_reset_clears_devices(self, make_beacon):
        scanner = BeaconScanner()
        scanner.scan_frames([make_beacon(ssid="Test", mac=ESPRESSIF_MAC_1)])
        assert len(scanner.devices) > 0
        scanner.reset()
        assert len(scanner.devices) == 0


class TestScanPcap:
    """Scanning from pcap files."""

    def test_scan_pcap_basic(self, make_beacon, tmp_pcap):
        frames = [
            make_beacon(ssid="PcapNet", mac=ESPRESSIF_MAC_1),
            make_beacon(ssid="PcapNet2", mac=ESPRESSIF_MAC_2),
        ]
        pcap_path = tmp_pcap(frames)
        scanner = BeaconScanner()
        anomalies = scanner.scan_pcap(pcap_path)
        assert len(anomalies) >= 2  # At least espressif_device anomalies
        assert len(scanner.devices) == 2
