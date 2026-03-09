"""Shared fixtures for goop-veil tests.

Provides frame construction helpers, pcap file generation, and mock objects
that match the Rust core's expected 802.11 frame format.
"""

from __future__ import annotations

import struct
import tempfile
from pathlib import Path

import pytest

from goop_veil.config import VeilConfig
from goop_veil.hardware.esp32_hal import MockESP32HAL


# ---------------------------------------------------------------------------
# 802.11 frame construction helpers
# ---------------------------------------------------------------------------

# Espressif OUI prefix used in tests (24:0A:C4 is a real Espressif OUI)
ESPRESSIF_MAC = bytes([0x24, 0x0A, 0xC4, 0x00, 0x11, 0x22])

# Non-Espressif MAC used in tests
GENERIC_MAC = bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])


def _mac_str_to_bytes(mac: str) -> bytes:
    """Convert 'aa:bb:cc:dd:ee:ff' or raw hex string to 6 bytes."""
    clean = mac.replace(":", "").replace("-", "")
    return bytes.fromhex(clean)


@pytest.fixture
def make_beacon():
    """Create a valid 802.11 beacon frame that the Rust parser can handle.

    Frame layout:
      - Frame control: [0x80, 0x00] (management, subtype=8=beacon)
      - Duration: [0x00, 0x00]
      - Addr1 (dest, broadcast): ff:ff:ff:ff:ff:ff
      - Addr2 (source): mac parameter as 6 bytes
      - Addr3 (BSSID): same as addr2
      - Sequence control: [0x00, 0x00]
      - Fixed params (timestamp + interval + capability): 12 zero bytes
      - Tagged: SSID tag (id=0, len, ssid_bytes)
    """

    def _make(ssid: str = "TestNetwork", mac: str = "aa:bb:cc:dd:ee:01") -> bytes:
        mac_bytes = _mac_str_to_bytes(mac)
        frame = bytearray()
        # Frame control: type=0 (management), subtype=8 (beacon) -> 0x80, 0x00
        frame.extend([0x80, 0x00])
        # Duration
        frame.extend([0x00, 0x00])
        # Addr1 (destination, broadcast)
        frame.extend([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
        # Addr2 (source)
        frame.extend(mac_bytes)
        # Addr3 (BSSID) = same as source
        frame.extend(mac_bytes)
        # Sequence control
        frame.extend([0x00, 0x00])
        # Fixed parameters: timestamp(8) + interval(2) + capability(2) = 12 bytes
        frame.extend(bytes(12))
        # Tagged parameter: SSID (tag_id=0, length, data)
        ssid_bytes = ssid.encode("utf-8")
        frame.append(0x00)  # Tag ID: SSID
        frame.append(len(ssid_bytes))
        frame.extend(ssid_bytes)
        return bytes(frame)

    return _make


@pytest.fixture
def make_probe_request():
    """Create a valid 802.11 probe request frame.

    Frame layout:
      - Frame control: [0x40, 0x00] (management, subtype=4=probe_request)
      - Duration: [0x00, 0x00]
      - Addr1 (dest, broadcast): ff:ff:ff:ff:ff:ff
      - Addr2 (source): mac parameter as 6 bytes
      - Addr3 (BSSID, broadcast): ff:ff:ff:ff:ff:ff
      - Sequence control: [0x00, 0x00]
      - Tagged: SSID tag (no fixed params for probe requests)
    """

    def _make(ssid: str = "ProbeSSID", mac: str = "aa:bb:cc:dd:ee:02") -> bytes:
        mac_bytes = _mac_str_to_bytes(mac)
        frame = bytearray()
        # Frame control: type=0 (management), subtype=4 (probe request) -> 0x40, 0x00
        frame.extend([0x40, 0x00])
        # Duration
        frame.extend([0x00, 0x00])
        # Addr1 (destination, broadcast)
        frame.extend([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
        # Addr2 (source)
        frame.extend(mac_bytes)
        # Addr3 (BSSID, broadcast for probe req)
        frame.extend([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
        # Sequence control
        frame.extend([0x00, 0x00])
        # Tagged parameter: SSID (tag_id=0, length, data)
        # Probe requests have NO fixed params before tagged params
        ssid_bytes = ssid.encode("utf-8")
        frame.append(0x00)
        frame.append(len(ssid_bytes))
        frame.extend(ssid_bytes)
        return bytes(frame)

    return _make


@pytest.fixture
def make_data_frame():
    """Create a valid 802.11 data frame.

    Frame layout:
      - Frame control: [0x08, 0x00] (data, subtype=0=data)
      - Duration: [0x00, 0x00]
      - Addr1 (dest): dst_mac
      - Addr2 (source): src_mac
      - Addr3 (BSSID): src_mac (simplified)
      - Payload: 20 zero bytes
    """

    def _make(
        src_mac: str = "aa:bb:cc:dd:ee:01",
        dst_mac: str = "11:22:33:44:55:66",
    ) -> bytes:
        src_bytes = _mac_str_to_bytes(src_mac)
        dst_bytes = _mac_str_to_bytes(dst_mac)
        frame = bytearray()
        # Frame control: type=2 (data), subtype=0 -> 0x08, 0x00
        frame.extend([0x08, 0x00])
        # Duration
        frame.extend([0x00, 0x00])
        # Addr1 (destination)
        frame.extend(dst_bytes)
        # Addr2 (source)
        frame.extend(src_bytes)
        # Addr3 (BSSID)
        frame.extend(src_bytes)
        # Payload
        frame.extend(bytes(20))
        return bytes(frame)

    return _make


@pytest.fixture
def tmp_pcap(tmp_path):
    """Create a temporary pcap file from a list of frame bytes.

    Returns a function that accepts a list of raw frame bytes and returns
    the path to a valid pcap file with DLT_IEEE802_11 (105) linktype.

    pcap global header (24 bytes, little-endian):
      - magic: 0xa1b2c3d4
      - version: 2.4
      - timezone: 0
      - sigfigs: 0
      - snaplen: 65535
      - linktype: 105 (DLT_IEEE802_11)

    Per-frame record header (16 bytes, little-endian):
      - ts_sec, ts_usec, incl_len, orig_len
    """

    def _make(frames: list[bytes]) -> Path:
        pcap_path = tmp_path / "test.pcap"
        buf = bytearray()

        # Global header
        buf.extend(struct.pack("<I", 0xA1B2C3D4))  # magic
        buf.extend(struct.pack("<H", 2))  # version major
        buf.extend(struct.pack("<H", 4))  # version minor
        buf.extend(struct.pack("<i", 0))  # timezone
        buf.extend(struct.pack("<I", 0))  # sigfigs
        buf.extend(struct.pack("<I", 65535))  # snaplen
        buf.extend(struct.pack("<I", 105))  # linktype = DLT_IEEE802_11

        # Frame records
        for idx, frame_bytes in enumerate(frames):
            ts_sec = 1000 + idx
            ts_usec = idx * 1000
            incl_len = len(frame_bytes)
            orig_len = len(frame_bytes)
            buf.extend(struct.pack("<I", ts_sec))
            buf.extend(struct.pack("<I", ts_usec))
            buf.extend(struct.pack("<I", incl_len))
            buf.extend(struct.pack("<I", orig_len))
            buf.extend(frame_bytes)

        pcap_path.write_bytes(bytes(buf))
        return pcap_path

    return _make


@pytest.fixture
def veil_config():
    """Return a default VeilConfig instance."""
    return VeilConfig()


@pytest.fixture
def mock_hal():
    """Return a MockESP32HAL instance for testing without hardware."""
    return MockESP32HAL()
