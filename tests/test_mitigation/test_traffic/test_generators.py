"""Tests for traffic pattern generators.

All external I/O is mocked — no real network calls are made.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from goop_veil.mitigation.traffic.generators import (
    ALL_GENERATORS,
    BaseTrafficGenerator,
    CloudSyncGenerator,
    DNSPrefetchGenerator,
    HTTPKeepAliveGenerator,
    NTPSyncGenerator,
    StreamSimulatorGenerator,
    TrafficPattern,
)


# ---------------------------------------------------------------------------
# TrafficPattern
# ---------------------------------------------------------------------------


class TestTrafficPattern:
    def test_creation(self) -> None:
        p = TrafficPattern(
            name="test",
            protocol="https",
            target="example.com",
            bandwidth_mbps=1.0,
            duration_sec=60.0,
            interval_sec=5.0,
        )
        assert p.name == "test"
        assert p.protocol == "https"
        assert p.target == "example.com"
        assert p.bandwidth_mbps == 1.0
        assert p.duration_sec == 60.0
        assert p.interval_sec == 5.0

    def test_repr(self) -> None:
        p = TrafficPattern("t", "dns", "resolver", 0.01, 30.0, 1.0)
        r = repr(p)
        assert "t" in r
        assert "dns" in r


# ---------------------------------------------------------------------------
# Generator-level tests (parameterized across all implementations)
# ---------------------------------------------------------------------------


@pytest.fixture(
    params=[
        HTTPKeepAliveGenerator,
        DNSPrefetchGenerator,
        StreamSimulatorGenerator,
        NTPSyncGenerator,
        CloudSyncGenerator,
    ]
)
def generator(request: pytest.FixtureRequest) -> BaseTrafficGenerator:
    return request.param()


class TestAllGenerators:
    def test_generates_valid_pattern(self, generator: BaseTrafficGenerator) -> None:
        pattern = generator.generate(duration_sec=60.0)
        assert isinstance(pattern, TrafficPattern)
        assert pattern.duration_sec == 60.0
        assert pattern.bandwidth_mbps > 0
        assert pattern.interval_sec > 0
        assert pattern.name == generator.name
        assert len(pattern.protocol) > 0

    def test_bandwidth_positive_and_reasonable(self, generator: BaseTrafficGenerator) -> None:
        bw = generator.estimated_bandwidth_mbps
        assert bw > 0
        assert bw <= 25.0  # no generator should exceed 25 Mbps

    def test_name_is_non_empty_string(self, generator: BaseTrafficGenerator) -> None:
        assert isinstance(generator.name, str)
        assert len(generator.name) > 0

    def test_not_running_initially(self, generator: BaseTrafficGenerator) -> None:
        assert not generator.is_running


class TestAllGeneratorsHaveUniqueNames:
    def test_unique_names(self) -> None:
        names = [cls().name for cls in ALL_GENERATORS]
        assert len(names) == len(set(names)), f"Duplicate generator names: {names}"


# ---------------------------------------------------------------------------
# HTTPKeepAliveGenerator
# ---------------------------------------------------------------------------


class TestHTTPKeepAliveGenerator:
    def test_default_targets(self) -> None:
        gen = HTTPKeepAliveGenerator()
        assert len(gen._targets) > 0

    def test_custom_targets(self) -> None:
        gen = HTTPKeepAliveGenerator(targets=["https://example.com"])
        assert gen._targets == ["https://example.com"]

    def test_execute_success(self) -> None:
        mock_httpx = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.read.return_value = b""
        mock_httpx.get.return_value = mock_resp

        gen = HTTPKeepAliveGenerator(targets=["https://example.com"])
        pattern = gen.generate(60.0)

        # Patch httpx at the import location inside execute
        with patch.dict("sys.modules", {"httpx": mock_httpx}):
            result = gen.execute(pattern)
        assert result is True

    def test_execute_no_httpx(self) -> None:
        gen = HTTPKeepAliveGenerator()
        pattern = gen.generate(60.0)
        with patch.dict("sys.modules", {"httpx": None}):
            # ImportError path
            result = gen.execute(pattern)
            assert result is False


# ---------------------------------------------------------------------------
# DNSPrefetchGenerator
# ---------------------------------------------------------------------------


class TestDNSPrefetchGenerator:
    def test_default_domains(self) -> None:
        gen = DNSPrefetchGenerator()
        assert len(gen._domains) >= 5

    @patch("goop_veil.mitigation.traffic.generators.socket.getaddrinfo")
    def test_execute_resolves_domains(self, mock_getaddr: MagicMock) -> None:
        mock_getaddr.return_value = [
            (2, 1, 6, "", ("93.184.216.34", 443))
        ]
        gen = DNSPrefetchGenerator(domains=["example.com", "example.org"])
        pattern = gen.generate(30.0)
        result = gen.execute(pattern)
        assert result is True
        assert mock_getaddr.call_count == 2

    @patch("goop_veil.mitigation.traffic.generators.socket.getaddrinfo")
    def test_execute_handles_resolution_failure(self, mock_getaddr: MagicMock) -> None:
        import socket

        mock_getaddr.side_effect = socket.gaierror("name resolution failed")
        gen = DNSPrefetchGenerator(domains=["nonexistent.invalid"])
        pattern = gen.generate(30.0)
        result = gen.execute(pattern)
        assert result is False


# ---------------------------------------------------------------------------
# StreamSimulatorGenerator
# ---------------------------------------------------------------------------


class TestStreamSimulatorGenerator:
    def test_bandwidth_capped_at_25(self) -> None:
        gen = StreamSimulatorGenerator(bandwidth_mbps=100.0)
        assert gen.estimated_bandwidth_mbps <= 25.0

    def test_bandwidth_floor_at_01(self) -> None:
        gen = StreamSimulatorGenerator(bandwidth_mbps=0.001)
        assert gen.estimated_bandwidth_mbps >= 0.1

    def test_respects_configured_bandwidth(self) -> None:
        gen = StreamSimulatorGenerator(bandwidth_mbps=15.0)
        assert gen.estimated_bandwidth_mbps == 15.0


# ---------------------------------------------------------------------------
# NTPSyncGenerator
# ---------------------------------------------------------------------------


class TestNTPSyncGenerator:
    def test_default_servers(self) -> None:
        gen = NTPSyncGenerator()
        assert len(gen._servers) >= 2

    @patch("goop_veil.mitigation.traffic.generators.socket.socket")
    @patch("goop_veil.mitigation.traffic.generators.socket.getaddrinfo")
    def test_execute_queries_servers(
        self, mock_getaddr: MagicMock, mock_socket_cls: MagicMock
    ) -> None:
        mock_getaddr.return_value = [
            (2, 2, 17, "", ("132.163.96.5", 123))
        ]
        mock_sock = MagicMock()
        mock_sock.recvfrom.return_value = (b"\x00" * 48, ("132.163.96.5", 123))
        mock_socket_cls.return_value = mock_sock

        gen = NTPSyncGenerator(servers=["pool.ntp.org"])
        pattern = gen.generate(30.0)
        result = gen.execute(pattern)
        assert result is True
        mock_sock.sendto.assert_called_once()


# ---------------------------------------------------------------------------
# CloudSyncGenerator
# ---------------------------------------------------------------------------


class TestCloudSyncGenerator:
    def test_bandwidth_capped_at_10(self) -> None:
        gen = CloudSyncGenerator(bandwidth_mbps=50.0)
        assert gen.estimated_bandwidth_mbps <= 10.0

    def test_bandwidth_floor_at_01(self) -> None:
        gen = CloudSyncGenerator(bandwidth_mbps=0.001)
        assert gen.estimated_bandwidth_mbps >= 0.1
