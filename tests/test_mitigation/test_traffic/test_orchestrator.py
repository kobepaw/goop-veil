"""Tests for TrafficOrchestrator.

All generators are mocked — no real network calls are made.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from goop_veil.config import TrafficConfig
from goop_veil.mitigation.traffic.generators import BaseTrafficGenerator, TrafficPattern
from goop_veil.mitigation.traffic.orchestrator import TrafficOrchestrator


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _FakeGenerator(BaseTrafficGenerator):
    """Minimal concrete generator for testing."""

    def __init__(self, gen_name: str = "fake", bw: float = 1.0) -> None:
        super().__init__()
        self._name = gen_name
        self._bw = bw

    @property
    def name(self) -> str:
        return self._name

    @property
    def estimated_bandwidth_mbps(self) -> float:
        return self._bw

    def generate(self, duration_sec: float) -> TrafficPattern:
        return TrafficPattern(
            name=self._name,
            protocol="test",
            target="localhost",
            bandwidth_mbps=self._bw,
            duration_sec=duration_sec,
            interval_sec=1.0,
        )

    def execute(self, pattern: TrafficPattern) -> bool:
        return True


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestOrchestratorInit:
    def test_default_config(self) -> None:
        orch = TrafficOrchestrator()
        assert not orch.is_running
        assert orch._total_bandwidth_mbps == 0.0

    def test_custom_config(self) -> None:
        cfg = TrafficConfig(max_bandwidth_mbps=5.0)
        orch = TrafficOrchestrator(config=cfg)
        assert orch._config.max_bandwidth_mbps == 5.0


class TestAddGenerator:
    def test_add_within_cap(self) -> None:
        cfg = TrafficConfig(max_bandwidth_mbps=10.0)
        orch = TrafficOrchestrator(config=cfg)
        gen = _FakeGenerator(bw=5.0)
        orch.add_generator(gen)
        assert len(orch._generators) == 1
        assert orch._total_bandwidth_mbps == 5.0

    def test_add_multiple_within_cap(self) -> None:
        cfg = TrafficConfig(max_bandwidth_mbps=10.0)
        orch = TrafficOrchestrator(config=cfg)
        orch.add_generator(_FakeGenerator("a", bw=3.0))
        orch.add_generator(_FakeGenerator("b", bw=4.0))
        assert len(orch._generators) == 2
        assert orch._total_bandwidth_mbps == 7.0

    def test_add_exceeds_cap_raises(self) -> None:
        cfg = TrafficConfig(max_bandwidth_mbps=5.0)
        orch = TrafficOrchestrator(config=cfg)
        orch.add_generator(_FakeGenerator("a", bw=3.0))
        with pytest.raises(ValueError, match="exceed bandwidth cap"):
            orch.add_generator(_FakeGenerator("b", bw=3.0))

    def test_add_exactly_at_cap(self) -> None:
        cfg = TrafficConfig(max_bandwidth_mbps=5.0)
        orch = TrafficOrchestrator(config=cfg)
        orch.add_generator(_FakeGenerator("a", bw=5.0))
        assert orch._total_bandwidth_mbps == 5.0


class TestStartStop:
    def test_start_with_generators(self) -> None:
        cfg = TrafficConfig(max_bandwidth_mbps=10.0)
        orch = TrafficOrchestrator(config=cfg)
        gen = _FakeGenerator(bw=1.0)
        orch.add_generator(gen)

        result = orch.start(duration_sec=0.1)
        assert result["status"] == "started"
        assert result["generators"] == 1
        assert orch.is_running

        stop_result = orch.stop()
        assert stop_result["status"] == "stopped"
        assert not orch.is_running

    def test_start_no_generators(self) -> None:
        orch = TrafficOrchestrator()
        result = orch.start()
        assert result["status"] == "no_generators"
        assert not orch.is_running

    def test_start_already_running(self) -> None:
        orch = TrafficOrchestrator()
        orch.add_generator(_FakeGenerator(bw=1.0))
        orch.start(duration_sec=0.1)
        result = orch.start()
        assert result["status"] == "already_running"
        orch.stop()

    def test_stop_when_not_running(self) -> None:
        orch = TrafficOrchestrator()
        result = orch.stop()
        assert result["status"] == "not_running"

    def test_start_returns_bandwidth_info(self) -> None:
        cfg = TrafficConfig(max_bandwidth_mbps=10.0)
        orch = TrafficOrchestrator(config=cfg)
        orch.add_generator(_FakeGenerator(bw=2.5))
        result = orch.start(duration_sec=0.1)
        assert result["total_bandwidth_mbps"] == 2.5
        orch.stop()

    def test_stop_returns_uptime(self) -> None:
        orch = TrafficOrchestrator()
        orch.add_generator(_FakeGenerator(bw=1.0))
        orch.start(duration_sec=0.1)
        result = orch.stop()
        assert "uptime_sec" in result
        assert result["uptime_sec"] >= 0


class TestGetStatus:
    def test_status_keys(self) -> None:
        orch = TrafficOrchestrator()
        status = orch.get_status()
        expected_keys = {
            "running",
            "generator_count",
            "total_bandwidth_mbps",
            "max_bandwidth_mbps",
            "uptime_sec",
            "generators",
        }
        assert set(status.keys()) == expected_keys

    def test_status_not_running(self) -> None:
        orch = TrafficOrchestrator()
        status = orch.get_status()
        assert status["running"] is False
        assert status["generator_count"] == 0
        assert status["uptime_sec"] == 0

    def test_status_with_generators(self) -> None:
        orch = TrafficOrchestrator()
        orch.add_generator(_FakeGenerator("alpha", bw=2.0))
        status = orch.get_status()
        assert status["generator_count"] == 1
        assert len(status["generators"]) == 1
        assert status["generators"][0]["name"] == "alpha"
        assert status["generators"][0]["bandwidth_mbps"] == 2.0


class TestCreateDefaultGenerators:
    def test_stays_under_cap(self) -> None:
        cfg = TrafficConfig(max_bandwidth_mbps=10.0)
        orch = TrafficOrchestrator(config=cfg)
        orch.create_default_generators()
        assert orch._total_bandwidth_mbps <= cfg.max_bandwidth_mbps
        assert len(orch._generators) >= 2  # at least DNS + HTTP

    def test_small_cap_gets_lightweight_only(self) -> None:
        cfg = TrafficConfig(max_bandwidth_mbps=0.6)
        orch = TrafficOrchestrator(config=cfg)
        orch.create_default_generators()
        assert orch._total_bandwidth_mbps <= 0.6
        # Should have at least DNS (0.005 Mbps) + HTTP (0.5 Mbps)
        names = [g.name for g in orch._generators]
        assert "dns_prefetch" in names

    def test_large_cap_includes_streaming(self) -> None:
        cfg = TrafficConfig(max_bandwidth_mbps=20.0)
        orch = TrafficOrchestrator(config=cfg)
        orch.create_default_generators()
        names = [g.name for g in orch._generators]
        assert "stream_simulator" in names

    def test_is_running_reflects_state(self) -> None:
        orch = TrafficOrchestrator()
        assert orch.is_running is False
        orch.add_generator(_FakeGenerator(bw=1.0))
        orch.start(duration_sec=0.1)
        assert orch.is_running is True
        orch.stop()
        assert orch.is_running is False
