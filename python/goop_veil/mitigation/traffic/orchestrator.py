"""Traffic orchestrator — manages multiple traffic generators for RF diversity.

Coordinates generators to stay within a bandwidth cap while maximizing
the RF diversity that degrades CSI-based sensing quality.
"""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING

from goop_veil.mitigation.traffic.generators import (
    BaseTrafficGenerator,
    CloudSyncGenerator,
    DNSPrefetchGenerator,
    HTTPKeepAliveGenerator,
    StreamSimulatorGenerator,
)

if TYPE_CHECKING:
    from goop_veil.config import TrafficConfig

logger = logging.getLogger(__name__)


class TrafficOrchestrator:
    """Main controller for traffic-based RF diversity.

    Manages multiple :class:`BaseTrafficGenerator` instances, ensuring
    their aggregate bandwidth stays within the configured cap.
    """

    def __init__(self, config: TrafficConfig | None = None) -> None:
        if config is None:
            from goop_veil.config import TrafficConfig as _TC

            config = _TC()
        self._config = config
        self._generators: list[BaseTrafficGenerator] = []
        self._running = False
        self._total_bandwidth_mbps = 0.0
        self._start_time: float | None = None

    # ------------------------------------------------------------------
    # Generator management
    # ------------------------------------------------------------------

    def add_generator(self, generator: BaseTrafficGenerator) -> None:
        """Add a traffic generator, enforcing the bandwidth cap.

        Raises:
            ValueError: If adding this generator would exceed
                ``config.max_bandwidth_mbps``.
        """
        new_total = self._total_bandwidth_mbps + generator.estimated_bandwidth_mbps
        if new_total > self._config.max_bandwidth_mbps:
            raise ValueError(
                f"Adding {generator.name!r} ({generator.estimated_bandwidth_mbps} Mbps) "
                f"would exceed bandwidth cap "
                f"({new_total:.2f} > {self._config.max_bandwidth_mbps} Mbps)"
            )
        self._generators.append(generator)
        self._total_bandwidth_mbps = new_total
        logger.info(
            "Added generator %s (%.3f Mbps); total %.3f / %.1f Mbps",
            generator.name,
            generator.estimated_bandwidth_mbps,
            self._total_bandwidth_mbps,
            self._config.max_bandwidth_mbps,
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self, duration_sec: float = 3600.0) -> dict:
        """Start all generators.

        Validates total bandwidth before launching.  Returns a status dict.
        """
        if self._running:
            return {"status": "already_running", "generators": len(self._generators)}

        if not self._generators:
            return {"status": "no_generators", "generators": 0}

        if self._total_bandwidth_mbps > self._config.max_bandwidth_mbps:
            return {
                "status": "bandwidth_exceeded",
                "total_mbps": self._total_bandwidth_mbps,
                "cap_mbps": self._config.max_bandwidth_mbps,
            }

        for gen in self._generators:
            gen.start(duration_sec)

        self._running = True
        self._start_time = time.monotonic()
        logger.info(
            "Traffic orchestrator started: %d generators, %.3f Mbps total",
            len(self._generators),
            self._total_bandwidth_mbps,
        )
        return {
            "status": "started",
            "generators": len(self._generators),
            "total_bandwidth_mbps": self._total_bandwidth_mbps,
        }

    def stop(self) -> dict:
        """Stop all generators cleanly."""
        if not self._running:
            return {"status": "not_running"}

        for gen in self._generators:
            gen.stop()

        uptime = time.monotonic() - self._start_time if self._start_time else 0.0
        self._running = False
        self._start_time = None
        logger.info("Traffic orchestrator stopped after %.1f seconds", uptime)
        return {
            "status": "stopped",
            "generators": len(self._generators),
            "uptime_sec": round(uptime, 1),
        }

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    @property
    def is_running(self) -> bool:
        return self._running

    def get_status(self) -> dict:
        """Return current orchestrator status."""
        uptime = 0.0
        if self._running and self._start_time is not None:
            uptime = time.monotonic() - self._start_time

        return {
            "running": self._running,
            "generator_count": len(self._generators),
            "total_bandwidth_mbps": self._total_bandwidth_mbps,
            "max_bandwidth_mbps": self._config.max_bandwidth_mbps,
            "uptime_sec": round(uptime, 1),
            "generators": [
                {
                    "name": g.name,
                    "bandwidth_mbps": g.estimated_bandwidth_mbps,
                    "running": g.is_running,
                }
                for g in self._generators
            ],
        }

    # ------------------------------------------------------------------
    # Convenience
    # ------------------------------------------------------------------

    def create_default_generators(self) -> None:
        """Create a standard set of generators within the bandwidth cap.

        Adds generators in priority order (DNS, HTTP keepalive, stream
        simulator), stopping when the next generator would exceed the cap.
        """
        cap = self._config.max_bandwidth_mbps

        # Always add lightweight generators first
        candidates: list[BaseTrafficGenerator] = [
            DNSPrefetchGenerator(),
            HTTPKeepAliveGenerator(),
        ]

        # Scale streaming bandwidth to fit within remaining cap
        remaining = cap - sum(g.estimated_bandwidth_mbps for g in candidates)
        if remaining >= 1.0:
            stream_bw = min(remaining - 0.5, 15.0)  # leave headroom
            if stream_bw >= 1.0:
                candidates.append(StreamSimulatorGenerator(bandwidth_mbps=stream_bw))

        # Add cloud sync if space remains
        used = sum(g.estimated_bandwidth_mbps for g in candidates)
        cloud_remaining = cap - used
        if cloud_remaining >= 1.0:
            candidates.append(CloudSyncGenerator(bandwidth_mbps=min(cloud_remaining, 5.0)))

        for gen in candidates:
            if self._total_bandwidth_mbps + gen.estimated_bandwidth_mbps <= cap:
                self.add_generator(gen)
            else:
                logger.debug(
                    "Skipping %s (%.3f Mbps) — would exceed cap",
                    gen.name,
                    gen.estimated_bandwidth_mbps,
                )
