"""Traffic pattern generators that create legitimate network activity.

Each generator produces real protocol traffic (HTTP, DNS, NTP, etc.) that
degrades CSI sensing quality through RF diversity.  All traffic is genuine
protocol traffic routed through standard OS networking stacks.

Reference: "Et Tu Alexa?" — co-channel legitimate traffic drops attacker
detection rate to 47% (UChicago, NDSS 2020).
"""

from __future__ import annotations

import logging
import socket
import threading
import time
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# TrafficPattern value object
# ---------------------------------------------------------------------------


class TrafficPattern:
    """Represents a scheduled traffic pattern produced by a generator."""

    __slots__ = ("name", "protocol", "target", "bandwidth_mbps", "duration_sec", "interval_sec")

    def __init__(
        self,
        name: str,
        protocol: str,
        target: str,
        bandwidth_mbps: float,
        duration_sec: float,
        interval_sec: float,
    ) -> None:
        self.name = name
        self.protocol = protocol
        self.target = target
        self.bandwidth_mbps = bandwidth_mbps
        self.duration_sec = duration_sec
        self.interval_sec = interval_sec

    def __repr__(self) -> str:
        return (
            f"TrafficPattern(name={self.name!r}, protocol={self.protocol!r}, "
            f"target={self.target!r}, bw={self.bandwidth_mbps}Mbps, "
            f"dur={self.duration_sec}s, interval={self.interval_sec}s)"
        )


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------


class BaseTrafficGenerator(ABC):
    """Abstract base for traffic generators.

    Subclasses produce real, legitimate protocol traffic that creates
    RF diversity on the local WiFi channel.
    """

    def __init__(self) -> None:
        self._running = False
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    @abstractmethod
    def generate(self, duration_sec: float) -> TrafficPattern:
        """Create a traffic pattern descriptor for the given duration."""
        ...

    @abstractmethod
    def execute(self, pattern: TrafficPattern) -> bool:
        """Execute a traffic pattern.  Returns True on success."""
        ...

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique name for this generator."""
        ...

    @property
    @abstractmethod
    def estimated_bandwidth_mbps(self) -> float:
        """Estimated bandwidth consumption in Mbps."""
        ...

    @property
    def is_running(self) -> bool:
        return self._running

    def start(self, duration_sec: float) -> None:
        """Start the generator in a background thread."""
        if self._running:
            return
        self._stop_event.clear()
        pattern = self.generate(duration_sec)
        self._thread = threading.Thread(
            target=self._run_loop,
            args=(pattern,),
            daemon=True,
            name=f"traffic-{self.name}",
        )
        self._running = True
        self._thread.start()
        logger.info("Started traffic generator: %s", self.name)

    def stop(self) -> None:
        """Stop the generator."""
        if not self._running:
            return
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None
        self._running = False
        logger.info("Stopped traffic generator: %s", self.name)

    def _run_loop(self, pattern: TrafficPattern) -> None:
        """Execute the pattern repeatedly until stopped or duration elapses."""
        deadline = time.monotonic() + pattern.duration_sec
        while not self._stop_event.is_set() and time.monotonic() < deadline:
            try:
                self.execute(pattern)
            except Exception:
                logger.exception("Traffic generator %s error", self.name)
            self._stop_event.wait(timeout=pattern.interval_sec)
        self._running = False


# ---------------------------------------------------------------------------
# Concrete generators
# ---------------------------------------------------------------------------


class HTTPKeepAliveGenerator(BaseTrafficGenerator):
    """Maintains HTTPS connections to well-known services.

    Creates unpredictable traffic bursts by fetching small resources from
    public endpoints using standard HTTP/1.1 keep-alive connections.
    """

    #: Public endpoints used for legitimate traffic generation
    DEFAULT_TARGETS: list[str] = [
        "https://www.google.com/generate_204",
        "https://detectportal.firefox.com/success.txt",
        "https://connectivity-check.ubuntu.com/",
        "https://www.apple.com/library/test/success.html",
    ]

    def __init__(self, targets: list[str] | None = None) -> None:
        super().__init__()
        self._targets = targets or self.DEFAULT_TARGETS

    @property
    def name(self) -> str:
        return "http_keepalive"

    @property
    def estimated_bandwidth_mbps(self) -> float:
        return 0.5

    def generate(self, duration_sec: float) -> TrafficPattern:
        return TrafficPattern(
            name=self.name,
            protocol="https",
            target=self._targets[0],
            bandwidth_mbps=self.estimated_bandwidth_mbps,
            duration_sec=duration_sec,
            interval_sec=2.0,
        )

    def execute(self, pattern: TrafficPattern) -> bool:
        """Fetch a small resource via HTTPS."""
        try:
            import httpx  # deferred — optional dependency
        except ImportError:
            logger.debug("httpx not available; HTTP keepalive generator inactive")
            return False

        for target in self._targets:
            if self._stop_event.is_set():
                return False
            try:
                resp = httpx.get(target, timeout=5.0, follow_redirects=True)
                resp.read()
                logger.debug("HTTP keepalive: %s -> %d", target, resp.status_code)
            except Exception:
                logger.debug("HTTP keepalive target unreachable: %s", target)
        return True


class DNSPrefetchGenerator(BaseTrafficGenerator):
    """DNS resolution bursts — lightweight, legitimate traffic spikes.

    Resolves lists of common domains via the system resolver, generating
    small UDP packets that contribute to RF diversity.
    """

    DEFAULT_DOMAINS: list[str] = [
        "www.google.com",
        "www.cloudflare.com",
        "www.amazon.com",
        "www.microsoft.com",
        "www.apple.com",
        "github.com",
        "www.wikipedia.org",
        "www.reddit.com",
        "cdn.jsdelivr.net",
        "fonts.googleapis.com",
    ]

    def __init__(self, domains: list[str] | None = None) -> None:
        super().__init__()
        self._domains = domains or self.DEFAULT_DOMAINS

    @property
    def name(self) -> str:
        return "dns_prefetch"

    @property
    def estimated_bandwidth_mbps(self) -> float:
        return 0.005

    def generate(self, duration_sec: float) -> TrafficPattern:
        return TrafficPattern(
            name=self.name,
            protocol="dns",
            target="system_resolver",
            bandwidth_mbps=self.estimated_bandwidth_mbps,
            duration_sec=duration_sec,
            interval_sec=1.0,
        )

    def execute(self, pattern: TrafficPattern) -> bool:
        """Resolve a batch of domains via the system resolver."""
        resolved = 0
        for domain in self._domains:
            if self._stop_event.is_set():
                return False
            try:
                socket.getaddrinfo(domain, 443, socket.AF_UNSPEC, socket.SOCK_STREAM)
                resolved += 1
            except socket.gaierror:
                logger.debug("DNS resolution failed: %s", domain)
        logger.debug("DNS prefetch: resolved %d/%d domains", resolved, len(self._domains))
        return resolved > 0


class StreamSimulatorGenerator(BaseTrafficGenerator):
    """Simulates streaming media traffic patterns.

    Downloads from public speed-test endpoints using legitimate HTTP range
    requests.  Bandwidth is configurable (5-25 Mbps).
    """

    #: Public endpoints that serve large test files
    DEFAULT_TARGETS: list[str] = [
        "https://speed.cloudflare.com/__down?bytes=1048576",
        "https://proof.ovh.net/files/1Mb.dat",
    ]

    def __init__(
        self,
        targets: list[str] | None = None,
        bandwidth_mbps: float = 10.0,
    ) -> None:
        super().__init__()
        self._targets = targets or self.DEFAULT_TARGETS
        self._bandwidth_mbps = max(0.1, min(bandwidth_mbps, 25.0))

    @property
    def name(self) -> str:
        return "stream_simulator"

    @property
    def estimated_bandwidth_mbps(self) -> float:
        return self._bandwidth_mbps

    def generate(self, duration_sec: float) -> TrafficPattern:
        return TrafficPattern(
            name=self.name,
            protocol="https",
            target=self._targets[0],
            bandwidth_mbps=self.estimated_bandwidth_mbps,
            duration_sec=duration_sec,
            interval_sec=0.5,
        )

    def execute(self, pattern: TrafficPattern) -> bool:
        """Download chunks from a public endpoint."""
        try:
            import httpx  # deferred — optional dependency
        except ImportError:
            logger.debug("httpx not available; stream simulator generator inactive")
            return False

        target = self._targets[0]
        try:
            # Download ~1 MB chunk per cycle
            resp = httpx.get(target, timeout=10.0)
            _ = resp.content
            logger.debug("Stream simulator: fetched %d bytes from %s", len(resp.content), target)
            return True
        except Exception:
            logger.debug("Stream simulator target unreachable: %s", target)
            return False


class NTPSyncGenerator(BaseTrafficGenerator):
    """NTP synchronization bursts.

    Queries public NTP pools to create small, regular UDP traffic patterns.
    Bandwidth is negligible but the packets contribute to RF diversity.
    """

    DEFAULT_SERVERS: list[str] = [
        "pool.ntp.org",
        "time.google.com",
        "time.cloudflare.com",
        "time.apple.com",
    ]

    def __init__(self, servers: list[str] | None = None) -> None:
        super().__init__()
        self._servers = servers or self.DEFAULT_SERVERS

    @property
    def name(self) -> str:
        return "ntp_sync"

    @property
    def estimated_bandwidth_mbps(self) -> float:
        return 0.001

    def generate(self, duration_sec: float) -> TrafficPattern:
        return TrafficPattern(
            name=self.name,
            protocol="ntp",
            target=self._servers[0],
            bandwidth_mbps=self.estimated_bandwidth_mbps,
            duration_sec=duration_sec,
            interval_sec=5.0,
        )

    def execute(self, pattern: TrafficPattern) -> bool:
        """Send NTP queries to public pool servers.

        Uses a minimal NTP v3 client packet (48 bytes) and reads the reply.
        """
        queried = 0
        for server in self._servers:
            if self._stop_event.is_set():
                return False
            try:
                # Minimal NTP v3 client request: LI=0, VN=3, Mode=3
                ntp_packet = b"\x1b" + 47 * b"\x00"
                addr_info = socket.getaddrinfo(server, 123, socket.AF_UNSPEC, socket.SOCK_DGRAM)
                if not addr_info:
                    continue
                family, stype, proto, _, sockaddr = addr_info[0]
                sock = socket.socket(family, stype, proto)
                sock.settimeout(3.0)
                try:
                    sock.sendto(ntp_packet, sockaddr)
                    sock.recvfrom(1024)
                    queried += 1
                finally:
                    sock.close()
            except (OSError, socket.timeout):
                logger.debug("NTP query failed: %s", server)
        logger.debug("NTP sync: queried %d/%d servers", queried, len(self._servers))
        return queried > 0


class CloudSyncGenerator(BaseTrafficGenerator):
    """Simulates cloud backup/sync traffic patterns.

    Uploads and downloads data to/from public endpoints, mimicking
    the traffic shape of cloud storage synchronization.
    Bandwidth: 1-10 Mbps (configurable).
    """

    DEFAULT_TARGETS: list[str] = [
        "https://httpbin.org/post",
        "https://httpbin.org/get",
    ]

    def __init__(
        self,
        targets: list[str] | None = None,
        bandwidth_mbps: float = 2.0,
    ) -> None:
        super().__init__()
        self._targets = targets or self.DEFAULT_TARGETS
        self._bandwidth_mbps = max(0.1, min(bandwidth_mbps, 10.0))

    @property
    def name(self) -> str:
        return "cloud_sync"

    @property
    def estimated_bandwidth_mbps(self) -> float:
        return self._bandwidth_mbps

    def generate(self, duration_sec: float) -> TrafficPattern:
        return TrafficPattern(
            name=self.name,
            protocol="https",
            target=self._targets[0],
            bandwidth_mbps=self.estimated_bandwidth_mbps,
            duration_sec=duration_sec,
            interval_sec=1.0,
        )

    def execute(self, pattern: TrafficPattern) -> bool:
        """Upload/download data to/from cloud endpoints."""
        try:
            import httpx  # deferred — optional dependency
        except ImportError:
            logger.debug("httpx not available; cloud sync generator inactive")
            return False

        # Simulate upload: POST random-ish data
        chunk_size = int(self._bandwidth_mbps * 125_000)  # bytes per second -> per cycle
        payload = b"\x00" * min(chunk_size, 1_048_576)  # cap at 1 MB per cycle

        for target in self._targets:
            if self._stop_event.is_set():
                return False
            try:
                if "/post" in target:
                    resp = httpx.post(target, content=payload, timeout=10.0)
                else:
                    resp = httpx.get(target, timeout=10.0)
                logger.debug("Cloud sync: %s -> %d", target, resp.status_code)
            except Exception:
                logger.debug("Cloud sync target unreachable: %s", target)
        return True


# ---------------------------------------------------------------------------
# Registry helper
# ---------------------------------------------------------------------------

ALL_GENERATORS: list[type[BaseTrafficGenerator]] = [
    HTTPKeepAliveGenerator,
    DNSPrefetchGenerator,
    StreamSimulatorGenerator,
    NTPSyncGenerator,
    CloudSyncGenerator,
]
