"""goop-veil CLI — typer application for WiFi privacy defense.

Commands:
  scan     — Scan nearby WiFi networks for sensing devices (no root needed)
  detect   — Analyze pcap file for WiFi sensing activity
  capture  — Capture live WiFi traffic to pcap (requires root)
  monitor  — Continuous monitoring with alerts
  assess   — Assess room vulnerability and recommend materials
  status   — Show system status and WiFi interface info
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

try:
    import typer
    from rich.console import Console
    from rich.table import Table
    _CLI_DEPS_AVAILABLE = True
except ImportError:
    _CLI_DEPS_AVAILABLE = False

    class _TyperShim:
        """Minimal shim so module import works without optional CLI deps."""

        class Exit(Exception):
            def __init__(self, code: int = 0) -> None:
                self.code = code
                super().__init__(f"CLI unavailable (exit code {code})")

        @staticmethod
        def Option(default=None, *args, **kwargs):
            return default

        @staticmethod
        def Argument(default=None, *args, **kwargs):
            return default

        class Typer:
            def __init__(self, *args, **kwargs) -> None:
                pass

            def command(self, *args, **kwargs):
                def decorator(func):
                    return func

                return decorator

            def __call__(self, *args, **kwargs):
                raise RuntimeError("CLI extras not installed")

    class _ConsoleShim:
        def print(self, *args, **kwargs) -> None:
            print(*args)

        def print_json(self, value: str) -> None:
            print(value)

    class _TableShim:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def add_column(self, *args, **kwargs) -> None:
            pass

        def add_row(self, *args, **kwargs) -> None:
            pass

    typer = _TyperShim()
    Console = _ConsoleShim
    Table = _TableShim

console = Console()

app = typer.Typer(
    name="goop-veil",
    help="WiFi privacy defense — detect, shield, and counter WiFi CSI surveillance",
)


# =============================================================================
# scan — zero root, zero hardware, works everywhere
# =============================================================================


@app.command()
def scan(
    interface: str | None = typer.Option(None, help="WiFi interface (auto-detected)"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Scan nearby WiFi networks for sensing devices.

    No root required. Uses nmcli or iw scan to find visible networks,
    then checks for Espressif OUIs, suspicious SSIDs, and sensing indicators.
    """
    from goop_veil._core import is_espressif_oui, lookup_oui
    from goop_veil.detection.beacon_scanner import SENSING_SSID_PATTERNS
    from goop_veil.hardware.wifi_hal import create_wifi_hal

    hal = create_wifi_hal(interface=interface, mode="scan")
    networks = hal.scan_networks()

    if not networks:
        console.print("[yellow]No networks found. Check WiFi is enabled.[/yellow]")
        raise typer.Exit(1)

    # Analyze each network
    suspicious: list[dict] = []
    for net in networks:
        bssid = net.get("bssid", "")
        ssid = net.get("ssid", "")
        flags: list[str] = []

        try:
            if is_espressif_oui(bssid):
                flags.append("espressif_hardware")
            vendor = lookup_oui(bssid)
            net["vendor"] = vendor
        except (ValueError, Exception):
            net["vendor"] = "Unknown"

        if ssid and any(p in ssid.lower() for p in SENSING_SSID_PATTERNS):
            flags.append("suspicious_ssid")

        if not ssid:
            flags.append("hidden_ssid")

        net["flags"] = flags
        if flags:
            suspicious.append(net)

    if json_output:
        console.print_json(json.dumps({
            "total_networks": len(networks),
            "suspicious_count": len(suspicious),
            "suspicious": suspicious,
            "all_networks": networks,
        }))
        return

    console.print(f"\n[bold]WiFi Network Scan[/bold]")
    console.print(f"Found {len(networks)} networks, {len(suspicious)} suspicious\n")

    table = Table(title="Nearby Networks")
    table.add_column("BSSID", style="cyan")
    table.add_column("SSID")
    table.add_column("Vendor")
    table.add_column("Ch", justify="right")
    table.add_column("Signal", justify="right")
    table.add_column("Flags")

    for net in networks:
        flags = net.get("flags", [])
        flag_str = ", ".join(flags) if flags else ""
        flag_style = "[red]" if flags else ""
        flag_end = "[/red]" if flags else ""

        table.add_row(
            net.get("bssid", ""),
            net.get("ssid", "[hidden]") or "[hidden]",
            net.get("vendor", "Unknown"),
            str(net.get("channel", "")),
            f"{net.get('signal_dbm', net.get('signal_pct', ''))}",
            f"{flag_style}{flag_str}{flag_end}",
        )

    console.print(table)

    if suspicious:
        console.print(f"\n[bold red]WARNING: {len(suspicious)} suspicious network(s) detected[/bold red]")
        for net in suspicious:
            console.print(f"  {net.get('bssid', '')} — {', '.join(net['flags'])}")
        console.print("\nRun [bold]goop-veil capture[/bold] for deeper analysis (requires root)")


# =============================================================================
# detect — analyze pcap file (software only)
# =============================================================================


@app.command()
def detect(
    pcap: Path = typer.Argument(..., help="Path to pcap file", exists=True),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Analyze a pcap file for WiFi sensing activity."""
    from goop_veil.config import VeilConfig
    from goop_veil.detection.alert_engine import AlertEngine
    from goop_veil.detection.beacon_scanner import BeaconScanner
    from goop_veil.detection.traffic_analyzer import TrafficAnalyzer

    config = VeilConfig()
    scanner = BeaconScanner(config.detection)
    analyzer = TrafficAnalyzer()
    engine = AlertEngine(config.detection)

    anomalies = scanner.scan_pcap(pcap)
    threat_level, indicators = analyzer.analyze_pcap(pcap)

    result = engine.assess(
        devices=list(scanner.devices.values()),
        beacon_anomalies=anomalies,
        traffic_indicators=indicators,
        traffic_threat=threat_level,
    )

    if json_output:
        console.print_json(json.dumps({
            "threat_level": result.threat_level.value,
            "confidence": result.confidence,
            "devices": len(result.devices),
            "anomalies": len(result.beacon_anomalies),
            "capabilities": [c.value for c in result.detected_capabilities],
            "summary": result.summary,
        }))
        return

    level_color = {
        "none": "green", "low": "yellow", "medium": "dark_orange",
        "high": "red", "confirmed": "bold red",
    }
    color = level_color.get(result.threat_level.value, "white")

    console.print(f"\n[bold]WiFi Sensing Detection Report[/bold]")
    console.print(f"Threat Level: [{color}]{result.threat_level.value.upper()}[/{color}]")
    console.print(f"Confidence: {result.confidence:.0%}")
    console.print(f"Summary: {result.summary}\n")

    if result.devices:
        table = Table(title="Detected Devices")
        table.add_column("MAC", style="cyan")
        table.add_column("Vendor")
        table.add_column("Espressif", justify="center")
        table.add_column("SSID")

        for device in result.devices:
            table.add_row(
                device.mac_address,
                device.vendor,
                "Y" if device.is_espressif else "",
                device.ssid or "",
            )
        console.print(table)


# =============================================================================
# capture — live WiFi capture to pcap (requires root for monitor mode)
# =============================================================================


@app.command()
def capture(
    output: Path = typer.Option("capture.pcap", help="Output pcap file path"),
    duration: float = typer.Option(30.0, help="Capture duration in seconds"),
    interface: str | None = typer.Option(None, help="WiFi interface (auto-detected)"),
    channel: int | None = typer.Option(None, help="WiFi channel to monitor (None=current)"),
    analyze: bool = typer.Option(True, help="Auto-analyze after capture"),
) -> None:
    """Capture live WiFi traffic to a pcap file.

    Requires root or CAP_NET_ADMIN for monitor mode capture.
    After capture, automatically runs detection analysis.
    """
    import os

    if os.geteuid() != 0:
        console.print("[yellow]Monitor mode capture requires root. Run with sudo.[/yellow]")
        console.print("Alternative: [bold]goop-veil scan[/bold] works without root.\n")
        raise typer.Exit(1)

    from goop_veil.hardware.wifi_hal import LinuxWiFiHAL

    hal = LinuxWiFiHAL(interface=interface)

    console.print(f"Starting monitor mode capture ({duration:.0f}s)...")
    if not hal.start_monitor(channel=channel):
        console.print("[red]Failed to enter monitor mode.[/red]")
        raise typer.Exit(1)

    try:
        if hal.capture_to_pcap(output, duration):
            size = output.stat().st_size
            console.print(f"[green]Captured to {output} ({size:,} bytes)[/green]")
        else:
            console.print("[red]Capture failed.[/red]")
            raise typer.Exit(1)
    finally:
        hal.stop_monitor()
        console.print("Restored managed mode.")

    if analyze and output.exists():
        console.print("\nRunning detection analysis...\n")
        detect(pcap=output, json_output=False)


# =============================================================================
# monitor — continuous scanning with alerts
# =============================================================================


@app.command()
def monitor(
    interface: str | None = typer.Option(None, help="WiFi interface (auto-detected)"),
    interval: float = typer.Option(60.0, help="Scan interval in seconds"),
    alert_threshold: int = typer.Option(1, help="Min suspicious networks to alert"),
) -> None:
    """Continuous WiFi monitoring with alerts.

    Repeatedly scans for nearby networks and flags suspicious activity.
    No root required — uses network scanning (not monitor mode).
    Press Ctrl+C to stop.
    """
    from goop_veil._core import is_espressif_oui
    from goop_veil.detection.beacon_scanner import SENSING_SSID_PATTERNS
    from goop_veil.hardware.wifi_hal import create_wifi_hal

    hal = create_wifi_hal(interface=interface, mode="scan")
    scan_count = 0

    console.print(f"[bold]Continuous WiFi monitoring[/bold] (interval={interval:.0f}s)")
    console.print("Press Ctrl+C to stop.\n")

    try:
        while True:
            scan_count += 1
            networks = hal.scan_networks()
            suspicious_count = 0

            for net in networks:
                bssid = net.get("bssid", "")
                ssid = net.get("ssid", "")
                try:
                    if is_espressif_oui(bssid):
                        suspicious_count += 1
                except (ValueError, Exception):
                    pass
                if ssid and any(p in ssid.lower() for p in SENSING_SSID_PATTERNS):
                    suspicious_count += 1

            timestamp = time.strftime("%H:%M:%S")
            if suspicious_count >= alert_threshold:
                console.print(
                    f"[{timestamp}] Scan #{scan_count}: "
                    f"[red]{suspicious_count} suspicious[/red] / {len(networks)} networks"
                )
            else:
                console.print(
                    f"[{timestamp}] Scan #{scan_count}: "
                    f"[green]clear[/green] ({len(networks)} networks)"
                )

            time.sleep(interval)

    except KeyboardInterrupt:
        console.print(f"\nStopped after {scan_count} scans.")


# =============================================================================
# assess — room vulnerability (pure software)
# =============================================================================


@app.command()
def assess(
    room: str = typer.Option("4.5x3.5x2.7", help="Room dimensions LxWxH in meters"),
    budget: float = typer.Option(100.0, help="Maximum budget in USD"),
    goal: str = typer.Option("hide_pose", help="Privacy goal"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Assess room vulnerability and recommend materials."""
    from goop_veil.config import VeilConfig
    from goop_veil.passive.placement_optimizer import PlacementOptimizer

    dims = [float(x) for x in room.split("x")]
    if len(dims) != 3:
        console.print("[red]Room dimensions must be LxWxH (e.g., 4.5x3.5x2.7)[/red]")
        raise typer.Exit(1)

    config = VeilConfig()
    optimizer = PlacementOptimizer(config.passive)

    result = optimizer.assess_room(
        room_length_m=dims[0],
        room_width_m=dims[1],
        room_height_m=dims[2],
        budget_usd=budget,
        target=goal,
    )

    if json_output:
        console.print_json(json.dumps({
            "vulnerability_score": result.vulnerability_score,
            "current_attenuation_db": result.current_attenuation_db,
            "target_attenuation_db": result.target_attenuation_db,
            "recommendations": [
                {
                    "material": r.material,
                    "location": r.location,
                    "attenuation_db": r.attenuation_db,
                    "cost_usd": r.cost_usd,
                }
                for r in result.recommendations
            ],
            "estimated_cost_usd": result.estimated_cost_usd,
            "summary": result.summary,
        }))
        return

    console.print(f"\n[bold]Room Vulnerability Assessment[/bold]")
    console.print(f"Room: {dims[0]}x{dims[1]}x{dims[2]}m")
    console.print(f"Vulnerability: {result.vulnerability_score:.0%}")
    console.print(f"Current attenuation: {result.current_attenuation_db:.1f} dB")
    console.print(f"Target attenuation: {result.target_attenuation_db:.1f} dB\n")

    if result.recommendations:
        table = Table(title="Material Recommendations")
        table.add_column("#", justify="right")
        table.add_column("Material")
        table.add_column("Location")
        table.add_column("Attenuation", justify="right")
        table.add_column("Cost", justify="right")

        for r in result.recommendations:
            table.add_row(
                str(r.priority),
                r.material,
                r.location,
                f"{r.attenuation_db:.1f} dB",
                f"${r.cost_usd:.0f}",
            )
        console.print(table)
        console.print(f"\n[bold]Estimated total: ${result.estimated_cost_usd:.0f}[/bold]")
    else:
        console.print("[green]Room already meets target attenuation[/green]")


# =============================================================================
# mitigate — recommend and apply countermeasures
# =============================================================================


@app.command()
def mitigate(
    pcap: Path | None = typer.Option(None, help="Path to pcap file for analysis"),
    auto_apply: bool = typer.Option(False, help="Auto-apply safe router changes"),
    router_host: str | None = typer.Option(None, help="Router hostname/IP"),
    router_type: str | None = typer.Option(None, help="Router type (openwrt/unifi/tplink)"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Recommend and apply software-only WiFi privacy mitigations.

    Analyzes detection results and recommends ranked countermeasures:
    router reconfiguration, traffic orchestration, and reporting.
    """
    from goop_veil.config import VeilConfig
    from goop_veil.mitigation.advisor import MitigationAdvisor
    from goop_veil.models import DetectionResult, ThreatLevel

    config = VeilConfig()
    detection_result = None

    if pcap and pcap.exists():
        from goop_veil.detection.alert_engine import AlertEngine
        from goop_veil.detection.beacon_scanner import BeaconScanner
        from goop_veil.detection.traffic_analyzer import TrafficAnalyzer

        scanner = BeaconScanner(config.detection)
        analyzer = TrafficAnalyzer()
        engine = AlertEngine(config.detection)

        anomalies = scanner.scan_pcap(pcap)
        threat_level, indicators = analyzer.analyze_pcap(pcap)
        detection_result = engine.assess(
            devices=list(scanner.devices.values()),
            beacon_anomalies=anomalies,
            traffic_indicators=indicators,
            traffic_threat=threat_level,
        )

    if detection_result is None:
        detection_result = DetectionResult(threat_level=ThreatLevel.MEDIUM)

    # Set up router adapter
    router_adapter = None
    if router_host and router_type:
        from goop_veil.config import RouterConfig
        from goop_veil.mitigation.router.base import create_router_adapter

        rc = RouterConfig(
            adapter_type=router_type,
            host=router_host,
            apply_changes=auto_apply,
        )
        router_adapter = create_router_adapter(rc)
        if router_adapter:
            router_adapter.connect()

    advisor = MitigationAdvisor(config=config.mitigation, router_adapter=router_adapter)
    plan = advisor.assess_and_recommend(detection_result)

    applied = []
    if auto_apply and router_adapter:
        applied = advisor.auto_apply(plan, dry_run=False, confirmed=True)

    if json_output:
        import json
        console.print_json(json.dumps({
            "threat_level": plan.threat_level.value,
            "recommendations": [
                {
                    "priority": r.priority,
                    "title": r.title,
                    "effectiveness": r.effectiveness_score,
                    "difficulty": r.difficulty.value,
                    "auto_applicable": r.auto_applicable,
                }
                for r in plan.recommendations
            ],
            "auto_applied": applied,
            "estimated_effectiveness": plan.estimated_effectiveness,
            "summary": plan.summary,
        }))
        return

    console.print(f"\n[bold]Mitigation Recommendations[/bold]")
    console.print(f"Threat level: {plan.threat_level.value.upper()}")
    console.print(f"Estimated effectiveness: {plan.estimated_effectiveness:.0%}\n")

    table = Table(title="Ranked Mitigations")
    table.add_column("#", justify="right")
    table.add_column("Mitigation")
    table.add_column("Effectiveness", justify="right")
    table.add_column("Difficulty")
    table.add_column("Auto", justify="center")
    table.add_column("WiFi Impact")

    for r in plan.recommendations:
        auto_mark = "Y" if r.auto_applicable else ""
        table.add_row(
            str(r.priority),
            r.title,
            f"{r.effectiveness_score:.0%}",
            r.difficulty.value,
            auto_mark,
            r.wifi_impact,
        )

    console.print(table)

    if applied:
        console.print(f"\n[bold green]Auto-applied: {', '.join(applied)}[/bold green]")
    elif router_host:
        console.print("\n[yellow]Dry-run mode. Use --auto-apply to apply changes.[/yellow]")
    else:
        console.print("\n[dim]Provide --router-host and --router-type to enable auto-apply.[/dim]")


# =============================================================================
# report — documentation package
# =============================================================================


@app.command()
def report(
    pcap: Path = typer.Argument(..., help="Path to pcap file", exists=True),
    output_dir: str = typer.Option("data/reports", help="Output directory"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Generate a report package from detection results."""
    from goop_veil.config import ReportingConfig, VeilConfig
    from goop_veil.detection.alert_engine import AlertEngine
    from goop_veil.detection.beacon_scanner import BeaconScanner
    from goop_veil.detection.traffic_analyzer import TrafficAnalyzer
    from goop_veil.mitigation.reporting.package import ReportPackageGenerator

    config = VeilConfig()
    scanner = BeaconScanner(config.detection)
    analyzer = TrafficAnalyzer()
    engine = AlertEngine(config.detection)

    anomalies = scanner.scan_pcap(pcap)
    threat_level, indicators = analyzer.analyze_pcap(pcap)
    result = engine.assess(
        devices=list(scanner.devices.values()),
        beacon_anomalies=anomalies,
        traffic_indicators=indicators,
        traffic_threat=threat_level,
    )

    reporting_config = ReportingConfig(output_dir=output_dir)
    generator = ReportPackageGenerator(config=reporting_config)
    package = generator.generate(
        detection_results=[result],
        alerts=list(engine.alerts),
        output_dir=output_dir,
    )

    if json_output:
        import json
        console.print_json(json.dumps({
            "output_path": package.output_path,
            "report_hash": package.report_hash,
            "devices": len(package.device_fingerprints),
            "timeline_events": len(package.timeline),
        }))
        return

    console.print(f"\n[bold]Report Package Generated[/bold]")
    console.print(f"Output: {package.output_path}")
    console.print(f"Report hash: {package.report_hash[:16]}...")
    console.print(f"Devices documented: {len(package.device_fingerprints)}")
    console.print(f"Timeline events: {len(package.timeline)}")
    console.print(f"\n[dim]{package.disclaimer[:80]}...[/dim]")


# =============================================================================
# status — system info
# =============================================================================


@app.command()
def status(
    interface: str | None = typer.Option(None, help="WiFi interface to check"),
) -> None:
    """Show system status and WiFi interface info."""
    console.print("[bold]goop-veil status[/bold]")
    console.print("Version: 0.1.0")

    # Rust core
    try:
        from goop_veil._core import __version__ as core_version
        console.print(f"Rust core: v{core_version} [green]OK[/green]")
    except ImportError:
        console.print("Rust core: [red]NOT AVAILABLE[/red]")

    # WiFi interface
    from goop_veil.hardware.wifi_hal import create_wifi_hal
    hal = create_wifi_hal(interface=interface, mode="scan")
    info = hal.get_interface_info()
    console.print(f"WiFi interface: {info.get('interface', 'none')}")
    if "type" in info:
        console.print(f"  Mode: {info['type']}")
    if "channel" in info:
        console.print(f"  Channel: {info['channel']}")
    if "ssid" in info:
        console.print(f"  SSID: {info['ssid']}")


def main() -> None:
    """Entry point for goop-veil CLI."""
    if not _CLI_DEPS_AVAILABLE:
        print(
            "CLI extras not installed. Install with:\n"
            "  pip install goop-veil[cli]\n"
            "or:\n"
            "  pip install typer rich",
            file=sys.stderr,
        )
        raise SystemExit(1)
    app()


if __name__ == "__main__":
    main()
