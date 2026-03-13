"""VeilConfig — Pydantic v2 frozen configuration for goop-veil.

Follows goop ecosystem ConfigDict(frozen=True, extra="forbid") pattern.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class _VeilBaseConfig(BaseModel):
    """Base configuration for Veil (matches goop-shield pattern)."""

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        validate_default=True,
        str_strip_whitespace=True,
    )


class DetectionConfig(_VeilBaseConfig):
    """T1: WiFi sensing detection configuration."""

    #: Minimum beacon anomaly score to trigger alert (0.0-1.0)
    beacon_anomaly_threshold: float = Field(default=0.7, ge=0.0, le=1.0)

    #: Minimum number of Espressif devices to consider suspicious
    espressif_device_threshold: int = Field(default=2, ge=1)

    #: Channel hopping detection window (seconds)
    channel_hop_window_sec: float = Field(default=10.0, gt=0.0)

    #: Minimum channel hops in window to trigger alert
    channel_hop_threshold: int = Field(default=5, ge=1)

    #: CSI signature SNR threshold (dB) for periodic signal detection
    csi_snr_threshold_db: float = Field(default=6.0, ge=0.0)

    #: CSI sample rate (Hz) for periodic analysis
    csi_sample_rate_hz: float = Field(default=100.0, gt=0.0)


class PassiveDefenseConfig(_VeilBaseConfig):
    """T2: Passive defense (material placement) configuration."""

    #: Default frequency for Fresnel calculations (MHz)
    default_freq_mhz: float = Field(default=2437.0, gt=0.0)

    #: Default room dimensions (meters): length x width x height
    default_room_length_m: float = Field(default=4.5, gt=0.0)
    default_room_width_m: float = Field(default=3.5, gt=0.0)
    default_room_height_m: float = Field(default=2.7, gt=0.0)

    #: Maximum budget for material recommendations (USD)
    max_budget_usd: float = Field(default=500.0, ge=0.0)

    #: Target attenuation (dB) for material placement
    target_attenuation_db: float = Field(default=15.0, ge=0.0)


class ActiveDefenseConfig(_VeilBaseConfig):
    """T3: Active defense (ESP32 privacy enhancement) configuration."""

    #: Serial port for ESP32 communication
    serial_port: str = "/dev/ttyUSB0"

    #: Serial baud rate
    baud_rate: int = Field(default=115200, ge=9600)

    #: Default transmission power (dBm) — must be <= 20
    default_power_dbm: float = Field(default=15.0, ge=0.0, le=20.0)

    #: WiFi channel (1-11 for US)
    channel: int = Field(default=6, ge=1, le=11)

    #: Maximum channel utilization (percentage)
    max_utilization_pct: float = Field(default=7.5, gt=0.0, le=100.0)

    #: Privacy enhancement mode
    mode: Literal["vitals_privacy", "motion_privacy", "full_privacy"] = "vitals_privacy"

    #: Enable legitimate functions (mesh AP, sensors, positioning)
    enable_mesh_ap: bool = True
    enable_sensors: bool = True
    enable_positioning: bool = True


class AdversarialConfig(_VeilBaseConfig):
    """T4: Adversarial/adaptive defense configuration."""

    #: BroRL learning rate for technique adaptation
    brorl_learning_rate: float = Field(default=0.1, gt=0.0, le=1.0)

    #: BroRL state persistence path
    brorl_state_path: str = "data/brorl_state.json"

    #: Self-test interval (seconds)
    self_test_interval_sec: float = Field(default=300.0, gt=0.0)

    #: Adversarial CSI generation model (if available)
    adversarial_model: str | None = None


class TrafficConfig(_VeilBaseConfig):
    """T5: Traffic orchestration configuration for RF diversity."""

    #: Enable traffic orchestration
    enabled: bool = False

    #: Maximum aggregate bandwidth for all generators (Mbps)
    max_bandwidth_mbps: float = Field(default=10.0, gt=0.0)

    #: Enable time-based scheduling of traffic generation
    schedule_enabled: bool = True

    #: Enable smart home device discovery for additional RF diversity
    smart_home_discovery: bool = False


class RouterConfig(_VeilBaseConfig):
    """T5: Router adapter configuration for mitigation layer."""

    #: Router adapter type (mock for testing, none to disable)
    adapter_type: Literal["openwrt", "unifi", "tplink", "mock", "none"] = "none"

    #: Router host address
    host: str = ""

    #: Router SSH/API username
    username: str = ""

    #: Path to SSH private key (if applicable)
    ssh_key_path: str | None = None

    #: Whether to actually apply changes (False = dry-run)
    apply_changes: bool = False

    #: Connection timeout in seconds
    timeout_sec: float = Field(default=30.0, gt=0.0)


class ReportingConfig(_VeilBaseConfig):
    """T5: Reporting/documentation output configuration."""

    #: Output directory for report packages
    output_dir: str = "data/reports"

    #: Include advisory disclaimer in report packages
    include_disclaimer: bool = True

    #: Allow random-key signing for explicit dev/test temporary artifacts only
    allow_temporary_signing: bool = False


class MitigationConfig(_VeilBaseConfig):
    """T5: Software-only mitigation layer configuration."""

    #: Router reconfiguration settings
    router: RouterConfig = Field(default_factory=RouterConfig)

    #: Traffic orchestration settings
    traffic: TrafficConfig = Field(default_factory=TrafficConfig)

    #: Reporting/documentation settings
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)


class VeilConfig(_VeilBaseConfig):
    """Root configuration for goop-veil.

    Follows goop ecosystem pattern: frozen=True, extra="forbid".
    """

    #: Log level
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"

    #: Data directory for state, results, signatures
    data_dir: str = "data"

    #: Detection subsystem config
    detection: DetectionConfig = Field(default_factory=DetectionConfig)

    #: Passive defense config
    passive: PassiveDefenseConfig = Field(default_factory=PassiveDefenseConfig)

    #: Active defense config
    active: ActiveDefenseConfig = Field(default_factory=ActiveDefenseConfig)

    #: Adversarial config
    adversarial: AdversarialConfig = Field(default_factory=AdversarialConfig)

    #: Traffic orchestration config
    traffic: TrafficConfig = Field(default_factory=TrafficConfig)

    #: Mitigation layer config
    mitigation: MitigationConfig = Field(default_factory=MitigationConfig)

    @classmethod
    def from_file(cls, path: str | Path) -> VeilConfig:
        """Load configuration from a JSON file."""
        import json

        data = json.loads(Path(path).read_text())
        return cls.model_validate(data)
