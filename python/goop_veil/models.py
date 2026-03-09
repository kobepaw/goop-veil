"""Data models for goop-veil — detection results, defense recommendations, alerts.

All models are Pydantic v2 frozen (immutable after creation).
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ThreatLevel(StrEnum):
    """WiFi sensing threat assessment level."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CONFIRMED = "confirmed"


class SensingCapability(StrEnum):
    """Types of WiFi sensing capabilities detected."""

    PRESENCE = "presence"
    MOTION = "motion"
    BREATHING = "breathing"
    HEARTBEAT = "heartbeat"
    POSE = "pose"
    GESTURE = "gesture"


class AlertSeverity(StrEnum):
    """Alert severity levels."""

    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class DefenseMode(StrEnum):
    """Active defense operating modes."""

    VITALS_PRIVACY = "vitals_privacy"
    MOTION_PRIVACY = "motion_privacy"
    FULL_PRIVACY = "full_privacy"


# =============================================================================
# Detection models (T1)
# =============================================================================


class DeviceFingerprint(BaseModel):
    """Fingerprint of a detected WiFi device."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    mac_address: str
    vendor: str = "Unknown"
    is_espressif: bool = False
    ssid: str | None = None
    channels_observed: list[int] = Field(default_factory=list)
    beacon_interval_ms: float | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    frame_count: int = 0


class BeaconAnomaly(BaseModel):
    """Anomalous beacon behavior suggesting WiFi sensing mesh."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    device: DeviceFingerprint
    anomaly_type: str  # e.g., "rapid_channel_hop", "unusual_interval", "espressif_mesh"
    score: float = Field(ge=0.0, le=1.0)
    description: str = ""


class CSISignature(BaseModel):
    """CSI-based periodic signal detection result."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    frequency_hz: float
    magnitude: float
    label: str  # "breathing", "heartbeat", "walking", "gesture"
    snr_db: float
    confidence: float = Field(ge=0.0, le=1.0)


class DetectionResult(BaseModel):
    """Complete T1 detection assessment."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    timestamp: datetime = Field(default_factory=datetime.now)
    threat_level: ThreatLevel = ThreatLevel.NONE
    detected_capabilities: list[SensingCapability] = Field(default_factory=list)
    devices: list[DeviceFingerprint] = Field(default_factory=list)
    beacon_anomalies: list[BeaconAnomaly] = Field(default_factory=list)
    csi_signatures: list[CSISignature] = Field(default_factory=list)
    channel_hop_detected: bool = False
    espressif_mesh_detected: bool = False
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    summary: str = ""


# =============================================================================
# Passive defense models (T2)
# =============================================================================


class MaterialRecommendation(BaseModel):
    """Single material placement recommendation."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    material: str
    thickness_m: float
    area_m2: float
    attenuation_db: float
    cost_usd: float
    location: str  # e.g., "wall_north", "window_east", "ceiling"
    priority: int = Field(ge=1)  # 1 = highest priority


class RoomAssessment(BaseModel):
    """Room vulnerability assessment result."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    room_dimensions_m: tuple[float, float, float]  # length, width, height
    frequency_mhz: float
    fresnel_zones: list[dict[str, Any]] = Field(default_factory=list)
    vulnerability_score: float = Field(ge=0.0, le=1.0)
    current_attenuation_db: float = 0.0
    target_attenuation_db: float = 15.0
    recommendations: list[MaterialRecommendation] = Field(default_factory=list)
    estimated_cost_usd: float = 0.0
    summary: str = ""


# =============================================================================
# Active defense models (T3)
# =============================================================================


class ActiveDefenseStatus(BaseModel):
    """Status of the active defense system."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    mode: DefenseMode
    power_dbm: float
    channel: int
    utilization_pct: float
    mesh_ap_active: bool = False
    sensors_active: bool = False
    positioning_active: bool = False
    frames_transmitted: int = 0
    uptime_sec: float = 0.0
    compliant: bool = True
    audit_entries: int = 0


# =============================================================================
# Alert models
# =============================================================================


class VeilAlert(BaseModel):
    """Alert generated by the detection or monitoring system."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    timestamp: datetime = Field(default_factory=datetime.now)
    severity: AlertSeverity
    category: str  # "detection", "compliance", "hardware", "self_test"
    title: str
    description: str
    source: str = ""  # Module/component that generated the alert
    metadata: dict[str, Any] = Field(default_factory=dict)
