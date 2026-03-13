"""Mitigation layer data models — recommendations, plans, router status, reporting.

All models are Pydantic v2 frozen (immutable after creation).
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from goop_veil.models import ThreatLevel  # noqa: F401 — re-exported for convenience


class MitigationCategory(StrEnum):
    """Categories of software-only mitigation actions."""

    ROUTER_CONFIG = "router_config"
    TRAFFIC_ORCHESTRATION = "traffic_orchestration"
    BAND_MIGRATION = "band_migration"
    PMF_ENABLEMENT = "pmf_enablement"
    BEAMFORMING_CONTROL = "beamforming_control"
    REPORTING_ACTION = "reporting_action"
    CHANNEL_MANAGEMENT = "channel_management"
    BEACON_MANAGEMENT = "beacon_management"


class MitigationDifficulty(StrEnum):
    """Estimated difficulty for applying a mitigation."""

    TRIVIAL = "trivial"
    EASY = "easy"
    MODERATE = "moderate"
    HARD = "hard"
    EXPERT = "expert"


class MitigationRecommendation(BaseModel):
    """Single mitigation recommendation with scoring metadata."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    category: MitigationCategory
    title: str
    description: str
    effectiveness_score: float = Field(ge=0.0, le=1.0)
    difficulty: MitigationDifficulty
    auto_applicable: bool = False
    requires_router: bool = False
    estimated_time_minutes: int = Field(ge=0)
    priority: int = Field(ge=1)
    wifi_impact: str = "none"  # "none", "brief_drop", "throughput_reduction"


class MitigationPlan(BaseModel):
    """Complete mitigation plan produced by the advisor."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    timestamp: datetime = Field(default_factory=datetime.now)
    detection_summary: str
    threat_level: ThreatLevel
    recommendations: list[MitigationRecommendation] = Field(default_factory=list)
    auto_applied: list[str] = Field(default_factory=list)
    estimated_effectiveness: float = Field(ge=0.0, le=1.0)
    summary: str = ""


class RouterStatus(BaseModel):
    """Current state of the router connection and configuration."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    connected: bool = False
    adapter_type: str = "none"
    current_channel: int | None = None
    current_bandwidth_mhz: int | None = None
    current_band: str | None = None
    pmf_enabled: bool | None = None
    tx_power_dbm: float | None = None
    beamforming_enabled: bool | None = None
    changes_applied: list[str] = Field(default_factory=list)


class ReportPackage(BaseModel):
    """Report package with detection results and device fingerprints."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    timestamp: datetime = Field(default_factory=datetime.now)
    detection_results: list[dict[str, Any]] = Field(default_factory=list)
    device_fingerprints: list[dict[str, Any]] = Field(default_factory=list)
    timeline: list[dict[str, Any]] = Field(default_factory=list)
    output_path: str = ""
    report_hash: str = ""
    disclaimer: str = (
        "This report is generated automatically and may not fit every workflow. "
        "Consult a qualified professional as needed."
    )
