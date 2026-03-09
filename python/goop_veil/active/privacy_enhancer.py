"""Privacy enhancer — controls ESP32 active defense via serial HAL.

Manages privacy enhancement modes that use legitimate WiFi functions
to degrade CSI-based sensing accuracy. All operations comply with
FCC Part 15.247 power limits and use approved terminology.

Operating modes:
- vitals_privacy: Masks heartbeat/breathing CSI signatures (5-10 dBm)
- motion_privacy: Masks motion/walking patterns (10-15 dBm)
- full_privacy: Masks all sensing including presence (15-18 dBm)
"""

from __future__ import annotations

import logging
from datetime import datetime

from goop_veil.compliance import (
    MAX_CONDUCTED_POWER_DBM,
    TARGET_MIN_POWER_DBM,
    US_ALLOWED_CHANNELS,
    LegitimateFunction,
    PrivacyTarget,
)
from goop_veil.config import ActiveDefenseConfig
from goop_veil.models import ActiveDefenseStatus, DefenseMode

logger = logging.getLogger(__name__)

#: Mode to privacy targets mapping
MODE_TARGETS: dict[DefenseMode, list[PrivacyTarget]] = {
    DefenseMode.VITALS_PRIVACY: [PrivacyTarget.HEARTBEAT, PrivacyTarget.BREATHING],
    DefenseMode.MOTION_PRIVACY: [
        PrivacyTarget.HEARTBEAT,
        PrivacyTarget.BREATHING,
        PrivacyTarget.MOTION,
    ],
    DefenseMode.FULL_PRIVACY: [
        PrivacyTarget.HEARTBEAT,
        PrivacyTarget.BREATHING,
        PrivacyTarget.MOTION,
        PrivacyTarget.PRESENCE,
    ],
}


class PrivacyEnhancer:
    """Controls ESP32 privacy enhancement via the hardware abstraction layer."""

    def __init__(self, config: ActiveDefenseConfig | None = None, hal: object | None = None) -> None:
        self._config = config or ActiveDefenseConfig()
        self._hal = hal  # ESP32HAL or MockESP32HAL
        self._active = False
        self._mode = DefenseMode(self._config.mode)
        self._start_time: datetime | None = None
        self._frames_transmitted = 0

    @property
    def is_active(self) -> bool:
        return self._active

    @property
    def mode(self) -> DefenseMode:
        return self._mode

    def activate(
        self,
        mode: str | None = None,
        power_dbm: float | None = None,
        channel: int | None = None,
    ) -> ActiveDefenseStatus:
        """Activate privacy enhancement.

        All parameters are validated against FCC compliance limits.
        """
        if mode:
            self._mode = DefenseMode(mode)

        power = power_dbm if power_dbm is not None else self._config.default_power_dbm
        ch = channel if channel is not None else self._config.channel

        # Compliance validation
        if power > MAX_CONDUCTED_POWER_DBM:
            raise ValueError(
                f"Power {power} dBm exceeds FCC limit of {MAX_CONDUCTED_POWER_DBM} dBm"
            )
        if ch not in US_ALLOWED_CHANNELS:
            raise ValueError(f"Channel {ch} not in US allowed channels: {US_ALLOWED_CHANNELS}")

        # Determine required power for selected targets
        targets = MODE_TARGETS[self._mode]
        min_power = max(TARGET_MIN_POWER_DBM[t] for t in targets)
        if power < min_power:
            logger.warning(
                "Power %.1f dBm below minimum %.1f dBm for %s mode — "
                "some privacy targets may not be fully effective",
                power,
                min_power,
                self._mode.value,
            )

        # Send configuration to HAL
        if self._hal is not None:
            self._hal.configure(power_dbm=power, channel=ch)
            self._hal.set_mode(self._mode.value)

            # Enable legitimate functions
            functions = self._get_legitimate_functions()
            for func in functions:
                self._hal.enable_function(func.value)

            self._hal.start()

        self._active = True
        self._start_time = datetime.now()
        logger.info(
            "Privacy enhancement activated: mode=%s, power=%.1f dBm, channel=%d",
            self._mode.value,
            power,
            ch,
        )

        return self.status()

    def deactivate(self) -> ActiveDefenseStatus:
        """Deactivate privacy enhancement."""
        if self._hal is not None:
            self._hal.stop()

        self._active = False
        logger.info("Privacy enhancement deactivated")
        return self.status()

    def status(self) -> ActiveDefenseStatus:
        """Get current active defense status."""
        uptime = 0.0
        if self._start_time and self._active:
            uptime = (datetime.now() - self._start_time).total_seconds()

        return ActiveDefenseStatus(
            mode=self._mode,
            power_dbm=self._config.default_power_dbm,
            channel=self._config.channel,
            utilization_pct=0.0,  # Would come from HAL telemetry
            mesh_ap_active=self._config.enable_mesh_ap and self._active,
            sensors_active=self._config.enable_sensors and self._active,
            positioning_active=self._config.enable_positioning and self._active,
            frames_transmitted=self._frames_transmitted,
            uptime_sec=round(uptime, 1),
            compliant=True,
            audit_entries=0,
        )

    def _get_legitimate_functions(self) -> list[LegitimateFunction]:
        """Get legitimate functions to enable based on config."""
        functions: list[LegitimateFunction] = []
        if self._config.enable_mesh_ap:
            functions.extend([
                LegitimateFunction.AP_BEACON,
                LegitimateFunction.CLIENT_DATA,
                LegitimateFunction.MESH_PEERING,
                LegitimateFunction.ACK,
            ])
        if self._config.enable_sensors:
            functions.append(LegitimateFunction.SENSOR_DATA)
        if self._config.enable_positioning:
            functions.append(LegitimateFunction.FTM_POSITIONING)
        return functions
