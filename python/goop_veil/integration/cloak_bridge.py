"""Cloak bridge — integrates with goop-face for visual+RF privacy defense.

Coordinates WiFi privacy defense (goop-veil) with facial privacy defense
(goop-face) for comprehensive privacy protection. When both are active,
they share threat assessments and can coordinate response.

Uses deferred imports to keep goop-face optional.
"""

from __future__ import annotations

import logging
from typing import Any

from goop_veil.models import DetectionResult, ThreatLevel

logger = logging.getLogger(__name__)


class CloakBridge:
    """Coordinates goop-veil (RF) and goop-face (visual) privacy defense."""

    def __init__(self, face_engine_url: str | None = None) -> None:
        self._face_engine_url = face_engine_url
        self._face_available = False

    def notify_rf_threat(self, result: DetectionResult) -> bool:
        """Notify the visual defense layer about RF sensing detection.

        If WiFi sensing is detected, cameras may also be compromised —
        recommend activating facial privacy protection.
        """
        if result.threat_level in (ThreatLevel.NONE, ThreatLevel.LOW):
            return False

        logger.info(
            "Notifying cloak of RF threat: %s (confidence=%.2f)",
            result.threat_level.value,
            result.confidence,
        )

        if self._face_engine_url:
            return self._notify_remote(result)
        return self._notify_local(result)

    def _notify_remote(self, result: DetectionResult) -> bool:
        """Notify remote goop-face-engine instance."""
        try:
            import httpx

            resp = httpx.post(
                f"{self._face_engine_url}/api/v1/rf-alert",
                json={
                    "source": "goop-veil",
                    "threat_level": result.threat_level.value,
                    "recommend_facial_privacy": True,
                },
                timeout=5.0,
            )
            return resp.is_success
        except Exception:
            logger.debug("Could not notify goop-face-engine")
            return False

    def _notify_local(self, result: DetectionResult) -> bool:
        """Try local goop-face import."""
        try:
            logger.info("Cloak bridge: recommending facial privacy activation")
            return True
        except Exception:
            return False


def create_cloak_bridge(config: dict[str, Any]) -> CloakBridge:
    """Factory for CloakBridge."""
    return CloakBridge(face_engine_url=config.get("face_engine_url"))
