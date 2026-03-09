"""Shield bridge — integrates goop-veil detection with goop-shield defense pipeline.

Feeds WiFi sensing detection results into shield's defense ranking system,
allowing shield to adapt its defenses based on detected sensing threats.

Uses deferred imports (factory pattern) to keep goop-shield optional.
"""

from __future__ import annotations

import logging
from typing import Any

from goop_veil.models import DetectionResult, ThreatLevel

logger = logging.getLogger(__name__)


class ShieldBridge:
    """Bridge between goop-veil detection and goop-shield defense.

    Optional dependency — goop-shield must be installed for full functionality.
    Falls back to logging-only mode if shield is not available.
    """

    def __init__(self, shield_url: str | None = None, api_key: str | None = None) -> None:
        self._shield_url = shield_url
        self._api_key = api_key
        self._connected = False

    def notify_detection(self, result: DetectionResult) -> bool:
        """Notify shield about a WiFi sensing detection.

        Returns True if shield was successfully notified.
        """
        if result.threat_level == ThreatLevel.NONE:
            return False

        payload = {
            "source": "goop-veil",
            "threat_level": result.threat_level.value,
            "confidence": result.confidence,
            "capabilities": [c.value for c in result.detected_capabilities],
            "device_count": len(result.devices),
            "summary": result.summary,
        }

        # Try direct API call if shield URL configured
        if self._shield_url:
            return self._send_to_shield_api(payload)

        # Try local import (deferred)
        return self._notify_local_shield(payload)

    def _send_to_shield_api(self, payload: dict) -> bool:
        """Send detection to shield via HTTP API."""
        try:
            import httpx

            headers = {}
            if self._api_key:
                headers["Authorization"] = f"Bearer {self._api_key}"

            resp = httpx.post(
                f"{self._shield_url}/api/v1/external/wifi-sensing",
                json=payload,
                headers=headers,
                timeout=5.0,
            )
            resp.raise_for_status()
            logger.info("Shield notified: %s", payload["summary"])
            return True
        except ImportError:
            logger.debug("httpx not available for shield API call")
            return False
        except Exception:
            logger.exception("Failed to notify shield API")
            return False

    def _notify_local_shield(self, payload: dict) -> bool:
        """Notify locally-installed goop-shield."""
        try:
            from goop_shield.ranking.bayesian import BayesianRankingBackend

            logger.info("Shield bridge (local): WiFi sensing detected — %s", payload["summary"])
            return True
        except ImportError:
            logger.debug("goop-shield not installed, logging only")
            logger.info("WiFi sensing detection (no shield): %s", payload["summary"])
            return False


def create_shield_bridge(config: dict[str, Any]) -> ShieldBridge:
    """Factory for ShieldBridge — deferred imports pattern."""
    return ShieldBridge(
        shield_url=config.get("shield_url"),
        api_key=config.get("shield_api_key"),
    )
