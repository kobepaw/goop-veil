"""Exports detection logs with HMAC integrity signatures for chain of custody.

Provides tamper-evident export of detection results and alerts, suitable
for use as supporting evidence in legal proceedings or regulatory complaints.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import warnings
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from goop_veil.models import DetectionResult, VeilAlert

logger = logging.getLogger(__name__)

#: Environment variable name for the log signing key (base64 encoded).
_SIGNING_KEY_ENV_VAR = "VEIL_LOG_SIGNING_KEY"


def _serialize_model(obj: Any) -> Any:
    """JSON-safe serializer for Pydantic models and datetime objects."""
    if hasattr(obj, "model_dump"):
        return obj.model_dump(mode="json")
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


class TimestampedLogExporter:
    """Exports detection logs with HMAC-SHA256 integrity signatures.

    The signing key can be provided directly, via the VEIL_LOG_SIGNING_KEY
    environment variable (base64-encoded), or auto-generated (with a warning).
    """

    def __init__(self, signing_key: bytes | None = None) -> None:
        """Initialize the log exporter.

        Args:
            signing_key: HMAC signing key as raw bytes. If None, attempts to
                read from VEIL_LOG_SIGNING_KEY env var (base64-encoded). If
                still unavailable, generates a random 32-byte key and emits
                a warning.
        """
        if signing_key is not None:
            self._signing_key = signing_key
            return

        env_key = os.environ.get(_SIGNING_KEY_ENV_VAR)
        if env_key:
            try:
                self._signing_key = base64.b64decode(env_key)
            except Exception as exc:
                raise ValueError(
                    f"Failed to decode {_SIGNING_KEY_ENV_VAR} as base64: {exc}"
                ) from exc
            return

        # Generate random key as last resort
        self._signing_key = os.urandom(32)
        warnings.warn(
            "No signing key provided and VEIL_LOG_SIGNING_KEY not set. "
            "A random key has been generated. Evidence logs signed with this "
            "key cannot be verified later unless the key is preserved.",
            UserWarning,
            stacklevel=2,
        )

    @property
    def signing_key(self) -> bytes:
        """Return the current signing key (for preservation)."""
        return self._signing_key

    def export(
        self,
        alerts: list[VeilAlert],
        detection_results: list[DetectionResult],
        output_path: str | Path,
    ) -> str:
        """Export logs as JSON with HMAC-SHA256 integrity signature.

        Args:
            alerts: List of VeilAlert instances to include.
            detection_results: List of DetectionResult instances to include.
            output_path: File path for the exported JSON log.

        Returns:
            HMAC-SHA256 hex digest of the exported content.
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        payload = {
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "version": "1.0",
            "alerts": [a.model_dump(mode="json") for a in alerts],
            "detections": [d.model_dump(mode="json") for d in detection_results],
        }

        # Serialize to deterministic JSON (sorted keys) for reproducible HMAC
        content_json = json.dumps(payload, sort_keys=True, default=_serialize_model)

        # Compute HMAC over the content (excluding the hmac field)
        hmac_digest = hmac.new(
            self._signing_key,
            content_json.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        # Add HMAC to the output document
        payload["hmac"] = hmac_digest
        output_json = json.dumps(payload, indent=2, sort_keys=True, default=_serialize_model)
        output_path.write_text(output_json, encoding="utf-8")

        logger.info("Exported log to %s (HMAC: %s...)", output_path, hmac_digest[:16])
        return hmac_digest

    def verify(self, log_path: str | Path, expected_hmac: str) -> bool:
        """Verify a log file's HMAC integrity.

        Re-computes the HMAC over the log content (excluding the hmac field)
        and compares it to the expected value using constant-time comparison.

        Args:
            log_path: Path to the previously exported JSON log file.
            expected_hmac: Expected HMAC hex digest to verify against.

        Returns:
            True if the HMAC matches, False otherwise.
        """
        log_path = Path(log_path)
        data = json.loads(log_path.read_text(encoding="utf-8"))

        # Remove the stored HMAC field before re-computing
        stored_hmac = data.pop("hmac", None)

        # Re-serialize to the same deterministic format used during export
        content_json = json.dumps(data, sort_keys=True, default=_serialize_model)

        computed_hmac = hmac.new(
            self._signing_key,
            content_json.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        return hmac.compare_digest(computed_hmac, expected_hmac)
