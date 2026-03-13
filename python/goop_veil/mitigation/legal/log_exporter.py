"""Exports detection logs with explicit HMAC signing semantics.

Provides tamper-evident export of detection results and alerts. Durable signed
artifacts require an explicit signing key; temporary random-key signing is
opt-in for dev/test workflows only.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import warnings
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from goop_veil.models import DetectionResult, VeilAlert

logger = logging.getLogger(__name__)

#: Environment variable name for the log signing key (base64 encoded).
_SIGNING_KEY_ENV_VAR = "VEIL_LOG_SIGNING_KEY"


class MissingSigningKeyError(RuntimeError):
    """Raised when durable signing is requested without a configured key."""


def _serialize_model(obj: Any) -> Any:
    """JSON-safe serializer for Pydantic models and datetime objects."""
    if hasattr(obj, "model_dump"):
        return obj.model_dump(mode="json")
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


def _mask_mac(mac: str | None) -> str | None:
    if not mac:
        return mac
    parts = mac.split(":")
    if len(parts) != 6:
        return mac
    return ":".join(parts[:3] + ["xx", "xx", "xx"])


def _mask_ip(ip: str | None) -> str | None:
    if not ip:
        return ip
    if "." in ip:
        parts = ip.split(".")
        if len(parts) == 4:
            return ".".join(parts[:3] + ["x"])
    return ip


def _redact_value(obj: Any) -> Any:
    if isinstance(obj, dict):
        redacted: dict[str, Any] = {}
        for key, value in obj.items():
            if key in {"mac", "mac_address", "bssid"}:
                redacted[key] = _mask_mac(value)
            elif key in {"ip", "ipaddr"}:
                redacted[key] = _mask_ip(value)
            elif key in {"hostname", "ssid"} and isinstance(value, str):
                redacted[key] = "[REDACTED]"
            else:
                redacted[key] = _redact_value(value)
        return redacted
    if isinstance(obj, list):
        return [_redact_value(item) for item in obj]
    return obj


class TimestampedLogExporter:
    """Exports detection logs with HMAC-SHA256 integrity signatures.

    The signing key can be provided directly, via the VEIL_LOG_SIGNING_KEY
    environment variable (base64-encoded), or explicitly auto-generated for
    temporary dev/test artifacts only.
    """

    def __init__(
        self,
        signing_key: bytes | None = None,
        *,
        allow_temporary_key: bool = False,
    ) -> None:
        """Initialize the log exporter.

        Args:
            signing_key: HMAC signing key as raw bytes. If None, attempts to
                read from VEIL_LOG_SIGNING_KEY env var (base64-encoded).
            allow_temporary_key: Explicitly allow generating a random signing
                key for temporary dev/test artifacts that will not remain
                durably verifiable after process exit.
        """
        self._uses_temporary_key = False
        self._key_source = "explicit"

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
            self._key_source = "environment"
            return

        if allow_temporary_key:
            self._signing_key = os.urandom(32)
            self._uses_temporary_key = True
            self._key_source = "temporary"
            warnings.warn(
                "No signing key provided and VEIL_LOG_SIGNING_KEY not set. "
                "A temporary random key has been generated for dev/test use. "
                "Artifacts signed with this key are not durably verifiable.",
                UserWarning,
                stacklevel=2,
            )
            return

        raise MissingSigningKeyError(
            "No signing key provided and VEIL_LOG_SIGNING_KEY not set. "
            "Refusing to create a durably signed artifact without an explicit "
            f"key. Set {_SIGNING_KEY_ENV_VAR}, pass signing_key=..., or use "
            "allow_temporary_key=True for explicit dev/test temporary mode."
        )

    @property
    def signing_key(self) -> bytes:
        """Return the current signing key."""
        return self._signing_key

    @property
    def verification_mode(self) -> str:
        """Return whether exported artifacts are durably or temporarily signed."""
        return "temporary_signed" if self._uses_temporary_key else "signed"

    @property
    def key_source(self) -> str:
        """Return how the signing key was sourced."""
        return self._key_source

    def export(
        self,
        alerts: list[VeilAlert],
        detection_results: list[DetectionResult],
        output_path: str | Path,
        redact_sensitive: bool = True,
    ) -> str:
        """Export logs as JSON with HMAC-SHA256 integrity signature.

        Args:
            alerts: List of VeilAlert instances to include.
            detection_results: List of DetectionResult instances to include.
            output_path: File path for the exported JSON log.
            redact_sensitive: Redact MAC/IP/SSID/hostname fields.

        Returns:
            HMAC-SHA256 hex digest of the exported content.
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        payload = {
            "exported_at": datetime.now(UTC).isoformat(),
            "version": "1.0",
            "verification": {
                "mode": self.verification_mode,
                "key_source": self.key_source,
            },
            "alerts": [a.model_dump(mode="json") for a in alerts],
            "detections": [d.model_dump(mode="json") for d in detection_results],
        }
        if redact_sensitive:
            payload = _redact_value(payload)

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
        output_json = json.dumps(
            payload,
            indent=2,
            sort_keys=True,
            default=_serialize_model,
        )
        output_path.write_text(output_json, encoding="utf-8")

        logger.info(
            "Exported log to %s (%s, HMAC: %s...)",
            output_path,
            self.verification_mode,
            hmac_digest[:16],
        )
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
        data.pop("hmac", None)

        # Re-serialize to the same deterministic format used during export
        content_json = json.dumps(data, sort_keys=True, default=_serialize_model)

        computed_hmac = hmac.new(
            self._signing_key,
            content_json.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        return hmac.compare_digest(computed_hmac, expected_hmac)
