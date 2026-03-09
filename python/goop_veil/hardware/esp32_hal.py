"""ESP32 HAL — hardware abstraction layer for ESP32 serial communication.

Sends JSON commands to ESP32 firmware over UART and parses responses.
Provides MockESP32HAL for development/testing without hardware.
"""

from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod
from typing import Any

logger = logging.getLogger(__name__)


class BaseESP32HAL(ABC):
    """Abstract base for ESP32 hardware abstraction."""

    @abstractmethod
    def connect(self) -> bool:
        """Connect to ESP32 via serial port."""
        ...

    @abstractmethod
    def disconnect(self) -> None:
        """Disconnect from ESP32."""
        ...

    @abstractmethod
    def configure(self, power_dbm: float, channel: int) -> bool:
        """Configure ESP32 transmission parameters."""
        ...

    @abstractmethod
    def set_mode(self, mode: str) -> bool:
        """Set privacy enhancement mode."""
        ...

    @abstractmethod
    def enable_function(self, function: str) -> bool:
        """Enable a legitimate function."""
        ...

    @abstractmethod
    def start(self) -> bool:
        """Start transmission."""
        ...

    @abstractmethod
    def stop(self) -> bool:
        """Stop all transmission (emergency safe)."""
        ...

    @abstractmethod
    def get_telemetry(self) -> dict[str, Any]:
        """Read telemetry from ESP32."""
        ...

    @abstractmethod
    def get_audit_log(self, count: int = 100) -> list[dict]:
        """Read audit log entries from ESP32."""
        ...


class ESP32HAL(BaseESP32HAL):
    """Real ESP32 HAL using pyserial for UART communication."""

    def __init__(self, port: str = "/dev/ttyUSB0", baud_rate: int = 115200) -> None:
        self._port = port
        self._baud = baud_rate
        self._serial = None
        self._connected = False

    def connect(self) -> bool:
        try:
            import serial

            self._serial = serial.Serial(self._port, self._baud, timeout=2.0)
            self._connected = True
            logger.info("Connected to ESP32 on %s at %d baud", self._port, self._baud)
            return True
        except ImportError:
            logger.error("pyserial not installed: pip install goop-veil[active]")
            return False
        except Exception:
            logger.exception("Failed to connect to ESP32")
            return False

    def disconnect(self) -> None:
        if self._serial:
            self._serial.close()
            self._serial = None
        self._connected = False

    def _send_command(self, cmd: dict) -> dict:
        """Send JSON command and read JSON response."""
        if not self._serial:
            raise RuntimeError("Not connected to ESP32")

        payload = json.dumps(cmd) + "\n"
        self._serial.write(payload.encode())
        self._serial.flush()

        line = self._serial.readline().decode().strip()
        if not line:
            return {"status": "error", "message": "No response from ESP32"}
        return json.loads(line)

    def configure(self, power_dbm: float, channel: int) -> bool:
        resp = self._send_command({
            "cmd": "configure",
            "power_dbm": power_dbm,
            "channel": channel,
        })
        return resp.get("status") == "ok"

    def set_mode(self, mode: str) -> bool:
        resp = self._send_command({"cmd": "set_mode", "mode": mode})
        return resp.get("status") == "ok"

    def enable_function(self, function: str) -> bool:
        resp = self._send_command({"cmd": "enable_function", "function": function})
        return resp.get("status") == "ok"

    def start(self) -> bool:
        resp = self._send_command({"cmd": "start"})
        return resp.get("status") == "ok"

    def stop(self) -> bool:
        resp = self._send_command({"cmd": "stop"})
        return resp.get("status") == "ok"

    def get_telemetry(self) -> dict[str, Any]:
        return self._send_command({"cmd": "telemetry"})

    def get_audit_log(self, count: int = 100) -> list[dict]:
        resp = self._send_command({"cmd": "audit_log", "count": count})
        return resp.get("entries", [])


class MockESP32HAL(BaseESP32HAL):
    """Mock ESP32 HAL for development and testing without hardware."""

    def __init__(self) -> None:
        self._connected = False
        self._power_dbm = 15.0
        self._channel = 6
        self._mode = "vitals_privacy"
        self._running = False
        self._functions: list[str] = []
        self._commands: list[dict] = []

    @property
    def commands(self) -> list[dict]:
        """All commands sent (for test assertions)."""
        return list(self._commands)

    def connect(self) -> bool:
        self._connected = True
        self._commands.append({"cmd": "connect"})
        return True

    def disconnect(self) -> None:
        self._connected = False
        self._commands.append({"cmd": "disconnect"})

    def configure(self, power_dbm: float, channel: int) -> bool:
        self._power_dbm = power_dbm
        self._channel = channel
        self._commands.append({"cmd": "configure", "power_dbm": power_dbm, "channel": channel})
        return True

    def set_mode(self, mode: str) -> bool:
        self._mode = mode
        self._commands.append({"cmd": "set_mode", "mode": mode})
        return True

    def enable_function(self, function: str) -> bool:
        self._functions.append(function)
        self._commands.append({"cmd": "enable_function", "function": function})
        return True

    def start(self) -> bool:
        self._running = True
        self._commands.append({"cmd": "start"})
        return True

    def stop(self) -> bool:
        self._running = False
        self._commands.append({"cmd": "stop"})
        return True

    def get_telemetry(self) -> dict[str, Any]:
        return {
            "status": "ok",
            "power_dbm": self._power_dbm,
            "channel": self._channel,
            "mode": self._mode,
            "running": self._running,
            "utilization_pct": 3.2,
            "frames_tx": 1234,
        }

    def get_audit_log(self, count: int = 100) -> list[dict]:
        return []
