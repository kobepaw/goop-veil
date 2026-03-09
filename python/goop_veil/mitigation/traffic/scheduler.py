"""Traffic generation scheduler — time-based activation of traffic patterns.

Schedules traffic generation during periods when WiFi sensing privacy
risk is highest (typically sleeping hours when the occupant is stationary
and breathing/heartbeat detection is easiest).
"""

from __future__ import annotations

import logging
from datetime import datetime

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# ScheduledTask value object
# ---------------------------------------------------------------------------


class ScheduledTask:
    """A time-based task that controls when a traffic generator runs."""

    __slots__ = ("name", "generator_name", "start_hour", "end_hour", "days", "enabled")

    def __init__(
        self,
        name: str,
        generator_name: str,
        start_hour: int,
        end_hour: int,
        days: tuple[int, ...] | None = None,
        enabled: bool = True,
    ) -> None:
        self.name = name
        self.generator_name = generator_name
        self.start_hour = start_hour
        self.end_hour = end_hour
        # Days of week: 0=Monday ... 6=Sunday; None means every day
        self.days = days
        self.enabled = enabled

    def __repr__(self) -> str:
        return (
            f"ScheduledTask(name={self.name!r}, gen={self.generator_name!r}, "
            f"hours={self.start_hour}-{self.end_hour}, enabled={self.enabled})"
        )


# ---------------------------------------------------------------------------
# TrafficScheduler
# ---------------------------------------------------------------------------


class TrafficScheduler:
    """Manages time-based scheduling of traffic generators.

    Each :class:`ScheduledTask` maps a generator name to a time window
    (hour range + optional days of week).  The scheduler determines
    which tasks should be active at any given moment.
    """

    def __init__(self) -> None:
        self._tasks: list[ScheduledTask] = []
        self._running = False

    # ------------------------------------------------------------------
    # Task management
    # ------------------------------------------------------------------

    def add_task(self, task: ScheduledTask) -> None:
        """Register a scheduled task."""
        self._tasks.append(task)
        logger.info("Scheduled task added: %s", task.name)

    @property
    def tasks(self) -> list[ScheduledTask]:
        """Return all registered tasks."""
        return list(self._tasks)

    # ------------------------------------------------------------------
    # Time checks
    # ------------------------------------------------------------------

    def should_run(self, task: ScheduledTask, now: datetime | None = None) -> bool:
        """Check if a task should be running at the given time.

        Handles overnight windows (e.g., start_hour=22, end_hour=7)
        correctly by treating them as wrapping past midnight.

        Args:
            task: The scheduled task to check.
            now: Override for current time (defaults to ``datetime.now()``).

        Returns:
            True if the task should be active right now.
        """
        if not task.enabled:
            return False

        if now is None:
            now = datetime.now()

        # Day-of-week filter (Monday=0 .. Sunday=6)
        if task.days is not None and now.weekday() not in task.days:
            return False

        hour = now.hour

        if task.start_hour <= task.end_hour:
            # Same-day window, e.g., 9-17
            return task.start_hour <= hour < task.end_hour
        else:
            # Overnight window, e.g., 22-7 means 22:00 .. 06:59
            return hour >= task.start_hour or hour < task.end_hour

    def get_active_tasks(self, now: datetime | None = None) -> list[ScheduledTask]:
        """Return all tasks that should be active right now."""
        return [t for t in self._tasks if self.should_run(t, now=now)]

    # ------------------------------------------------------------------
    # Default schedule
    # ------------------------------------------------------------------

    def create_default_schedule(self) -> None:
        """Create a default schedule targeting high-risk hours.

        Sleeping hours (10 PM - 7 AM) are highest risk for biometric
        sensing (occupant stationary, breathing/heartbeat signals
        strongest).  The default schedule runs all traffic generators
        during this window every day.
        """
        defaults = [
            ScheduledTask(
                name="nighttime_dns",
                generator_name="dns_prefetch",
                start_hour=22,
                end_hour=7,
            ),
            ScheduledTask(
                name="nighttime_http",
                generator_name="http_keepalive",
                start_hour=22,
                end_hour=7,
            ),
            ScheduledTask(
                name="nighttime_stream",
                generator_name="stream_simulator",
                start_hour=22,
                end_hour=7,
            ),
            ScheduledTask(
                name="nighttime_ntp",
                generator_name="ntp_sync",
                start_hour=22,
                end_hour=7,
            ),
            ScheduledTask(
                name="nighttime_cloud",
                generator_name="cloud_sync",
                start_hour=22,
                end_hour=7,
            ),
        ]
        for task in defaults:
            self.add_task(task)
        logger.info("Default schedule created: %d tasks (22:00-07:00 daily)", len(defaults))
