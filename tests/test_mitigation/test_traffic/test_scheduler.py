"""Tests for TrafficScheduler.

No external I/O — all time-based logic uses explicit datetime values.
"""

from __future__ import annotations

from datetime import datetime

import pytest

from goop_veil.mitigation.traffic.scheduler import ScheduledTask, TrafficScheduler


# ---------------------------------------------------------------------------
# ScheduledTask
# ---------------------------------------------------------------------------


class TestScheduledTask:
    def test_creation(self) -> None:
        task = ScheduledTask(
            name="night_dns",
            generator_name="dns_prefetch",
            start_hour=22,
            end_hour=7,
        )
        assert task.name == "night_dns"
        assert task.generator_name == "dns_prefetch"
        assert task.start_hour == 22
        assert task.end_hour == 7
        assert task.days is None
        assert task.enabled is True

    def test_repr(self) -> None:
        task = ScheduledTask("t", "gen", 9, 17)
        r = repr(task)
        assert "t" in r
        assert "gen" in r

    def test_disabled_task(self) -> None:
        task = ScheduledTask("t", "gen", 0, 24, enabled=False)
        assert task.enabled is False


# ---------------------------------------------------------------------------
# TrafficScheduler — should_run
# ---------------------------------------------------------------------------


class TestShouldRun:
    def test_during_active_same_day_window(self) -> None:
        """Task with 9-17 window, checked at 12:00."""
        scheduler = TrafficScheduler()
        task = ScheduledTask("work", "gen", start_hour=9, end_hour=17)
        noon = datetime(2026, 3, 8, 12, 0, 0)  # Sunday
        assert scheduler.should_run(task, now=noon) is True

    def test_outside_same_day_window(self) -> None:
        """Task with 9-17 window, checked at 20:00."""
        scheduler = TrafficScheduler()
        task = ScheduledTask("work", "gen", start_hour=9, end_hour=17)
        evening = datetime(2026, 3, 8, 20, 0, 0)
        assert scheduler.should_run(task, now=evening) is False

    def test_overnight_window_late_night(self) -> None:
        """Task with 22-7 overnight window, checked at 23:00."""
        scheduler = TrafficScheduler()
        task = ScheduledTask("night", "gen", start_hour=22, end_hour=7)
        late = datetime(2026, 3, 8, 23, 0, 0)
        assert scheduler.should_run(task, now=late) is True

    def test_overnight_window_early_morning(self) -> None:
        """Task with 22-7 overnight window, checked at 3:00."""
        scheduler = TrafficScheduler()
        task = ScheduledTask("night", "gen", start_hour=22, end_hour=7)
        early = datetime(2026, 3, 9, 3, 0, 0)
        assert scheduler.should_run(task, now=early) is True

    def test_overnight_window_midday_inactive(self) -> None:
        """Task with 22-7 overnight window, checked at 14:00."""
        scheduler = TrafficScheduler()
        task = ScheduledTask("night", "gen", start_hour=22, end_hour=7)
        midday = datetime(2026, 3, 8, 14, 0, 0)
        assert scheduler.should_run(task, now=midday) is False

    def test_disabled_task_never_runs(self) -> None:
        scheduler = TrafficScheduler()
        task = ScheduledTask("off", "gen", start_hour=0, end_hour=23, enabled=False)
        assert scheduler.should_run(task, now=datetime(2026, 3, 8, 12, 0)) is False

    def test_day_filter_matching(self) -> None:
        """Task restricted to weekdays, checked on Wednesday (2)."""
        scheduler = TrafficScheduler()
        task = ScheduledTask("weekday", "gen", 9, 17, days=(0, 1, 2, 3, 4))
        # 2026-03-04 is a Wednesday (weekday=2)
        wed = datetime(2026, 3, 4, 12, 0, 0)
        assert scheduler.should_run(task, now=wed) is True

    def test_day_filter_not_matching(self) -> None:
        """Task restricted to weekdays, checked on Sunday (6)."""
        scheduler = TrafficScheduler()
        task = ScheduledTask("weekday", "gen", 9, 17, days=(0, 1, 2, 3, 4))
        # 2026-03-08 is a Sunday (weekday=6)
        sun = datetime(2026, 3, 8, 12, 0, 0)
        assert scheduler.should_run(task, now=sun) is False


# ---------------------------------------------------------------------------
# TrafficScheduler — add_task / get_active_tasks
# ---------------------------------------------------------------------------


class TestAddTask:
    def test_add_task(self) -> None:
        scheduler = TrafficScheduler()
        task = ScheduledTask("t1", "gen", 0, 24)
        scheduler.add_task(task)
        assert len(scheduler.tasks) == 1
        assert scheduler.tasks[0].name == "t1"

    def test_add_multiple_tasks(self) -> None:
        scheduler = TrafficScheduler()
        scheduler.add_task(ScheduledTask("a", "gen_a", 0, 12))
        scheduler.add_task(ScheduledTask("b", "gen_b", 12, 24))
        assert len(scheduler.tasks) == 2


class TestGetActiveTasks:
    def test_returns_active_only(self) -> None:
        scheduler = TrafficScheduler()
        scheduler.add_task(ScheduledTask("morning", "gen_a", 6, 12))
        scheduler.add_task(ScheduledTask("evening", "gen_b", 18, 23))
        # Check at 10:00 — only morning should be active
        morning = datetime(2026, 3, 8, 10, 0, 0)
        active = scheduler.get_active_tasks(now=morning)
        assert len(active) == 1
        assert active[0].name == "morning"

    def test_returns_empty_when_none_active(self) -> None:
        scheduler = TrafficScheduler()
        scheduler.add_task(ScheduledTask("night", "gen", 22, 6))
        # Check at 14:00 — nothing active
        midday = datetime(2026, 3, 8, 14, 0, 0)
        active = scheduler.get_active_tasks(now=midday)
        assert active == []


# ---------------------------------------------------------------------------
# TrafficScheduler — create_default_schedule
# ---------------------------------------------------------------------------


class TestCreateDefaultSchedule:
    def test_creates_nighttime_tasks(self) -> None:
        scheduler = TrafficScheduler()
        scheduler.create_default_schedule()
        assert len(scheduler.tasks) >= 3  # at least DNS, HTTP, stream

    def test_default_covers_nighttime(self) -> None:
        """Default schedule should be active at 2 AM."""
        scheduler = TrafficScheduler()
        scheduler.create_default_schedule()
        two_am = datetime(2026, 3, 9, 2, 0, 0)
        active = scheduler.get_active_tasks(now=two_am)
        assert len(active) >= 3

    def test_default_inactive_at_noon(self) -> None:
        """Default schedule should NOT be active at noon."""
        scheduler = TrafficScheduler()
        scheduler.create_default_schedule()
        noon = datetime(2026, 3, 8, 12, 0, 0)
        active = scheduler.get_active_tasks(now=noon)
        assert len(active) == 0

    def test_default_active_at_11pm(self) -> None:
        """Default schedule should be active at 11 PM."""
        scheduler = TrafficScheduler()
        scheduler.create_default_schedule()
        late = datetime(2026, 3, 8, 23, 0, 0)
        active = scheduler.get_active_tasks(now=late)
        assert len(active) >= 3
