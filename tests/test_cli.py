"""Tests for CLI import/runtime behavior when optional deps are missing."""

from __future__ import annotations

import importlib
import sys

import pytest


def _reload_cli_without_deps(monkeypatch):
    monkeypatch.setitem(sys.modules, "typer", None)
    monkeypatch.setitem(sys.modules, "rich.console", None)
    monkeypatch.setitem(sys.modules, "rich.table", None)
    sys.modules.pop("goop_veil.cli", None)
    return importlib.import_module("goop_veil.cli")


def test_cli_import_without_optional_deps_does_not_exit(monkeypatch):
    cli = _reload_cli_without_deps(monkeypatch)
    assert cli._CLI_DEPS_AVAILABLE is False


def test_cli_main_exits_cleanly_without_optional_deps(monkeypatch):
    cli = _reload_cli_without_deps(monkeypatch)
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 1
