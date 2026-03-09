"""Terminology compliance CI gate tests.

Scans ALL source files in the project for prohibited terms that violate
FCC compliance design specifications. Any prohibited term found in source
code, comments, or documentation is a test failure.

This is a CI gate — these tests must pass before merge.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from goop_veil.compliance import PROHIBITED_TERMS

# Project root directories
PROJECT_ROOT = Path(__file__).parent.parent
PYTHON_SRC = PROJECT_ROOT / "python" / "goop_veil"
RUST_SRC = PROJECT_ROOT / "src"
FIRMWARE_SRC = PROJECT_ROOT / "firmware"


def _scan_files(directory: Path, suffixes: tuple[str, ...]) -> list[tuple[Path, int, str]]:
    """Scan files for prohibited terms.

    Returns list of (file_path, line_number, violation_description).
    """
    violations: list[tuple[Path, int, str]] = []
    if not directory.exists():
        return violations

    for path in directory.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix not in suffixes:
            continue
        # Skip compiled/binary files
        if "__pycache__" in str(path) or path.suffix == ".pyc":
            continue

        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue

        for line_num, line in enumerate(content.splitlines(), start=1):
            lower_line = line.lower()
            for term in PROHIBITED_TERMS:
                if term in lower_line:
                    violations.append((
                        path,
                        line_num,
                        f"Prohibited term '{term}' found in {path.name}:{line_num}: "
                        f"{line.strip()[:100]}",
                    ))

    return violations


class TestPythonTerminologyCompliance:
    """Scan Python source files for prohibited terms."""

    def test_no_prohibited_terms_in_python(self):
        violations = _scan_files(PYTHON_SRC, (".py",))
        # Filter out the compliance.py file itself (it defines the terms)
        violations = [
            v for v in violations
            if "compliance.py" not in str(v[0])
        ]
        if violations:
            report = "\n".join(v[2] for v in violations[:20])
            pytest.fail(
                f"Found {len(violations)} prohibited term(s) in Python source:\n{report}"
            )


class TestRustTerminologyCompliance:
    """Scan Rust source files for prohibited terms."""

    def test_no_prohibited_terms_in_rust(self):
        violations = _scan_files(RUST_SRC, (".rs",))
        if violations:
            report = "\n".join(v[2] for v in violations[:20])
            pytest.fail(
                f"Found {len(violations)} prohibited term(s) in Rust source:\n{report}"
            )


class TestFirmwareTerminologyCompliance:
    """Scan firmware C/H source files for prohibited terms."""

    def test_no_prohibited_terms_in_firmware(self):
        violations = _scan_files(FIRMWARE_SRC, (".c", ".h"))
        if violations:
            report = "\n".join(v[2] for v in violations[:20])
            pytest.fail(
                f"Found {len(violations)} prohibited term(s) in firmware source:\n{report}"
            )


class TestProhibitedTermsListIntegrity:
    """Verify the prohibited terms list itself is non-empty and well-formed."""

    def test_prohibited_terms_non_empty(self):
        assert len(PROHIBITED_TERMS) >= 10

    def test_prohibited_terms_are_lowercase(self):
        for term in PROHIBITED_TERMS:
            assert term == term.lower(), f"Prohibited term should be lowercase: '{term}'"
