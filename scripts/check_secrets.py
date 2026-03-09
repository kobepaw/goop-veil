#!/usr/bin/env python3
"""Lightweight high-signal secret scan for tracked source and workflow files."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
IGNORE_MARKER = "secrets-scan: ignore"
TEXT_SUFFIXES = {
    ".c",
    ".cc",
    ".cpp",
    ".h",
    ".hpp",
    ".ini",
    ".json",
    ".md",
    ".py",
    ".rs",
    ".sh",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}
SCAN_ROOTS = (
    ".github/",
    "python/",
    "firmware/",
    "scripts/",
    "Cargo.toml",
    "pyproject.toml",
)
PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("AWS access key", re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b")),
    ("GitHub token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}\b")),
    ("GitHub fine-grained PAT", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,255}\b")),
    ("Slack token", re.compile(r"\bxox(?:a|b|p|r|s)-[A-Za-z0-9-]{10,255}\b")),
    ("Private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("Stripe live key", re.compile(r"\bsk_live_[A-Za-z0-9]{16,255}\b")),
)


def tracked_files() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files"],
        cwd=PROJECT_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    files: list[Path] = []
    for raw_path in result.stdout.splitlines():
        if not raw_path.startswith(SCAN_ROOTS):
            continue
        path = PROJECT_ROOT / raw_path
        if path.suffix and path.suffix not in TEXT_SUFFIXES:
            continue
        if path.is_file():
            files.append(path)
    return files


def scan_file(path: Path) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return []

    findings: list[str] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        if IGNORE_MARKER in line:
            continue
        for label, pattern in PATTERNS:
            if pattern.search(line):
                findings.append(f"{path.relative_to(PROJECT_ROOT)}:{line_no}: {label}")
    return findings


def main() -> int:
    findings: list[str] = []
    for path in tracked_files():
        findings.extend(scan_file(path))

    if findings:
        print("Potential secrets detected:")
        for finding in findings:
            print(f"  {finding}")
        print(f"Add `{IGNORE_MARKER}` to a false positive line if it is intentional.")
        return 1

    print("No high-signal secrets detected in tracked source/workflow files.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
