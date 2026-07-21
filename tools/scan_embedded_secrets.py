#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""REV-102 — lightweight embedded secret scanner for CI/source trees.

Fails the process if high-confidence private key / credential patterns appear
outside allowlisted documentation fixtures.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKIP_DIR_NAMES = {
    ".git", ".venv", "venv", "__pycache__", "dist", "build", "node_modules",
    ".pytest_cache", "agent-transcripts",
}
# Public identifiers / docs are not secrets.
ALLOW_SUBSTRINGS = (
    "docs/",
    "honeypot-contract/",
    "tests/",
    "CHANGELOG",
    "SECURITY_RESILIENCE",
)

PATTERNS = [
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "private_key"),
    (re.compile(r"(?i)api[_-]?secret\s*[:=]\s*['\"][A-Za-z0-9/+=]{24,}"), "api_secret"),
    (re.compile(r"(?i)(aws_secret_access_key|private_key)\s*[:=]\s*['\"][^'\"]{16,}"), "named_secret"),
]


def _allowed(path: Path) -> bool:
    rel = path.relative_to(ROOT).as_posix()
    return any(token in rel for token in ALLOW_SUBSTRINGS)


def main() -> int:
    findings = []
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIR_NAMES]
        for name in filenames:
            path = Path(dirpath) / name
            if path.suffix.lower() not in {
                ".py", ".ps1", ".json", ".md", ".yml", ".yaml", ".txt", ".nsi",
                ".spec", ".toml", ".ini", ".cfg",
            }:
                continue
            if _allowed(path):
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            for pattern, kind in PATTERNS:
                if pattern.search(text):
                    findings.append(f"{kind}: {path.relative_to(ROOT).as_posix()}")
                    break
    if findings:
        print("Embedded secret scan FAILED:")
        for item in findings:
            print(f"  - {item}")
        return 1
    print("Embedded secret scan OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
