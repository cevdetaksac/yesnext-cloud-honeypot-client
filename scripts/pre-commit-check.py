#!/usr/bin/env python3
"""Pre-commit: block committing secrets and runtime logs."""
import re
import sys
from pathlib import Path

BLOCKED_PATTERNS = [
    re.compile(r"client\.log$"),
    re.compile(r"token\.dat$"),
    re.compile(r"token\.txt$"),
]
SECRET_IN_DIFF = re.compile(
    r"['\"]token['\"]\s*:\s*['\"][0-9a-f]{8}-[0-9a-f]{4}-",
    re.I,
)


def main() -> int:
    staged = Path(".git")
    if not staged.exists():
        return 0
    import subprocess
    out = subprocess.check_output(["git", "diff", "--cached", "--name-only"], text=True)
    for line in out.splitlines():
        for pat in BLOCKED_PATTERNS:
            if pat.search(line):
                print(f"Blocked: refusing to commit {line}")
                return 1
    diff = subprocess.check_output(["git", "diff", "--cached"], text=True, errors="replace")
    if SECRET_IN_DIFF.search(diff):
        print("Blocked: possible API token in staged diff")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
