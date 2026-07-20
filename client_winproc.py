#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Hidden Windows process helpers (CREATE_NO_WINDOW + safe decode).

Canonical place for netsh/schtasks/powershell spawns so GUI/daemon never
flash consoles or crash on OEM encodings.
"""

from __future__ import annotations

import os
import subprocess
from typing import List, Optional, Tuple

CREATE_NO_WINDOW = 0x08000000


def run_hidden(
    cmd: List[str],
    *,
    timeout: Optional[float] = 20,
) -> Tuple[int, str, str]:
    """Run argv without a console window. Returns (rc, stdout, stderr)."""
    def _dec(raw: Optional[bytes]) -> str:
        if not raw:
            return ""
        for enc in ("utf-8", "cp857", "cp850", "cp1254", "oem", "latin-1"):
            try:
                return raw.decode(enc)
            except (UnicodeDecodeError, LookupError):
                continue
        return raw.decode("utf-8", errors="replace")

    kwargs: dict = {
        "shell": False,
        "capture_output": True,
        "text": False,
        "timeout": timeout if timeout and timeout > 0 else None,
    }
    if os.name == "nt":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", CREATE_NO_WINDOW)
        try:
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            si.wShowWindow = 0  # SW_HIDE
            kwargs["startupinfo"] = si
        except Exception:
            pass
    try:
        p = subprocess.run(cmd, **kwargs)
        return p.returncode, _dec(p.stdout), _dec(p.stderr)
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s"
    except Exception as e:
        return 1, "", f"{e}"
