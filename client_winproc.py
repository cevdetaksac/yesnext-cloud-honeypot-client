#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Hidden Windows process helpers (CREATE_NO_WINDOW + safe decode).

Canonical place for netsh/schtasks/powershell/query spawns so GUI/daemon never
flash consoles or crash on OEM encodings.
"""

from __future__ import annotations

import base64
import os
import subprocess
from typing import List, Optional, Sequence, Tuple, Union

CREATE_NO_WINDOW = 0x08000000

CmdArg = Union[str, os.PathLike]


def _creationflags() -> int:
    return int(getattr(subprocess, "CREATE_NO_WINDOW", CREATE_NO_WINDOW))


def _startupinfo():
    if os.name != "nt":
        return None
    try:
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        si.wShowWindow = 0  # SW_HIDE
        return si
    except Exception:
        return None


def decode_bytes(raw: Optional[bytes]) -> str:
    if not raw:
        return ""
    for enc in ("utf-8", "cp857", "cp850", "cp1254", "oem", "latin-1"):
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("utf-8", errors="replace")


def run_hidden(
    cmd: Sequence[CmdArg],
    *,
    timeout: Optional[float] = 20,
) -> Tuple[int, str, str]:
    """Run argv without a console window. Returns (rc, stdout, stderr)."""
    argv = [os.fspath(c) for c in cmd]
    kwargs: dict = {
        "shell": False,
        "capture_output": True,
        "text": False,
        "timeout": timeout if timeout and timeout > 0 else None,
    }
    if os.name == "nt":
        kwargs["creationflags"] = _creationflags()
        si = _startupinfo()
        if si is not None:
            kwargs["startupinfo"] = si
    try:
        p = subprocess.run(argv, **kwargs)
        return p.returncode, decode_bytes(p.stdout), decode_bytes(p.stderr)
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s"
    except Exception as e:
        return 1, "", f"{e}"


def run_ps(
    command: str,
    *,
    timeout: Optional[float] = 30,
) -> Tuple[int, str, str]:
    """powershell -NoProfile -Command <command>."""
    return run_hidden(
        ["powershell", "-NoProfile", "-Command", command],
        timeout=timeout,
    )


def run_ps_script(
    script: str,
    *,
    timeout: Optional[float] = 30,
) -> Tuple[int, str, str]:
    """powershell -EncodedCommand (UTF-16LE) — avoids $_ escaping issues."""
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    return run_hidden(
        ["powershell", "-NoProfile", "-EncodedCommand", encoded],
        timeout=timeout,
    )


def popen_detached(args: Sequence[CmdArg]) -> Optional[subprocess.Popen]:
    """Start a process detached from the console (daemon / helper spawn)."""
    argv = [os.fspath(c) for c in args]
    flags = 0
    if os.name == "nt":
        flags = (
            getattr(subprocess, "DETACHED_PROCESS", 0x00000008)
            | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200)
            | _creationflags()
        )
    try:
        return subprocess.Popen(argv, creationflags=flags, close_fds=True)
    except Exception:
        return None
