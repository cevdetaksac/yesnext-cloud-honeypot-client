#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cloud Honeypot Client — Remote Desktop Screen Mirror (MVP)

Dashboard “Uzak Masaüstü” için JPEG frame upload + remote input.
AnyDesk/Guacamole değil; IR ekran aynası (1–2 fps).

Commands:
  remote_stream_start / remote_stream_stop / remote_input

Upload:
  POST /api/remote/frame (multipart) — fallback POST /api/remote/frame-json
"""

from __future__ import annotations

import io
import threading
import time
from collections import deque
from typing import Callable, Optional

from client_helpers import log

# Defaults (overridable via remote_stream_start params)
DEFAULT_FPS = 2.0
DEFAULT_QUALITY = 45
DEFAULT_MAX_WIDTH = 1280
MAX_FRAME_BYTES = 2 * 1024 * 1024
IDLE_STOP_SECONDS = 300          # 5 min without activity → auto stop
INPUT_RATE_LIMIT = 20            # max remote_input events / second
INPUT_RATE_WINDOW = 1.0


class RemoteDesktopStreamer:
    """Captures primary screen, uploads JPEG frames, applies remote input."""

    def __init__(
        self,
        api_client=None,
        token_getter: Optional[Callable[[], str]] = None,
    ):
        self.api_client = api_client
        self.token_getter = token_getter or (lambda: "")

        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

        self._fps = DEFAULT_FPS
        self._quality = DEFAULT_QUALITY
        self._max_width = DEFAULT_MAX_WIDTH
        self._seq = 0
        self._last_activity = 0.0
        self._screen_w = 0
        self._screen_h = 0
        self._capture_w = 0
        self._capture_h = 0

        self._input_ts: deque = deque(maxlen=INPUT_RATE_LIMIT * 4)
        self._stats = {
            "frames_sent": 0,
            "frames_failed": 0,
            "bytes_sent": 0,
            "inputs_applied": 0,
            "inputs_rate_limited": 0,
        }

        self._ensure_dpi_aware()

    # ── Public API ────────────────────────────────────────────────

    def start(self, fps: float = DEFAULT_FPS, quality: int = DEFAULT_QUALITY,
              max_width: int = DEFAULT_MAX_WIDTH) -> dict:
        """Start background capture/upload loop."""
        with self._lock:
            self._fps = max(0.5, min(float(fps or DEFAULT_FPS), 5.0))
            self._quality = max(20, min(int(quality or DEFAULT_QUALITY), 85))
            self._max_width = max(640, min(int(max_width or DEFAULT_MAX_WIDTH), 1920))
            self._seq = 0
            self._last_activity = time.time()
            self._stop.clear()

            if self._running and self._thread and self._thread.is_alive():
                log(f"[REMOTE-DESKTOP] Already streaming — params updated "
                    f"(fps={self._fps} q={self._quality} w={self._max_width})")
                return {
                    "success": True,
                    "message": "stream already active; params updated",
                    "data": self.get_status(),
                }

            self._running = True
            self._thread = threading.Thread(
                target=self._loop,
                name="RemoteDesktopStream",
                daemon=True,
            )
            self._thread.start()
            log(f"[REMOTE-DESKTOP] ▶ Stream started "
                f"(fps={self._fps} q={self._quality} max_w={self._max_width})")
            return {
                "success": True,
                "message": "remote stream started",
                "data": self.get_status(),
            }

    def stop(self, reason: str = "user") -> dict:
        """Stop capture loop."""
        with self._lock:
            was = self._running
            self._running = False
            self._stop.set()
        if was:
            log(f"[REMOTE-DESKTOP] ⏹ Stream stopped ({reason})")
        return {
            "success": True,
            "message": f"remote stream stopped ({reason})",
            "data": self.get_status(),
        }

    def is_streaming(self) -> bool:
        return self._running

    def get_status(self) -> dict:
        return {
            "streaming": self._running,
            "fps": self._fps,
            "quality": self._quality,
            "max_width": self._max_width,
            "seq": self._seq,
            "screen": {"w": self._screen_w, "h": self._screen_h},
            "capture": {"w": self._capture_w, "h": self._capture_h},
            "stats": dict(self._stats),
        }

    def apply_input(self, params: dict) -> dict:
        """Apply a remote_input event (click / type_text / key)."""
        if not self._running:
            # Allow input only while streaming (security: no blind control)
            return {"success": False, "error": "stream not active"}

        if not self._check_input_rate():
            self._stats["inputs_rate_limited"] += 1
            return {"success": False, "error": "input rate limited"}

        self._touch_activity()
        event = (params.get("event") or "").strip().lower()

        try:
            if event in ("click", "dblclick"):
                ok = self._do_click(
                    float(params.get("x", 0)),
                    float(params.get("y", 0)),
                    str(params.get("button", "left") or "left"),
                    double=(event == "dblclick"),
                )
            elif event == "type_text":
                ok = self._do_type_text(str(params.get("text", "") or ""))
            elif event == "key":
                ok = self._do_key(str(params.get("key", "") or ""))
            else:
                return {"success": False, "error": f"unknown event: {event}"}

            if ok:
                self._stats["inputs_applied"] += 1
                return {"success": True, "message": f"input {event} applied"}
            return {"success": False, "error": f"input {event} failed"}
        except Exception as e:
            log(f"[REMOTE-DESKTOP] Input error: {e}")
            return {"success": False, "error": str(e)}

    # ── Capture loop ──────────────────────────────────────────────

    def _loop(self):
        interval = 1.0 / self._fps
        while self._running and not self._stop.is_set():
            t0 = time.time()
            try:
                if time.time() - self._last_activity > IDLE_STOP_SECONDS:
                    log("[REMOTE-DESKTOP] Idle timeout — auto stop")
                    self.stop(reason="idle_timeout")
                    break
                self._capture_and_upload()
            except Exception as e:
                self._stats["frames_failed"] += 1
                log(f"[REMOTE-DESKTOP] Frame error: {e}")
            # Refresh interval if params changed
            interval = 1.0 / max(self._fps, 0.5)
            elapsed = time.time() - t0
            sleep_for = max(0.05, interval - elapsed)
            self._stop.wait(sleep_for)

    def _capture_and_upload(self):
        token = self.token_getter()
        if not token or not self.api_client:
            return

        jpeg, w, h = self._grab_jpeg()
        if not jpeg:
            return

        self._seq += 1
        seq = self._seq
        ok = False
        if hasattr(self.api_client, "upload_remote_frame"):
            ok = bool(self.api_client.upload_remote_frame(
                token=token,
                jpeg_bytes=jpeg,
                width=w,
                height=h,
                seq=seq,
                fps=self._fps,
            ))
        if ok:
            self._stats["frames_sent"] += 1
            self._stats["bytes_sent"] += len(jpeg)
        else:
            self._stats["frames_failed"] += 1

    def _grab_jpeg(self):
        """Capture primary screen → resize → JPEG bytes."""
        try:
            from PIL import ImageGrab, Image
        except ImportError:
            log("[REMOTE-DESKTOP] Pillow (PIL) not available")
            return None, 0, 0

        try:
            img = ImageGrab.grab(all_screens=False)
        except Exception as e:
            log(f"[REMOTE-DESKTOP] ImageGrab failed: {e}")
            return None, 0, 0

        self._screen_w, self._screen_h = img.size

        if img.width > self._max_width:
            ratio = self._max_width / float(img.width)
            new_size = (self._max_width, max(1, int(img.height * ratio)))
            img = img.resize(new_size, Image.Resampling.LANCZOS if hasattr(Image, "Resampling") else Image.LANCZOS)

        self._capture_w, self._capture_h = img.size

        quality = self._quality
        jpeg = None
        for _ in range(4):
            buf = io.BytesIO()
            img.convert("RGB").save(buf, format="JPEG", quality=quality, optimize=True)
            data = buf.getvalue()
            if len(data) <= MAX_FRAME_BYTES:
                jpeg = data
                break
            quality = max(20, quality - 10)
        if jpeg is None:
            log("[REMOTE-DESKTOP] Frame still too large after quality reduce")
            return None, 0, 0
        return jpeg, self._capture_w, self._capture_h

    # ── Input helpers ─────────────────────────────────────────────

    def _check_input_rate(self) -> bool:
        now = time.time()
        while self._input_ts and now - self._input_ts[0] > INPUT_RATE_WINDOW:
            self._input_ts.popleft()
        if len(self._input_ts) >= INPUT_RATE_LIMIT:
            return False
        self._input_ts.append(now)
        return True

    def _touch_activity(self):
        self._last_activity = time.time()

    def _norm_to_px(self, x: float, y: float):
        """Normalize 0..1 coords to screen pixels (physical screen)."""
        sw = self._screen_w or self._get_screen_size()[0]
        sh = self._screen_h or self._get_screen_size()[1]
        self._screen_w, self._screen_h = sw, sh
        x = max(0.0, min(1.0, float(x)))
        y = max(0.0, min(1.0, float(y)))
        return int(x * (sw - 1)), int(y * (sh - 1))

    def _do_click(self, x: float, y: float, button: str, double: bool = False) -> bool:
        import ctypes
        px, py = self._norm_to_px(x, y)
        user32 = ctypes.windll.user32
        user32.SetCursorPos(px, py)
        time.sleep(0.02)

        btn = (button or "left").lower()
        if btn == "right":
            down, up = 0x0008, 0x0010  # RIGHTDOWN / RIGHTUP
        elif btn == "middle":
            down, up = 0x0020, 0x0040
        else:
            down, up = 0x0002, 0x0004  # LEFTDOWN / LEFTUP

        def _click_once():
            user32.mouse_event(down, 0, 0, 0, 0)
            time.sleep(0.03)
            user32.mouse_event(up, 0, 0, 0, 0)

        _click_once()
        if double:
            time.sleep(0.05)
            _click_once()
        return True

    def _do_type_text(self, text: str) -> bool:
        if not text:
            return True
        import ctypes
        from ctypes import wintypes

        user32 = ctypes.windll.user32
        INPUT_KEYBOARD = 1
        KEYEVENTF_UNICODE = 0x0004
        KEYEVENTF_KEYUP = 0x0002

        class KEYBDINPUT(ctypes.Structure):
            _fields_ = [
                ("wVk", wintypes.WORD),
                ("wScan", wintypes.WORD),
                ("dwFlags", wintypes.DWORD),
                ("time", wintypes.DWORD),
                ("dwExtraInfo", ctypes.POINTER(ctypes.c_ulong)),
            ]

        class INPUT(ctypes.Structure):
            class _I(ctypes.Union):
                _fields_ = [("ki", KEYBDINPUT)]
            _anonymous_ = ("i",)
            _fields_ = [("type", wintypes.DWORD), ("i", _I)]

        extra = ctypes.pointer(ctypes.c_ulong(0))
        for ch in text[:500]:  # safety cap
            for flags in (KEYEVENTF_UNICODE, KEYEVENTF_UNICODE | KEYEVENTF_KEYUP):
                inp = INPUT(type=INPUT_KEYBOARD)
                inp.ki = KEYBDINPUT(0, ord(ch), flags, 0, extra)
                user32.SendInput(1, ctypes.byref(inp), ctypes.sizeof(INPUT))
            time.sleep(0.005)
        return True

    def _do_key(self, key: str) -> bool:
        import ctypes
        user32 = ctypes.windll.user32
        key = (key or "").strip().lower()

        VK = {
            "enter": 0x0D,
            "esc": 0x1B,
            "escape": 0x1B,
            "tab": 0x09,
            "backspace": 0x08,
            "delete": 0x2E,
            "up": 0x26,
            "down": 0x28,
            "left": 0x25,
            "right": 0x27,
            "home": 0x24,
            "end": 0x23,
            "f5": 0x74,
            "win": 0x5B,
        }
        MOD = {
            "ctrl": 0x11,
            "control": 0x11,
            "alt": 0x12,
            "shift": 0x10,
            "win": 0x5B,
        }

        # ctrl+alt+del cannot be injected from user session on modern Windows
        if key in ("ctrl+alt+del", "ctrl-alt-del", "cad"):
            log("[REMOTE-DESKTOP] ctrl+alt+del blocked by OS — skipped")
            return False

        parts = [p for p in key.replace("-", "+").split("+") if p]
        if not parts:
            return False

        mods = []
        main = None
        for p in parts:
            if p in MOD and p not in ("win",) or p in ("ctrl", "control", "alt", "shift"):
                mods.append(MOD[p])
            elif p in VK:
                main = VK[p]
            elif len(p) == 1:
                main = ord(p.upper())
            elif p == "win":
                mods.append(MOD["win"])

        if main is None and len(parts) == 1 and parts[0] in MOD:
            main = MOD[parts[0]]
            mods = []

        if main is None:
            return False

        for m in mods:
            user32.keybd_event(m, 0, 0, 0)
        user32.keybd_event(main, 0, 0, 0)
        user32.keybd_event(main, 0, 2, 0)  # KEYUP
        for m in reversed(mods):
            user32.keybd_event(m, 0, 2, 0)
        return True

    # ── Screen / DPI ──────────────────────────────────────────────

    @staticmethod
    def _ensure_dpi_aware():
        try:
            import ctypes
            try:
                ctypes.windll.shcore.SetProcessDpiAwareness(2)
            except Exception:
                ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass

    @staticmethod
    def _get_screen_size():
        try:
            import ctypes
            user32 = ctypes.windll.user32
            return int(user32.GetSystemMetrics(0)), int(user32.GetSystemMetrics(1))
        except Exception:
            return 1920, 1080
