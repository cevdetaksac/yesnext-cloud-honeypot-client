#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cloud Honeypot Client — Remote Desktop Screen Mirror

Dashboard “Uzak Masaüstü” — akıcı WebSocket + HTTP fallback.

Primary:
  wss://…/ws/remote/agent?token=…  → binary JPEG + JSON meta/input
Fallback:
  POST /api/remote/frame (+ frame-json)
  GET  /api/remote/inputs (200–500 ms) when WS down

Commands:
  remote_stream_start / remote_stream_stop / remote_input
"""

from __future__ import annotations

import io
import json
import threading
import time
from collections import deque
from typing import Callable, Optional
from urllib.parse import urlencode

from client_helpers import log

# Defaults tuned for smooth dashboard viewing (prompt: 5–10 fps, q~30–40)
DEFAULT_FPS = 6.0
DEFAULT_QUALITY = 35
DEFAULT_MAX_WIDTH = 1280
TARGET_FRAME_BYTES = 320 * 1024       # aim ≤ ~320 KB
MAX_FRAME_BYTES = 2 * 1024 * 1024
IDLE_STOP_SECONDS = 300
INPUT_RATE_LIMIT = 60                 # allow drag moves
INPUT_RATE_WINDOW = 1.0
HTTP_INPUT_POLL_SEC = 0.30
WS_RECONNECT_SEC = 3.0
META_EVERY_N_FRAMES = 15


def _api_to_ws_agent_url(api_base: str, token: str) -> str:
    """https://host/api → wss://host/ws/remote/agent?token=…"""
    base = (api_base or "").strip().rstrip("/")
    if base.lower().endswith("/api"):
        origin = base[:-4]
    else:
        origin = base
    if origin.startswith("https://"):
        ws = "wss://" + origin[len("https://"):]
    elif origin.startswith("http://"):
        ws = "ws://" + origin[len("http://"):]
    else:
        ws = "wss://" + origin.lstrip("/")
    return f"{ws}/ws/remote/agent?{urlencode({'token': token})}"


class RemoteDesktopStreamer:
    """Captures primary screen; streams via WebSocket (preferred) or HTTP."""

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
        self._ws_thread: Optional[threading.Thread] = None
        self._input_poll_thread: Optional[threading.Thread] = None
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

        self._ws = None
        self._ws_ok = False
        self._transport = "idle"  # idle | websocket | http

        self._input_ts: deque = deque(maxlen=INPUT_RATE_LIMIT * 4)
        self._stats = {
            "frames_sent": 0,
            "frames_failed": 0,
            "bytes_sent": 0,
            "inputs_applied": 0,
            "inputs_rate_limited": 0,
            "ws_reconnects": 0,
            "http_fallbacks": 0,
        }

        self._ensure_dpi_aware()

    # ── Public API ────────────────────────────────────────────────

    def start(self, fps: float = DEFAULT_FPS, quality: int = DEFAULT_QUALITY,
              max_width: int = DEFAULT_MAX_WIDTH) -> dict:
        """Start capture + WS (with HTTP fallback)."""
        with self._lock:
            self._fps = max(1.0, min(float(fps or DEFAULT_FPS), 10.0))
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
            self._transport = "http"  # until WS connects
            self._thread = threading.Thread(
                target=self._capture_loop,
                name="RemoteDesktopCapture",
                daemon=True,
            )
            self._thread.start()
            self._ws_thread = threading.Thread(
                target=self._ws_loop,
                name="RemoteDesktopWS",
                daemon=True,
            )
            self._ws_thread.start()
            self._input_poll_thread = threading.Thread(
                target=self._http_input_poll_loop,
                name="RemoteDesktopHttpInput",
                daemon=True,
            )
            self._input_poll_thread.start()

            log(f"[REMOTE-DESKTOP] ▶ Stream started "
                f"(fps={self._fps} q={self._quality} max_w={self._max_width} ws+http)")
            return {
                "success": True,
                "message": "remote stream started (websocket preferred)",
                "data": self.get_status(),
            }

    def stop(self, reason: str = "user") -> dict:
        """Stop capture + websocket."""
        with self._lock:
            was = self._running
            self._running = False
            self._stop.set()
        self._close_ws()
        self._transport = "idle"
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
            "transport": self._transport,
            "websocket": self._ws_ok,
            "fps": self._fps,
            "quality": self._quality,
            "max_width": self._max_width,
            "seq": self._seq,
            "screen": {"w": self._screen_w, "h": self._screen_h},
            "capture": {"w": self._capture_w, "h": self._capture_h},
            "stats": dict(self._stats),
        }

    def apply_input(self, params: dict) -> dict:
        """Apply remote input (WS message or HTTP command / poll)."""
        if not self._running:
            return {"success": False, "error": "stream not active"}

        event = (params.get("event") or "").strip().lower()
        # Move events can be frequent — softer rate limit
        if event == "move":
            if not self._check_input_rate(soft=True):
                self._stats["inputs_rate_limited"] += 1
                return {"success": False, "error": "input rate limited"}
        else:
            if not self._check_input_rate(soft=False):
                self._stats["inputs_rate_limited"] += 1
                return {"success": False, "error": "input rate limited"}

        self._touch_activity()

        try:
            ok = False
            if event in ("click", "dblclick"):
                ok = self._do_click(
                    float(params.get("x", 0)),
                    float(params.get("y", 0)),
                    str(params.get("button", "left") or "left"),
                    double=(event == "dblclick"),
                )
            elif event == "mousedown":
                ok = self._do_mouse_button(
                    float(params.get("x", 0)),
                    float(params.get("y", 0)),
                    str(params.get("button", "left") or "left"),
                    down=True,
                )
            elif event == "mouseup":
                ok = self._do_mouse_button(
                    float(params.get("x", 0)),
                    float(params.get("y", 0)),
                    str(params.get("button", "left") or "left"),
                    down=False,
                )
            elif event in ("move", "mousemove"):
                ok = self._do_move(
                    float(params.get("x", 0)),
                    float(params.get("y", 0)),
                )
            elif event == "wheel":
                delta = params.get("key", params.get("delta", params.get("deltaY", -120)))
                try:
                    delta = int(float(delta))
                except Exception:
                    delta = -120
                ok = self._do_wheel(
                    float(params.get("x", 0.5)),
                    float(params.get("y", 0.5)),
                    delta,
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

    def _capture_loop(self):
        while self._running and not self._stop.is_set():
            t0 = time.time()
            try:
                if time.time() - self._last_activity > IDLE_STOP_SECONDS:
                    log("[REMOTE-DESKTOP] Idle timeout — auto stop")
                    self.stop(reason="idle_timeout")
                    break
                self._capture_and_send()
            except Exception as e:
                self._stats["frames_failed"] += 1
                log(f"[REMOTE-DESKTOP] Frame error: {e}")
            interval = 1.0 / max(self._fps, 0.5)
            elapsed = time.time() - t0
            self._stop.wait(max(0.02, interval - elapsed))

    def _capture_and_send(self):
        token = self.token_getter()
        if not token:
            return

        jpeg, w, h = self._grab_jpeg()
        if not jpeg:
            return

        self._seq += 1
        seq = self._seq
        ok = False

        if self._ws_ok and self._ws is not None:
            ok = self._ws_send_frame(jpeg, w, h, seq)
            if ok:
                self._transport = "websocket"
            else:
                self._ws_ok = False
                self._transport = "http"

        if not ok:
            ok = self._http_send_frame(token, jpeg, w, h, seq)
            if ok:
                self._stats["http_fallbacks"] += 1
                self._transport = "http"

        if ok:
            self._stats["frames_sent"] += 1
            self._stats["bytes_sent"] += len(jpeg)
        else:
            self._stats["frames_failed"] += 1

    def _http_send_frame(self, token: str, jpeg: bytes, w: int, h: int, seq: int) -> bool:
        if not self.api_client or not hasattr(self.api_client, "upload_remote_frame"):
            return False
        return bool(self.api_client.upload_remote_frame(
            token=token,
            jpeg_bytes=jpeg,
            width=w,
            height=h,
            seq=seq,
            fps=self._fps,
        ))

    def _grab_jpeg(self):
        """Capture primary screen → resize → JPEG (target ≤ TARGET_FRAME_BYTES)."""
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
            # BILINEAR is faster than LANCZOS at high fps
            resample = Image.Resampling.BILINEAR if hasattr(Image, "Resampling") else Image.BILINEAR
            img = img.resize(new_size, resample)

        self._capture_w, self._capture_h = img.size
        rgb = img.convert("RGB")

        quality = self._quality
        jpeg = None
        for _ in range(6):
            buf = io.BytesIO()
            rgb.save(buf, format="JPEG", quality=quality, optimize=False, subsampling=2)
            data = buf.getvalue()
            if len(data) <= TARGET_FRAME_BYTES or quality <= 22:
                if len(data) <= MAX_FRAME_BYTES:
                    jpeg = data
                break
            quality = max(22, quality - 5)
        if jpeg is None:
            log("[REMOTE-DESKTOP] Frame still too large after quality reduce")
            return None, 0, 0
        return jpeg, self._capture_w, self._capture_h

    # ── WebSocket transport ───────────────────────────────────────

    def _ws_loop(self):
        """Keep trying WebSocket while streaming; fall back to HTTP between attempts."""
        while self._running and not self._stop.is_set():
            token = self.token_getter()
            if not token or not self.api_client:
                self._stop.wait(WS_RECONNECT_SEC)
                continue
            try:
                import websocket  # websocket-client
            except ImportError:
                log("[REMOTE-DESKTOP] websocket-client missing — HTTP only")
                self._transport = "http"
                return

            api_base = getattr(self.api_client, "base_url", "") or ""
            # base_url is typically …/api
            url = _api_to_ws_agent_url(api_base, token)
            log(f"[REMOTE-DESKTOP] WS connecting…")

            connected = threading.Event()

            def on_open(ws):
                self._ws = ws
                self._ws_ok = True
                self._transport = "websocket"
                connected.set()
                try:
                    ws.send(json.dumps({"t": "hello", "role": "agent"}))
                    self._ws_send_meta(force=True)
                except Exception as e:
                    log(f"[REMOTE-DESKTOP] WS hello failed: {e}")
                log("[REMOTE-DESKTOP] WS connected")

            def on_message(ws, message):
                self._on_ws_message(message)

            def on_error(ws, error):
                log(f"[REMOTE-DESKTOP] WS error: {error}")

            def on_close(ws, status_code, msg):
                self._ws_ok = False
                if self._running:
                    self._transport = "http"
                    self._stats["ws_reconnects"] += 1
                log(f"[REMOTE-DESKTOP] WS closed ({status_code})")

            try:
                verify = True
                try:
                    from client_security_utils import resolve_tls_verify
                    verify = bool(resolve_tls_verify())
                except Exception:
                    pass

                ws_app = websocket.WebSocketApp(
                    url,
                    on_open=on_open,
                    on_message=on_message,
                    on_error=on_error,
                    on_close=on_close,
                )
                # run_forever blocks until close
                run_kwargs = {
                    "ping_interval": 20,
                    "ping_timeout": 10,
                }
                if not verify:
                    import ssl
                    run_kwargs["sslopt"] = {"cert_reqs": ssl.CERT_NONE}
                t = threading.Thread(
                    target=lambda: ws_app.run_forever(**run_kwargs),
                    name="RemoteDesktopWSRun",
                    daemon=True,
                )
                t.start()
                # Wait until stopped or connection dies
                while self._running and not self._stop.is_set() and t.is_alive():
                    self._stop.wait(0.5)
                try:
                    ws_app.close()
                except Exception:
                    pass
                t.join(timeout=2)
            except Exception as e:
                log(f"[REMOTE-DESKTOP] WS loop error: {e}")
                self._ws_ok = False
                self._transport = "http"

            self._ws = None
            if self._running and not self._stop.is_set():
                self._stop.wait(WS_RECONNECT_SEC)

    def _close_ws(self):
        self._ws_ok = False
        ws = self._ws
        self._ws = None
        if ws is not None:
            try:
                ws.close()
            except Exception:
                pass

    def _ws_send_meta(self, force: bool = False):
        if not self._ws_ok or self._ws is None:
            return
        if not force and self._seq % META_EVERY_N_FRAMES != 0:
            return
        try:
            meta = {
                "t": "meta",
                "width": int(self._capture_w or self._max_width),
                "height": int(self._capture_h or 720),
                "seq": int(self._seq),
                "fps": float(self._fps),
            }
            self._ws.send(json.dumps(meta))
        except Exception as e:
            log(f"[REMOTE-DESKTOP] WS meta failed: {e}")
            self._ws_ok = False

    def _ws_send_frame(self, jpeg: bytes, w: int, h: int, seq: int) -> bool:
        if not self._ws_ok or self._ws is None:
            return False
        try:
            import websocket
            self._ws_send_meta(force=(seq <= 1 or seq % META_EVERY_N_FRAMES == 0))
            self._ws.send(jpeg, opcode=websocket.ABNF.OPCODE_BINARY)
            return True
        except Exception as e:
            log(f"[REMOTE-DESKTOP] WS binary send failed: {e}")
            self._ws_ok = False
            return False

    def _on_ws_message(self, message):
        try:
            if isinstance(message, bytes):
                message = message.decode("utf-8", errors="replace")
            data = json.loads(message)
        except Exception:
            return
        if not isinstance(data, dict):
            return
        t = (data.get("t") or data.get("type") or "").lower()
        if t in ("input", "remote_input", ""):
            # {"t":"input","event":"mousedown",...} or bare input fields
            params = dict(data)
            params.pop("t", None)
            params.pop("type", None)
            if "event" in params or "text" in params or "key" in params:
                self.apply_input(params)

    # ── HTTP input poll (only when WS down) ───────────────────────

    def _http_input_poll_loop(self):
        while self._running and not self._stop.is_set():
            try:
                if not self._ws_ok:
                    token = self.token_getter()
                    if token and self.api_client and hasattr(self.api_client, "fetch_remote_inputs"):
                        events = self.api_client.fetch_remote_inputs(token, limit=80) or []
                        for ev in events:
                            if isinstance(ev, dict):
                                self.apply_input(ev)
            except Exception as e:
                log(f"[REMOTE-DESKTOP] HTTP input poll error: {e}")
            self._stop.wait(HTTP_INPUT_POLL_SEC)

    # ── Input helpers ─────────────────────────────────────────────

    def _check_input_rate(self, soft: bool = False) -> bool:
        now = time.time()
        while self._input_ts and now - self._input_ts[0] > INPUT_RATE_WINDOW:
            self._input_ts.popleft()
        limit = INPUT_RATE_LIMIT if soft else max(20, INPUT_RATE_LIMIT // 2)
        if len(self._input_ts) >= limit:
            return False
        self._input_ts.append(now)
        return True

    def _touch_activity(self):
        self._last_activity = time.time()

    def _norm_to_px(self, x: float, y: float):
        sw = self._screen_w or self._get_screen_size()[0]
        sh = self._screen_h or self._get_screen_size()[1]
        self._screen_w, self._screen_h = sw, sh
        x = max(0.0, min(1.0, float(x)))
        y = max(0.0, min(1.0, float(y)))
        return int(x * (sw - 1)), int(y * (sh - 1))

    def _do_move(self, x: float, y: float) -> bool:
        import ctypes
        px, py = self._norm_to_px(x, y)
        ctypes.windll.user32.SetCursorPos(px, py)
        return True

    def _do_mouse_button(self, x: float, y: float, button: str, down: bool) -> bool:
        import ctypes
        px, py = self._norm_to_px(x, y)
        user32 = ctypes.windll.user32
        user32.SetCursorPos(px, py)
        btn = (button or "left").lower()
        if btn == "right":
            flag = 0x0008 if down else 0x0010
        elif btn == "middle":
            flag = 0x0020 if down else 0x0040
        else:
            flag = 0x0002 if down else 0x0004
        user32.mouse_event(flag, 0, 0, 0, 0)
        return True

    def _do_wheel(self, x: float, y: float, delta: int) -> bool:
        import ctypes
        px, py = self._norm_to_px(x, y)
        user32 = ctypes.windll.user32
        user32.SetCursorPos(px, py)
        # MOUSEEVENTF_WHEEL = 0x0800; delta typically ±120
        user32.mouse_event(0x0800, 0, 0, int(delta), 0)
        return True

    def _do_click(self, x: float, y: float, button: str, double: bool = False) -> bool:
        self._do_mouse_button(x, y, button, down=True)
        time.sleep(0.02)
        self._do_mouse_button(x, y, button, down=False)
        if double:
            time.sleep(0.04)
            self._do_mouse_button(x, y, button, down=True)
            time.sleep(0.02)
            self._do_mouse_button(x, y, button, down=False)
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
        for ch in text[:500]:
            for flags in (KEYEVENTF_UNICODE, KEYEVENTF_UNICODE | KEYEVENTF_KEYUP):
                inp = INPUT(type=INPUT_KEYBOARD)
                inp.ki = KEYBDINPUT(0, ord(ch), flags, 0, extra)
                user32.SendInput(1, ctypes.byref(inp), ctypes.sizeof(INPUT))
            time.sleep(0.003)
        return True

    def _do_key(self, key: str) -> bool:
        import ctypes
        user32 = ctypes.windll.user32
        key = (key or "").strip().lower()

        VK = {
            "enter": 0x0D, "esc": 0x1B, "escape": 0x1B, "tab": 0x09,
            "backspace": 0x08, "delete": 0x2E,
            "up": 0x26, "down": 0x28, "left": 0x25, "right": 0x27,
            "home": 0x24, "end": 0x23, "f5": 0x74, "win": 0x5B,
            "space": 0x20, "pageup": 0x21, "pagedown": 0x22,
        }
        MOD = {
            "ctrl": 0x11, "control": 0x11, "alt": 0x12,
            "shift": 0x10, "win": 0x5B,
        }

        if key in ("ctrl+alt+del", "ctrl-alt-del", "cad"):
            log("[REMOTE-DESKTOP] ctrl+alt+del blocked by OS — skipped")
            return False

        parts = [p for p in key.replace("-", "+").split("+") if p]
        if not parts:
            return False

        mods = []
        main = None
        for p in parts:
            if p in ("ctrl", "control", "alt", "shift", "win"):
                mods.append(MOD[p])
            elif p in VK:
                main = VK[p]
            elif len(p) == 1:
                main = ord(p.upper())

        if main is None and len(parts) == 1 and parts[0] in MOD:
            main = MOD[parts[0]]
            mods = []

        if main is None:
            return False

        for m in mods:
            user32.keybd_event(m, 0, 0, 0)
        user32.keybd_event(main, 0, 0, 0)
        user32.keybd_event(main, 0, 2, 0)
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
