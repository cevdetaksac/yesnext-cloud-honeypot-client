#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cloud Honeypot Client — Remote Desktop Screen Mirror

Dashboard “Uzak Masaüstü” — akıcı WebSocket + HTTP fallback.

Primary:
  wss://…/ws/remote/agent  + Authorization: Bearer …  → binary JPEG + JSON meta/input
  (legacy: ?token= only if api.legacy_token_query=true)
Fallback:
  POST /api/remote/frame (+ frame-json) — ACK may include inputs[] (primary input path)
  GET  /api/remote/inputs (200–500 ms) backup when queue not drained via frame ACK

Commands:
  remote_stream_start / remote_stream_stop / remote_input
"""

from __future__ import annotations

import io
import json
import queue
import threading
import time
from collections import deque
from typing import Callable, Optional, Tuple
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
META_EVERY_N_FRAMES = 5
BLACK_MEAN_THRESHOLD = 6.0            # nearly-black capture → skip send
HTTP_KEYFRAME_EVERY = 6               # also POST HTTP every N frames (dashboard cache)
MIN_JPEG_BYTES = 1500                 # API rejects tinier frames ("Frame too small")
MIN_GOOD_JPEG_BYTES = 5 * 1024        # healthy 1280q35 frame is usually ≥5KB
CAPTURE_FAIL_SECONDS = 10.0           # no frames in this window → fail stream
PROBE_TIMEOUT_SEC = 12.0              # SYSTEM→user CreateProcessAsUser needs cold-start room


def _api_to_ws_agent_url(api_base: str, token: str = "") -> str:
    """https://host/api → wss://host/ws/remote/agent (Bearer via header).

    If api.legacy_token_query is enabled, appends ?token= for old servers.
    """
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
    url = f"{ws}/ws/remote/agent"
    try:
        from client_security_utils import use_legacy_token_query
        if token and use_legacy_token_query():
            return f"{url}?{urlencode({'token': token})}"
    except Exception:
        pass
    return url


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
        self._out_q: queue.Queue = queue.Queue(maxsize=8)  # WS sends from WS thread only
        self._ws_send_lock = threading.Lock()
        self._black_warn_ts = 0.0
        self._capture_method = "none"
        self._stream_started_at = 0.0
        self._use_user_helper = False  # Session 0 / other session → CreateProcessAsUser helper
        self._input_desktop = None
        self._desktop_attached = False
        self._tscon_attempted = False
        self._last_good_jpeg: Optional[bytes] = None
        self._last_good_wh: Tuple[int, int] = (0, 0)
        # Dashboard session picker (AGENT_REMOTE_SESSION_SELECT_PROMPT)
        self._target_session_id: Optional[int] = None
        self._target_username: str = ""
        self._monitor_index: int = 0

        self._input_ts: deque = deque(maxlen=INPUT_RATE_LIMIT * 4)
        self._stats = {
            "frames_sent": 0,
            "frames_failed": 0,
            "bytes_sent": 0,
            "inputs_applied": 0,
            "inputs_piggyback": 0,
            "inputs_rate_limited": 0,
            "ws_reconnects": 0,
            "http_fallbacks": 0,
            "black_frames": 0,
            "capture_method": "none",
        }

        self._ensure_dpi_aware()

    # ── Public API ────────────────────────────────────────────────

    def start(self, fps: float = DEFAULT_FPS, quality: int = DEFAULT_QUALITY,
              max_width: int = DEFAULT_MAX_WIDTH,
              session_id: Optional[int] = None,
              username: Optional[str] = None,
              monitor: int = 0) -> dict:
        """Start capture + WS (with HTTP fallback).

        Honest start: resolve WTS session_id, probe desktop first.
        No interactive sessions → NO_INTERACTIVE_SESSION.
        screen/capture 0×0 → CAPTURE_NO_DESKTOP.
        """
        with self._lock:
            self._fps = max(1.0, min(float(fps or DEFAULT_FPS), 10.0))
            self._quality = max(20, min(int(quality or DEFAULT_QUALITY), 85))
            self._max_width = max(640, min(int(max_width or DEFAULT_MAX_WIDTH), 1920))
            try:
                self._monitor_index = max(0, int(monitor or 0))
            except (TypeError, ValueError):
                self._monitor_index = 0
            self._seq = 0
            self._last_activity = time.time()
            self._stop.clear()
            self._stats["frames_sent"] = 0
            self._stats["bytes_sent"] = 0
            self._stats["frames_failed"] = 0
            self._stats["black_frames"] = 0
            self._desktop_attached = False
            self._tscon_attempted = False
            self._last_good_jpeg = None
            self._last_good_wh = (0, 0)
            self._use_user_helper = False

            # ── Resolve target WTS session (dashboard picker) ──
            sessions = self._enumerate_sessions()
            interactive = [
                s for s in sessions
                if int(s.get("session_id") or 0) > 0
                and str(s.get("protocol") or "").lower() != "services"
            ]
            if not interactive:
                err = "NO_INTERACTIVE_SESSION"
                msg = "No interactive desktop to mirror"
                log(f"[REMOTE-DESKTOP] ✖ {err}: {msg}")
                self._running = False
                self._transport = "idle"
                self._target_session_id = None
                self._target_username = ""
                return {
                    "success": False,
                    "error": err,
                    "message": msg,
                    "data": self.get_status(),
                }

            resolved_sid: Optional[int] = None
            if session_id is not None:
                try:
                    resolved_sid = int(session_id)
                except (TypeError, ValueError):
                    resolved_sid = None
            if resolved_sid is not None:
                match = next(
                    (s for s in interactive if int(s["session_id"]) == resolved_sid),
                    None,
                )
                if match is None:
                    err = "NO_INTERACTIVE_SESSION"
                    msg = f"Requested session_id={resolved_sid} not in interactive session list"
                    log(f"[REMOTE-DESKTOP] ✖ {err}: {msg}")
                    return {
                        "success": False,
                        "error": err,
                        "message": msg,
                        "data": self.get_status(),
                    }
                self._target_session_id = resolved_sid
                self._target_username = (
                    (username or "").strip()
                    or str(match.get("username") or "")
                )
            else:
                picked = self._pick_default_session(interactive)
                self._target_session_id = int(picked["session_id"])
                self._target_username = (
                    (username or "").strip()
                    or str(picked.get("username") or "")
                )

            pid_sid, csid = self._session_ids()
            # Capture other user's desktop via helper when not already in that session
            need_helper = (
                self._target_session_id is not None
                and (pid_sid is None or int(pid_sid) != int(self._target_session_id))
            )
            log(
                f"[REMOTE-DESKTOP] start — target_session={self._target_session_id} "
                f"user={self._target_username!r} monitor={self._monitor_index} "
                f"pid_session={pid_sid} console={csid} helper={need_helper}"
            )

            if self._running and self._thread and self._thread.is_alive():
                st = self.get_status()
                same_sid = st.get("session_id") == self._target_session_id
                if same_sid and (st.get("screen") or {}).get("w", 0) > 0:
                    log(f"[REMOTE-DESKTOP] Already streaming — params updated "
                        f"(fps={self._fps} q={self._quality} w={self._max_width})")
                    return {
                        "success": True,
                        "message": "stream already active; params updated",
                        "data": st,
                    }
                # Different session or dead capture — restart
                self._running = False
                self._stop.set()

            sid, csid = pid_sid, csid
            state = self._session_connect_state(self._target_session_id)
            log(f"[REMOTE-DESKTOP] start probe — target={self._target_session_id} "
                f"state={state} pid_session={sid}")

            jpeg, w, h = None, 0, 0
            helper_err = ""
            if need_helper:
                t_helper = time.time()
                jpeg, w, h = self._grab_via_user_helper()
                took = time.time() - t_helper
                log(f"[REMOTE-DESKTOP] helper probe took {took:.1f}s "
                    f"jpeg={0 if not jpeg else len(jpeg)}B {w}x{h}")
                if not jpeg or w <= 0 or h <= 0 or len(jpeg) < MIN_JPEG_BYTES:
                    helper_err = (
                        f"user-helper failed for session={self._target_session_id} "
                        f"(jpeg={0 if not jpeg else len(jpeg)}B, {took:.1f}s). "
                        "Agent is Session 0 — capture requires WTSQueryUserToken/"
                        "CreateProcessAsUser into the selected RDP/console session."
                    )
                    # Do NOT fall back to Session-0 BitBlt (always black for other sessions)
                    err = "CAPTURE_NO_DESKTOP"
                    msg = helper_err
                    log(f"[REMOTE-DESKTOP] ✖ {err}: {msg}")
                    self._running = False
                    self._transport = "idle"
                    return {
                        "success": False,
                        "error": err,
                        "message": msg,
                        "data": self.get_status(),
                    }
            else:
                # Capture thread-less probe: attach input desktop first (RDP/elevated)
                self._attach_input_desktop()
                if state in ("Disconnected", "Down", "Init"):
                    self._try_reconnect_session_to_console(self._target_session_id)

                # Probe BEFORE advertising streaming=true
                jpeg, w, h = self._grab_jpeg()
                blackish = "+black" in (self._capture_method or "")
                if blackish or not jpeg:
                    # One more attempt after forced console reconnect
                    if not self._tscon_attempted:
                        self._try_reconnect_session_to_console(self._target_session_id)
                        time.sleep(0.4)
                        self._desktop_attached = False
                        self._attach_input_desktop()
                        jpeg, w, h = self._grab_jpeg()
                        blackish = "+black" in (self._capture_method or "")
                if not jpeg or w <= 0 or h <= 0 or len(jpeg) < MIN_JPEG_BYTES or blackish:
                    jpeg2, w2, h2 = self._grab_via_user_helper()
                    if jpeg2 and w2 > 0 and h2 > 0 and len(jpeg2) >= MIN_JPEG_BYTES:
                        jpeg, w, h = jpeg2, w2, h2

            if not jpeg or w <= 0 or h <= 0 or len(jpeg) < MIN_JPEG_BYTES:
                err = "CAPTURE_NO_DESKTOP"
                msg = (
                    "No interactive desktop bitmap "
                    f"(session={self._target_session_id}, size={w}x{h}, "
                    f"jpeg={0 if not jpeg else len(jpeg)}B)."
                )
                log(f"[REMOTE-DESKTOP] ✖ {err}: {msg}")
                self._running = False
                self._transport = "idle"
                return {
                    "success": False,
                    "error": err,
                    "message": msg,
                    "data": self.get_status(),
                }

            if need_helper or self._use_user_helper:
                self._use_user_helper = True

            self._screen_w = self._screen_w or w
            self._screen_h = self._screen_h or h
            self._capture_w, self._capture_h = w, h
            log(f"[REMOTE-DESKTOP] probe ok — screen={self._screen_w}x{self._screen_h} "
                f"capture={w}x{h} jpeg={len(jpeg)}B method={self._capture_method} "
                f"session={self._target_session_id}")

            self._running = True
            self._transport = "http"
            self._drain_out_q()
            self._stream_started_at = time.time()
            if self._use_user_helper:
                # CreateProcessAsUser per frame is heavy — keep IR usable
                self._fps = min(self._fps, 2.0)

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

            # Push probe frame immediately so dashboard is not blank for 1s
            try:
                token = self.token_getter()
                if token and jpeg:
                    self._last_good_jpeg = jpeg
                    self._last_good_wh = (w, h)
                    self._enqueue_ws_frame(jpeg, w, h, 0)
                    if self._http_send_frame(token, jpeg, w, h, 0):
                        self._stats["frames_sent"] = 1
                        self._stats["bytes_sent"] = len(jpeg)
                        self._last_activity = time.time()
            except Exception:
                pass

            log(f"[REMOTE-DESKTOP] ▶ Stream started "
                f"(fps={self._fps} q={self._quality} max_w={self._max_width} "
                f"session={self._target_session_id} ws+http)")
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
            "session_id": self._target_session_id,
            "username": self._target_username or "",
            "monitor": self._monitor_index,
            "capture_method": self._capture_method,
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
            # Self-check log (AGENT_REMOTE_KEYBOARD_PROMPT)
            log(
                f"[remote-input] t=input event={event or '?'} "
                f"key={params.get('key', '')!r} text={(params.get('text') or '')[:40]!r} "
                f"session={self._target_session_id}"
            )
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
                ok = self._do_key(
                    str(params.get("key", "") or ""),
                    code=str(params.get("code", "") or ""),
                )
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
                # Honest fail: streaming but no frames for 10s
                if (
                    self._stats.get("frames_sent", 0) <= 0
                    and self._stream_started_at
                    and (time.time() - self._stream_started_at) >= CAPTURE_FAIL_SECONDS
                ):
                    log("[REMOTE-DESKTOP] ✖ CAPTURE_NO_DESKTOP — "
                        f"no frames in {CAPTURE_FAIL_SECONDS:.0f}s (screen still empty)")
                    self.stop(reason="CAPTURE_NO_DESKTOP")
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

        if self._use_user_helper:
            jpeg, w, h = self._grab_via_user_helper()
            if not jpeg or w <= 0 or h <= 0:
                jpeg, w, h = self._grab_jpeg()
        else:
            jpeg, w, h = self._grab_jpeg()
            pid_sid, _ = self._session_ids()
            if (
                (not jpeg or w <= 0 or h <= 0)
                and self._target_session_id
                and (pid_sid is None or int(pid_sid) != int(self._target_session_id))
            ):
                jpeg, w, h = self._grab_via_user_helper()
        if not jpeg or w <= 0 or h <= 0:
            self._stats["frames_failed"] += 1
            return
        # API rejects tiny frames; black frames look like "live" black desktop
        if len(jpeg) < MIN_JPEG_BYTES:
            self._stats["frames_failed"] += 1
            self._stats["black_frames"] += 1
            return
        if jpeg[:2] != b"\xff\xd8" or jpeg[-2:] != b"\xff\xd9":
            self._stats["frames_failed"] += 1
            log("[REMOTE-DESKTOP] Invalid JPEG magic — skip frame")
            return
        if "+black" in (self._capture_method or ""):
            # Disconnected RDP / wrong desktop → re-attach + optional tscon
            self._desktop_attached = False
            self._attach_input_desktop()
            sid = self._target_session_id
            if not self._tscon_attempted:
                if self._try_reconnect_session_to_console(sid):
                    time.sleep(0.35)
                    self._desktop_attached = False
                    self._attach_input_desktop()
                    jpeg2, w2, h2 = self._grab_jpeg()
                    if jpeg2 and "+black" not in (self._capture_method or ""):
                        jpeg, w, h = jpeg2, w2, h2
                    else:
                        self._stats["frames_failed"] += 1
                        self._stats["black_frames"] += 1
                        return
                else:
                    self._stats["frames_failed"] += 1
                    self._stats["black_frames"] += 1
                    return
            else:
                self._stats["frames_failed"] += 1
                self._stats["black_frames"] += 1
                return

        self._seq += 1
        seq = self._seq
        ws_queued = self._enqueue_ws_frame(jpeg, w, h, seq)
        ws_live = bool(self._ws_ok and ws_queued)
        if ws_live:
            self._transport = "websocket"

        need_http = True  # every frame: cloud drains input queue on frame ACK
        http_ok = False
        if need_http:
            http_ok = self._http_send_frame(token, jpeg, w, h, seq)
            if http_ok:
                self._stats["http_fallbacks"] += 1
                if not ws_live:
                    self._transport = "http"

        if ws_live or http_ok:
            self._stats["frames_sent"] += 1
            self._stats["bytes_sent"] += len(jpeg)
            self._last_good_jpeg = jpeg
            self._last_good_wh = (w, h)
            self._last_activity = time.time()
            if self._stats["frames_sent"] == 1 or seq == 1:
                log(f"[REMOTE-DESKTOP] frame ok — {w}x{h} {len(jpeg)}B "
                    f"method={self._capture_method} ws={ws_live} http={http_ok}")
        else:
            self._stats["frames_failed"] += 1

    def _http_send_frame(self, token: str, jpeg: bytes, w: int, h: int, seq: int) -> bool:
        if not self.api_client or not hasattr(self.api_client, "upload_remote_frame"):
            return False
        result = self.api_client.upload_remote_frame(
            token=token,
            jpeg_bytes=jpeg,
            width=w,
            height=h,
            seq=seq,
            fps=self._fps,
        )
        # Backward compatible: older callers returned bool
        if isinstance(result, dict):
            ok = bool(result.get("ok"))
            self._apply_input_batch(result.get("inputs") or [])
            return ok
        return bool(result)

    def _apply_input_batch(self, events) -> None:
        """Apply piggybacked / polled remote input events (frame ACK primary path)."""
        if not events:
            return
        applied = 0
        for ev in events:
            if not isinstance(ev, dict):
                continue
            params = dict(ev)
            # Normalize alternate shapes from cloud
            if not params.get("event"):
                params["event"] = (
                    params.get("type")
                    or params.get("name")
                    or params.get("action")
                    or ""
                )
            # mousedown+mouseup already form a click — never invent an extra click here
            try:
                r = self.apply_input(params)
                if isinstance(r, dict) and r.get("success"):
                    applied += 1
            except Exception as e:
                log(f"[REMOTE-DESKTOP] piggyback input error: {e}")
        if applied:
            self._stats["inputs_piggyback"] = int(self._stats.get("inputs_piggyback") or 0) + applied

    def _grab_jpeg(self):
        """Capture primary screen → resize → JPEG. Avoids Session-0 black frames."""
        try:
            from PIL import Image
        except ImportError:
            log("[REMOTE-DESKTOP] Pillow (PIL) not available")
            return None, 0, 0

        # Ensure this thread is on the interactive input desktop (RDP black-BitBlt fix)
        self._attach_input_desktop()

        img = None
        method = "none"
        # Prefer GDI BitBlt (more reliable than ImageGrab under elevation / DPI)
        try:
            img = self._grab_gdi()
            if img is not None:
                method = "gdi"
        except Exception as e:
            log(f"[REMOTE-DESKTOP] GDI grab failed: {e}")

        if img is None or self._is_mostly_black(img):
            try:
                from PIL import ImageGrab
                w0, h0 = self._get_screen_size()
                candidates = []
                if w0 > 0 and h0 > 0:
                    try:
                        candidates.append(("imagegrab-bbox", ImageGrab.grab(bbox=(0, 0, w0, h0))))
                    except Exception as e:
                        log(f"[REMOTE-DESKTOP] imagegrab-bbox failed: {e}")
                try:
                    candidates.append(("imagegrab", ImageGrab.grab(all_screens=False)))
                except Exception as e:
                    log(f"[REMOTE-DESKTOP] ImageGrab failed: {e}")
                try:
                    candidates.append(("imagegrab-all", ImageGrab.grab(all_screens=True)))
                except Exception as e:
                    log(f"[REMOTE-DESKTOP] imagegrab-all failed: {e}")
                for label, alt in candidates:
                    if alt is None:
                        continue
                    if img is None or self._mean_brightness(alt) > self._mean_brightness(img):
                        img = alt
                        method = label
            except Exception as e:
                log(f"[REMOTE-DESKTOP] ImageGrab variants failed: {e}")

        # Optional mss (if installed) — often works when GDI is black on RDP
        if img is None or self._is_mostly_black(img):
            try:
                alt = self._grab_mss()
                if alt is not None and (
                    img is None
                    or self._mean_brightness(alt) > self._mean_brightness(img)
                ):
                    img = alt
                    method = "mss"
            except Exception as e:
                log(f"[REMOTE-DESKTOP] mss grab failed: {e}")

        if img is None:
            log("[REMOTE-DESKTOP] all in-process capture methods returned None")
            return None, 0, 0

        if self._is_mostly_black(img):
            self._stats["black_frames"] += 1
            now = time.time()
            if now - self._black_warn_ts > 10:
                self._black_warn_ts = now
                sid, csid = self._session_ids()
                state = self._session_connect_state(sid)
                log(f"[REMOTE-DESKTOP] ⚠ Nearly-black frame "
                    f"(mean={self._mean_brightness(img):.1f}) "
                    f"session={sid}/{csid} state={state} method={method}")
            method = method + "+black"

        self._capture_method = method
        self._stats["capture_method"] = method
        self._screen_w, self._screen_h = img.size

        if img.width > self._max_width:
            ratio = self._max_width / float(img.width)
            new_size = (self._max_width, max(1, int(img.height * ratio)))
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

    def _grab_gdi(self):
        """BitBlt full virtual screen → PIL Image (RGB). Always frees GDI objects."""
        import ctypes
        from ctypes import wintypes
        from PIL import Image

        user32 = ctypes.windll.user32
        gdi32 = ctypes.windll.gdi32

        SM_XVIRTUALSCREEN = 76
        SM_YVIRTUALSCREEN = 77
        SM_CXVIRTUALSCREEN = 78
        SM_CYVIRTUALSCREEN = 79
        left = 0
        top = 0
        width = int(user32.GetSystemMetrics(0))
        height = int(user32.GetSystemMetrics(1))
        if width <= 0 or height <= 0:
            left = int(user32.GetSystemMetrics(SM_XVIRTUALSCREEN))
            top = int(user32.GetSystemMetrics(SM_YVIRTUALSCREEN))
            width = int(user32.GetSystemMetrics(SM_CXVIRTUALSCREEN))
            height = int(user32.GetSystemMetrics(SM_CYVIRTUALSCREEN))
        if width <= 0 or height <= 0:
            return None

        hdc = None
        memdc = None
        bmp = None
        old = None
        release_hwnd = 0

        try:
            hdc = user32.GetDC(0)
            if not hdc:
                log("[REMOTE-DESKTOP] GDI GetDC(0) failed")
                return None
            memdc = gdi32.CreateCompatibleDC(hdc)
            bmp = gdi32.CreateCompatibleBitmap(hdc, width, height)
            old = gdi32.SelectObject(memdc, bmp)
            ok = gdi32.BitBlt(memdc, 0, 0, width, height, hdc, left, top, 0x00CC0020)
            if not ok:
                log(f"[REMOTE-DESKTOP] GDI BitBlt failed {width}x{height}")
                # Release primary and try desktop window DC
                if old:
                    gdi32.SelectObject(memdc, old)
                if bmp:
                    gdi32.DeleteObject(bmp)
                if memdc:
                    gdi32.DeleteDC(memdc)
                user32.ReleaseDC(0, hdc)
                hdc = memdc = bmp = old = None

                hwnd = user32.GetDesktopWindow()
                hdc = user32.GetWindowDC(hwnd) if hwnd else None
                if not hdc:
                    return None
                release_hwnd = hwnd
                memdc = gdi32.CreateCompatibleDC(hdc)
                bmp = gdi32.CreateCompatibleBitmap(hdc, width, height)
                old = gdi32.SelectObject(memdc, bmp)
                ok = gdi32.BitBlt(memdc, 0, 0, width, height, hdc, left, top, 0x00CC0020)
                if not ok:
                    return None

            class BITMAPINFOHEADER(ctypes.Structure):
                _fields_ = [
                    ("biSize", wintypes.DWORD),
                    ("biWidth", wintypes.LONG),
                    ("biHeight", wintypes.LONG),
                    ("biPlanes", wintypes.WORD),
                    ("biBitCount", wintypes.WORD),
                    ("biCompression", wintypes.DWORD),
                    ("biSizeImage", wintypes.DWORD),
                    ("biXPelsPerMeter", wintypes.LONG),
                    ("biYPelsPerMeter", wintypes.LONG),
                    ("biClrUsed", wintypes.DWORD),
                    ("biClrImportant", wintypes.DWORD),
                ]

            bi = BITMAPINFOHEADER()
            bi.biSize = ctypes.sizeof(BITMAPINFOHEADER)
            bi.biWidth = width
            bi.biHeight = -height  # top-down
            bi.biPlanes = 1
            bi.biBitCount = 32
            bi.biCompression = 0
            buf_size = width * height * 4
            buf = (ctypes.c_char * buf_size)()
            gdi32.GetDIBits(memdc, bmp, 0, height, buf, ctypes.byref(bi), 0)

            img = Image.frombuffer("RGB", (width, height), bytes(buf), "raw", "BGRX", 0, 1)
            # Avoid double-copy; brightness check on a tiny resize only when probing
            now = time.time()
            if now - getattr(self, "_gdi_log_ts", 0) > 30:
                self._gdi_log_ts = now
                br = self._mean_brightness(img)
                log(f"[REMOTE-DESKTOP] GDI capture {width}x{height} brightness={br:.1f}")
            return img.copy()
        finally:
            try:
                if old is not None and memdc:
                    gdi32.SelectObject(memdc, old)
            except Exception:
                pass
            try:
                if bmp:
                    gdi32.DeleteObject(bmp)
            except Exception:
                pass
            try:
                if memdc:
                    gdi32.DeleteDC(memdc)
            except Exception:
                pass
            try:
                if hdc:
                    user32.ReleaseDC(release_hwnd, hdc)
            except Exception:
                pass

    @staticmethod
    def _mean_brightness(img) -> float:
        try:
            small = img.resize((48, 27)).convert("L")
            data = list(small.getdata())
            return float(sum(data)) / max(1, len(data))
        except Exception:
            return 255.0

    def _is_mostly_black(self, img) -> bool:
        return self._mean_brightness(img) < BLACK_MEAN_THRESHOLD

    def _attach_input_desktop(self) -> bool:
        """Bind capture thread to the interactive input desktop.

        Elevated / tray processes often BitBlt a black screen when not on
        the input desktop (classic RDP remote-desktop black frame cause).
        """
        if self._desktop_attached:
            return True
        try:
            import ctypes
            user32 = ctypes.windll.user32
            kernel32 = ctypes.windll.kernel32
            kernel32.SetLastError(0)
            GENERIC_ALL = 0x10000000
            hdesk = user32.OpenInputDesktop(0, False, GENERIC_ALL)
            if not hdesk:
                err = kernel32.GetLastError()
                log(f"[REMOTE-DESKTOP] OpenInputDesktop failed err={err}")
                return False
            if not user32.SetThreadDesktop(hdesk):
                err = kernel32.GetLastError()
                log(f"[REMOTE-DESKTOP] SetThreadDesktop failed err={err}")
                try:
                    user32.CloseDesktop(hdesk)
                except Exception:
                    pass
                return False
            self._input_desktop = hdesk
            self._desktop_attached = True
            log("[REMOTE-DESKTOP] attached to input desktop")
            return True
        except Exception as e:
            log(f"[REMOTE-DESKTOP] desktop attach error: {e}")
            return False

    def _session_connect_state(self, session_id: Optional[int]) -> str:
        """Return WTS connect state name for logging (Active/Disconnected/…)."""
        if session_id is None:
            return "unknown"
        try:
            import ctypes
            from ctypes import wintypes
            WTSConnectState = 8
            states = {
                0: "Active", 1: "Connected", 2: "ConnectQuery",
                3: "Shadow", 4: "Disconnected", 5: "Idle",
                6: "Listen", 7: "Reset", 8: "Down", 9: "Init",
            }
            wts = ctypes.windll.wtsapi32
            buf = ctypes.c_void_p()
            length = wintypes.DWORD()
            if not wts.WTSQuerySessionInformationW(
                0, int(session_id), WTSConnectState,
                ctypes.byref(buf), ctypes.byref(length),
            ):
                return "query_failed"
            try:
                # Value is a ULONG / DWORD at buf
                val = ctypes.cast(buf, ctypes.POINTER(wintypes.DWORD)).contents.value
                return states.get(int(val), f"state_{val}")
            finally:
                wts.WTSFreeMemory(buf)
        except Exception:
            return "unknown"

    def _try_reconnect_session_to_console(self, session_id: Optional[int]) -> bool:
        """Disconnected RDP sessions don't render → BitBlt is black.

        `tscon <sid> /dest:console` forces the session onto the console so
        the desktop is drawn again (may switch physical console briefly).
        """
        if self._tscon_attempted or session_id is None or session_id <= 0:
            return False
        self._tscon_attempted = True
        try:
            import subprocess
            r = subprocess.run(
                ["tscon", str(int(session_id)), "/dest:console"],
                capture_output=True, text=True, timeout=8,
                creationflags=0x08000000,
            )
            ok = r.returncode == 0
            log(f"[REMOTE-DESKTOP] tscon session={session_id} → console "
                f"rc={r.returncode} out={(r.stdout or r.stderr or '').strip()[:200]}")
            # Reset desktop attach so next grab re-opens input desktop
            self._desktop_attached = False
            return ok
        except Exception as e:
            log(f"[REMOTE-DESKTOP] tscon failed: {e}")
            return False

    def _grab_mss(self):
        """Optional mss capture (if package present)."""
        try:
            import mss
            from PIL import Image
            with mss.mss() as sct:
                # monitors[0]=virtual all; [1]=primary; [2+]=extra
                idx = 1 + max(0, int(self._monitor_index or 0))
                if idx >= len(sct.monitors):
                    idx = 1 if len(sct.monitors) > 1 else 0
                mon = sct.monitors[idx]
                shot = sct.grab(mon)
                return Image.frombytes("RGB", shot.size, shot.bgra, "raw", "BGRX")
        except ImportError:
            return None

    @staticmethod
    def _session_ids() -> Tuple[Optional[int], Optional[int]]:
        try:
            import ctypes
            from ctypes import wintypes
            console = int(ctypes.windll.kernel32.WTSGetActiveConsoleSessionId())
            sid = wintypes.DWORD()
            pid = ctypes.windll.kernel32.GetCurrentProcessId()
            if ctypes.windll.kernel32.ProcessIdToSessionId(pid, ctypes.byref(sid)):
                return int(sid.value), console
            return None, console
        except Exception:
            return None, None

    @staticmethod
    def _enumerate_sessions() -> list:
        """List WTS sessions (Active + Disconnected). Mirrors health active_sessions shape."""
        import subprocess
        out = []
        try:
            r = subprocess.run(
                ["query", "user"],
                capture_output=True, text=True, timeout=8,
                creationflags=0x08000000,
            )
            for line in (r.stdout or "").splitlines()[1:]:
                parts = line.split()
                if len(parts) < 3:
                    continue
                if parts[0].startswith(">"):
                    parts[0] = parts[0][1:]
                username = parts[0]
                session_name = ""
                id_idx = None
                for i, p in enumerate(parts[1:], 1):
                    if p.isdigit():
                        id_idx = i
                        break
                if id_idx is None:
                    continue
                if id_idx > 1:
                    session_name = parts[1]
                session_id = int(parts[id_idx])
                status_raw = parts[id_idx + 1] if len(parts) > id_idx + 1 else ""
                status = {
                    "active": "Active",
                    "disc": "Disconnected",
                    "listen": "Listen",
                }.get(status_raw.lower(), status_raw or "Unknown")
                sn = (session_name or "").lower()
                if sn.startswith("rdp") or "tcp#" in sn:
                    protocol = "RDP"
                elif sn in ("services",):
                    protocol = "Services"
                else:
                    protocol = "Console"
                if session_id <= 0:
                    continue
                out.append({
                    "username": username,
                    "session_id": session_id,
                    "session_name": session_name or protocol,
                    "status": status,
                    "protocol": protocol,
                })
        except Exception as e:
            log(f"[REMOTE-DESKTOP] enumerate sessions failed: {e}")
        return out

    @staticmethod
    def _pick_default_session(sessions: list) -> dict:
        """Console Active → Console → Active RDP → first."""
        if not sessions:
            raise ValueError("no sessions")

        def _rank(s: dict) -> tuple:
            proto = str(s.get("protocol") or "").lower()
            status = str(s.get("status") or "").lower()
            active = status == "active"
            if proto == "console" and active:
                return (0, int(s.get("session_id") or 0))
            if proto == "console":
                return (1, int(s.get("session_id") or 0))
            if proto == "rdp" and active:
                return (2, int(s.get("session_id") or 0))
            if active:
                return (3, int(s.get("session_id") or 0))
            return (4, int(s.get("session_id") or 0))

        return min(sessions, key=_rank)

    def _grab_via_user_helper(self) -> Tuple[Optional[bytes], int, int]:
        """Capture via CreateProcessAsUser into the target WTS session.

        Used when agent runs in Session 0 or a different session than the
        dashboard-selected session_id.
        """
        import os
        import sys
        import tempfile

        sid, csid = self._session_ids()
        target = self._target_session_id
        if not target:
            sessions = self._enumerate_sessions()
            interactive = [
                s for s in sessions
                if int(s.get("session_id") or 0) > 0
                and str(s.get("protocol") or "").lower() != "services"
            ]
            if interactive:
                target = int(self._pick_default_session(interactive)["session_id"])
            else:
                target = csid if csid not in (None, 0, 0xFFFFFFFF) else None
        if not target:
            log("[REMOTE-DESKTOP] No interactive session for helper capture")
            return None, 0, 0

        # Already in the requested session — caller should use in-process grab
        if sid is not None and sid > 0 and int(sid) == int(target):
            log(f"[REMOTE-DESKTOP] skip token-helper — already in target session={sid}")
            return None, 0, 0

        out_path = os.path.join(
            tempfile.gettempdir(), f"honeypot_rd_capture_{os.getpid()}.jpg"
        )
        try:
            if os.path.isfile(out_path):
                os.remove(out_path)
        except OSError:
            pass

        exe = sys.executable
        cmd = f'"{exe}" --rd-capture-once "{out_path}"'

        launched = self._launch_in_session(int(target), cmd)
        if not launched:
            # Session-0 subprocess cannot see another user's desktop — do not fake it
            log(
                f"[REMOTE-DESKTOP] helper launch failed for session={target} "
                "(no Session-0 fallback — would capture black)"
            )
            return None, 0, 0

        deadline = time.time() + PROBE_TIMEOUT_SEC + 2
        while time.time() < deadline:
            if os.path.isfile(out_path) and os.path.getsize(out_path) >= MIN_JPEG_BYTES:
                break
            time.sleep(0.15)
        else:
            log("[REMOTE-DESKTOP] helper capture timed out (no JPEG file)")
            return None, 0, 0

        try:
            with open(out_path, "rb") as fh:
                data = fh.read()
            if len(data) < MIN_JPEG_BYTES or data[:2] != b"\xff\xd8":
                return None, 0, 0
            try:
                from PIL import Image
                import io as _io
                im = Image.open(_io.BytesIO(data))
                w, h = im.size
            except Exception:
                w = self._max_width
                h = int(self._max_width * 9 / 16)
            self._capture_method = "user-helper"
            self._stats["capture_method"] = "user-helper"
            self._use_user_helper = True
            self._screen_w, self._screen_h = w, h
            self._capture_w, self._capture_h = w, h
            log(f"[REMOTE-DESKTOP] helper capture ok — {w}x{h} {len(data)}B session={target}")
            return data, w, h
        except Exception as e:
            log(f"[REMOTE-DESKTOP] helper read failed: {e}")
            return None, 0, 0
        finally:
            try:
                os.remove(out_path)
            except OSError:
                pass

    @staticmethod
    def _find_active_session_id() -> Optional[int]:
        """Legacy helper — prefer Console Active via enumerate."""
        try:
            sessions = RemoteDesktopStreamer._enumerate_sessions()
            interactive = [
                s for s in sessions
                if int(s.get("session_id") or 0) > 0
                and str(s.get("protocol") or "").lower() != "services"
            ]
            if not interactive:
                return None
            return int(RemoteDesktopStreamer._pick_default_session(interactive)["session_id"])
        except Exception:
            return None

    def _launch_in_session(self, session_id: int, command: str) -> bool:
        """CreateProcessAsUser in target WTS session (requires SYSTEM / SeTcbPrivilege)."""
        try:
            import ctypes
            from ctypes import wintypes
            import subprocess

            wts = ctypes.windll.wtsapi32
            adv = ctypes.windll.advapi32
            kernel = ctypes.windll.kernel32

            h_token = wintypes.HANDLE()
            if not wts.WTSQueryUserToken(session_id, ctypes.byref(h_token)):
                err = kernel.GetLastError()
                log(f"[REMOTE-DESKTOP] WTSQueryUserToken({session_id}) failed err={err}")
                return False

            class STARTUPINFO(ctypes.Structure):
                _fields_ = [
                    ("cb", wintypes.DWORD),
                    ("lpReserved", wintypes.LPWSTR),
                    ("lpDesktop", wintypes.LPWSTR),
                    ("lpTitle", wintypes.LPWSTR),
                    ("dwX", wintypes.DWORD),
                    ("dwY", wintypes.DWORD),
                    ("dwXSize", wintypes.DWORD),
                    ("dwYSize", wintypes.DWORD),
                    ("dwXCountChars", wintypes.DWORD),
                    ("dwYCountChars", wintypes.DWORD),
                    ("dwFillAttribute", wintypes.DWORD),
                    ("dwFlags", wintypes.DWORD),
                    ("wShowWindow", wintypes.WORD),
                    ("cbReserved2", wintypes.WORD),
                    ("lpReserved2", ctypes.POINTER(ctypes.c_byte)),
                    ("hStdInput", wintypes.HANDLE),
                    ("hStdOutput", wintypes.HANDLE),
                    ("hStdError", wintypes.HANDLE),
                ]

            class PROCESS_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("hProcess", wintypes.HANDLE),
                    ("hThread", wintypes.HANDLE),
                    ("dwProcessId", wintypes.DWORD),
                    ("dwThreadId", wintypes.DWORD),
                ]

            si = STARTUPINFO()
            si.cb = ctypes.sizeof(STARTUPINFO)
            si.lpDesktop = "winsta0\\default"
            pi = PROCESS_INFORMATION()
            CREATE_NO_WINDOW = 0x08000000
            cmd_buf = ctypes.create_unicode_buffer(command)

            ok = adv.CreateProcessAsUserW(
                h_token,
                None,
                cmd_buf,
                None,
                None,
                False,
                CREATE_NO_WINDOW,
                None,
                None,
                ctypes.byref(si),
                ctypes.byref(pi),
            )
            kernel.CloseHandle(h_token)
            if not ok:
                log(f"[REMOTE-DESKTOP] CreateProcessAsUser failed err={kernel.GetLastError()}")
                return False
            # Wait up to probe timeout
            kernel.WaitForSingleObject(pi.hProcess, int((PROBE_TIMEOUT_SEC + 2) * 1000))
            kernel.CloseHandle(pi.hThread)
            kernel.CloseHandle(pi.hProcess)
            return True
        except Exception as e:
            log(f"[REMOTE-DESKTOP] launch_in_session error: {e}")
            return False

    def _drain_out_q(self):
        try:
            while True:
                self._out_q.get_nowait()
        except queue.Empty:
            pass

    # ── WebSocket transport (single-thread send+recv) ─────────────

    def _ws_loop(self):
        """Dedicated WS thread: create_connection + drain outbound queue + recv input."""
        while self._running and not self._stop.is_set():
            token = self.token_getter()
            if not token or not self.api_client:
                self._stop.wait(WS_RECONNECT_SEC)
                continue
            try:
                import websocket
            except ImportError:
                log("[REMOTE-DESKTOP] websocket-client missing — HTTP only")
                self._transport = "http"
                return

            api_base = getattr(self.api_client, "base_url", "") or ""
            url = _api_to_ws_agent_url(api_base, token)
            log(f"[REMOTE-DESKTOP] WS connecting… {url.split('?')[0]} (Bearer)")

            ws = None
            try:
                verify = True
                try:
                    from client_security_utils import resolve_tls_verify
                    verify = bool(resolve_tls_verify())
                except Exception:
                    pass
                sslopt = None
                if not verify:
                    import ssl
                    sslopt = {"cert_reqs": ssl.CERT_NONE}

                ws_headers = [f"Authorization: Bearer {token}"]
                ws = websocket.create_connection(
                    url,
                    timeout=12,
                    sslopt=sslopt,
                    enable_multithread=True,
                    header=ws_headers,
                )
                self._ws = ws
                self._ws_ok = True
                self._transport = "websocket"
                ws.send(json.dumps({"t": "hello", "role": "agent"}))
                self._enqueue_meta(force=True)
                # Re-push last good frame so viewer is not blank while waiting
                if self._last_good_jpeg and self._last_good_wh[0] > 0:
                    self._enqueue_ws_frame(
                        self._last_good_jpeg,
                        self._last_good_wh[0],
                        self._last_good_wh[1],
                        max(1, self._seq),
                    )
                log("[REMOTE-DESKTOP] WS connected")

                ws.settimeout(0.15)
                while self._running and not self._stop.is_set():
                    # Drain outbound (meta + binary JPEG) on THIS thread
                    self._ws_flush_out(ws)
                    try:
                        msg = ws.recv()
                        if msg is not None:
                            self._on_ws_message(msg)
                    except websocket.WebSocketTimeoutException:
                        pass
                    except Exception as e:
                        log(f"[REMOTE-DESKTOP] WS recv error: {e}")
                        break
            except Exception as e:
                log(f"[REMOTE-DESKTOP] WS connect/loop error: {e}")
            finally:
                self._ws_ok = False
                self._ws = None
                if self._running:
                    self._transport = "http"
                    self._stats["ws_reconnects"] += 1
                if ws is not None:
                    try:
                        ws.close()
                    except Exception:
                        pass
                log("[REMOTE-DESKTOP] WS closed")

            if self._running and not self._stop.is_set():
                self._stop.wait(WS_RECONNECT_SEC)

    def _enqueue_meta(self, force: bool = False):
        if not force and self._seq % META_EVERY_N_FRAMES != 0:
            return
        meta = {
            "t": "meta",
            "width": int(self._capture_w or self._max_width),
            "height": int(self._capture_h or 720),
            "seq": int(self._seq),
            "fps": float(self._fps),
            "session_id": self._target_session_id,
            "username": self._target_username or "",
        }
        self._q_put(("txt", json.dumps(meta)))

    def _enqueue_ws_frame(self, jpeg: bytes, w: int, h: int, seq: int) -> bool:
        """Queue JPEG for agent RD WS. Always enqueue — WS thread flushes when up.

        Previously returned False when !_ws_ok, so the probe frame was lost if
        HTTP also failed and the viewer stayed on "Yayın başlatılıyor…".
        """
        self._capture_w, self._capture_h = w, h
        self._enqueue_meta(force=(seq <= 3 or seq % META_EVERY_N_FRAMES == 0))
        return self._q_put(("bin", jpeg))

    def _q_put(self, item) -> bool:
        try:
            # Drop oldest if full — prefer fresh frames
            if self._out_q.full():
                try:
                    self._out_q.get_nowait()
                except queue.Empty:
                    pass
            self._out_q.put_nowait(item)
            return True
        except Exception:
            return False

    def _ws_flush_out(self, ws) -> None:
        import websocket
        while True:
            try:
                kind, payload = self._out_q.get_nowait()
            except queue.Empty:
                break
            try:
                if kind == "txt":
                    ws.send(payload)
                else:
                    ws.send(payload, opcode=websocket.ABNF.OPCODE_BINARY)
            except Exception as e:
                log(f"[REMOTE-DESKTOP] WS send failed: {e}")
                self._ws_ok = False
                raise

    def _close_ws(self):
        self._ws_ok = False
        ws = self._ws
        self._ws = None
        self._drain_out_q()
        if ws is not None:
            try:
                ws.close()
            except Exception:
                pass

    def _on_ws_message(self, message):
        try:
            if isinstance(message, bytes):
                # Ignore unexpected binary from server
                try:
                    message = message.decode("utf-8", errors="replace")
                except Exception:
                    return
            data = json.loads(message)
        except Exception:
            return
        if not isinstance(data, dict):
            return
        t = (data.get("t") or data.get("type") or "").lower()
        if t in ("input", "remote_input", ""):
            params = dict(data)
            params.pop("t", None)
            params.pop("type", None)
            if "event" in params or "text" in params or "key" in params:
                self.apply_input(params)

    # ── HTTP input poll (backup alongside frame ACK / WS) ─────────

    def _http_input_poll_loop(self):
        """Backup drain via GET /api/remote/inputs (primary = frame ACK inputs[])."""
        while self._running and not self._stop.is_set():
            try:
                token = self.token_getter()
                if token and self.api_client and hasattr(self.api_client, "fetch_remote_inputs"):
                    events = self.api_client.fetch_remote_inputs(token, limit=80) or []
                    if events:
                        self._apply_input_batch(events)
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
        """Inject Unicode string via SendInput KEYEVENTF_UNICODE (layout-independent)."""
        if not text:
            return True
        ok = True
        for ch in text[:500]:
            if not self._send_unicode_char(ch):
                ok = False
            time.sleep(0.003)
        return ok

    @staticmethod
    def _send_input_structs(inputs) -> int:
        """SendInput with correctly sized INPUT union (64-bit safe)."""
        import ctypes
        from ctypes import wintypes

        user32 = ctypes.windll.user32
        ULONG_PTR = ctypes.c_ulonglong if ctypes.sizeof(ctypes.c_void_p) == 8 else ctypes.c_ulong

        class MOUSEINPUT(ctypes.Structure):
            _fields_ = [
                ("dx", wintypes.LONG),
                ("dy", wintypes.LONG),
                ("mouseData", wintypes.DWORD),
                ("dwFlags", wintypes.DWORD),
                ("time", wintypes.DWORD),
                ("dwExtraInfo", ULONG_PTR),
            ]

        class KEYBDINPUT(ctypes.Structure):
            _fields_ = [
                ("wVk", wintypes.WORD),
                ("wScan", wintypes.WORD),
                ("dwFlags", wintypes.DWORD),
                ("time", wintypes.DWORD),
                ("dwExtraInfo", ULONG_PTR),
            ]

        class HARDWAREINPUT(ctypes.Structure):
            _fields_ = [
                ("uMsg", wintypes.DWORD),
                ("wParamL", wintypes.WORD),
                ("wParamH", wintypes.WORD),
            ]

        class INPUT_UNION(ctypes.Union):
            _fields_ = [("mi", MOUSEINPUT), ("ki", KEYBDINPUT), ("hi", HARDWAREINPUT)]

        class INPUT(ctypes.Structure):
            _fields_ = [("type", wintypes.DWORD), ("u", INPUT_UNION)]

        n = len(inputs)
        arr = (INPUT * n)()
        for i, (vk, scan, flags) in enumerate(inputs):
            arr[i].type = 1  # INPUT_KEYBOARD
            arr[i].u.ki = KEYBDINPUT(vk, scan, flags, 0, 0)
        sent = int(user32.SendInput(n, ctypes.byref(arr), ctypes.sizeof(INPUT)))
        return sent

    def _send_unicode_char(self, ch: str) -> bool:
        """KEYEVENTF_UNICODE down+up for one character (ğ, @, €, …)."""
        if not ch:
            return True
        KEYEVENTF_UNICODE = 0x0004
        KEYEVENTF_KEYUP = 0x0002
        code = ord(ch)
        # Surrogate pairs not needed for BMP; for >U+FFFF skip gracefully
        if code > 0xFFFF:
            log(f"[remote-input] skip non-BMP char U+{code:X}")
            return False
        sent = self._send_input_structs([
            (0, code, KEYEVENTF_UNICODE),
            (0, code, KEYEVENTF_UNICODE | KEYEVENTF_KEYUP),
        ])
        return sent == 2

    def _send_vk(self, vk: int, down: bool) -> bool:
        KEYEVENTF_KEYUP = 0x0002
        flags = 0 if down else KEYEVENTF_KEYUP
        sent = self._send_input_structs([(int(vk) & 0xFF, 0, flags)])
        return sent == 1

    def _do_key(self, key: str, code: str = "") -> bool:
        """Apply dashboard key event.

        - Single printable char → Unicode SendInput (never QWERTY scancode map)
        - Named keys / ctrl+c → virtual-key SendInput
        """
        raw = (key or "").strip()
        if not raw and not code:
            return False

        VK_NAMED = {
            "enter": 0x0D, "return": 0x0D,
            "esc": 0x1B, "escape": 0x1B,
            "tab": 0x09,
            "backspace": 0x08,
            "delete": 0x2E, "del": 0x2E,
            "up": 0x26, "down": 0x28, "left": 0x25, "right": 0x27,
            "home": 0x24, "end": 0x23,
            "f5": 0x74, "win": 0x5B, "meta": 0x5B,
            "space": 0x20,
            "pageup": 0x21, "pagedown": 0x22,
            "insert": 0x2D,
        }
        MOD = {
            "ctrl": 0x11, "control": 0x11,
            "alt": 0x12,
            "shift": 0x10,
            "win": 0x5B, "meta": 0x5B,
        }

        key_l = raw.lower()
        if key_l in ("ctrl+alt+del", "ctrl-alt-del", "ctrl+alt+delete", "cad"):
            # Real SAS requires remote_send_sas / SendSAS — not synthetic key events
            log("[remote-input] ctrl+alt+del ignored — use remote_send_sas / SendSAS")
            return False

        # Single character (including Turkish / AltGr results like @ € ğ) → Unicode
        # Do NOT lowercase before inject — preserve İ vs i etc.
        if len(raw) == 1 and key_l not in VK_NAMED and key_l not in MOD:
            return self._send_unicode_char(raw)

        # Space as literal
        if raw == " " or key_l == "space":
            return self._tap_vk(0x20)

        parts = [p for p in key_l.replace("-", "+").split("+") if p]
        if not parts:
            return False

        mods = []
        main = None
        for p in parts:
            if p in MOD:
                mods.append(MOD[p])
            elif p in VK_NAMED:
                main = VK_NAMED[p]
            elif len(p) == 1 and p.isascii() and p.isalnum():
                # ASCII letter/digit shortcut chord (ctrl+c) — VK equals uppercase ord
                main = ord(p.upper())
            elif len(p) == 1:
                # Unusual: modifier + unicode char → type unicode after mods
                main = ("unicode", p)

        if main is None and len(parts) == 1 and parts[0] in MOD:
            main = MOD[parts[0]]
            mods = []

        if main is None:
            # Optional physical code fallback (KeyQ) — still prefer failing honestly
            log(f"[remote-input] unmapped key={raw!r} code={code!r}")
            return False

        for m in mods:
            self._send_vk(m, down=True)
        try:
            if isinstance(main, tuple) and main[0] == "unicode":
                ok = self._send_unicode_char(main[1])
            else:
                ok = self._tap_vk(int(main))
        finally:
            for m in reversed(mods):
                self._send_vk(m, down=False)
        return ok

    def _tap_vk(self, vk: int) -> bool:
        ok1 = self._send_vk(vk, down=True)
        ok2 = self._send_vk(vk, down=False)
        return ok1 and ok2

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


def capture_once_to_file(path: str, max_width: int = DEFAULT_MAX_WIDTH, quality: int = DEFAULT_QUALITY) -> bool:
    """CLI helper: grab desktop JPEG to path (runs in interactive session)."""
    import os
    rd = RemoteDesktopStreamer()
    rd._max_width = max_width
    rd._quality = quality
    jpeg, w, h = rd._grab_jpeg()
    if not jpeg or w <= 0 or h <= 0 or len(jpeg) < MIN_JPEG_BYTES:
        log(f"[REMOTE-DESKTOP] capture_once failed — {w}x{h} bytes={0 if not jpeg else len(jpeg)}")
        return False
    if "+black" in (rd._capture_method or ""):
        log("[REMOTE-DESKTOP] capture_once nearly-black — refuse write")
        return False
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(jpeg)
    log(f"[REMOTE-DESKTOP] capture_once wrote {path} ({w}x{h} {len(jpeg)}B)")
    return True
