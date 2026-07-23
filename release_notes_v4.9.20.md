# Cloud Honeypot Client v4.9.20

## Remote Desktop — WebRTC smoothness (contract 1.4.20)

Closer to Chrome Remote Desktop fluidity on the agent side:

- **Raw RGB → H.264** on the WebRTC path (no JPEG staging / double-encode)
- **HW encode** when FFmpeg exposes `h264_nvenc` / `h264_qsv` / `h264_amf`; else `libx264` ultrafast + zerolatency
- **Idle skip** when the desktop frame is unchanged
- **Input:** move budget 120/s; critical ACK ≤80 ms; data-channel drain preference
- **Adaptive:** JPEG quality/fps churn does not thrash the session helper while WebRTC is connected
- Telemetry: `media.encoder`, `effective_capture_fps`, `target_bitrate_bps`

Cloud/viewer must-do: `honeypot-contract` **1.4.20** → `cloud/REMOTE_DESKTOP_SMOOTHNESS.md` (C-RD-1…8).
