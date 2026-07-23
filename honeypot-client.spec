# -*- mode: python ; coding: utf-8 -*-
"""
onedir package — python312.dll lives under $INSTDIR\\_internal (no _MEI unpack).

onefile caused: Failed to load Python DLL ... LoadLibrary: Access denied
(AV / execute-from-TEMP / concurrent extract). onedir avoids runtime extract.
"""
import os, importlib

# rd6 WebRTC is opt-in because aiortc/av add native binaries and substantial
# size. Build with HONEYPOT_WEBRTC=1 after installing requirements-webrtc.txt.
# The normal production build excludes them and advertises JPEG fallback only.
_webrtc_hidden = []
_webrtc_enabled = os.environ.get('HONEYPOT_WEBRTC') == '1'
_webrtc_excludes = [] if _webrtc_enabled else ['aiortc', 'av', 'dxcam']
if _webrtc_enabled:
    try:
        from PyInstaller.utils.hooks import collect_submodules
        _webrtc_hidden = (
            collect_submodules('aiortc')
            + collect_submodules('av')
            + collect_submodules('dxcam')
        )
    except Exception:
        _webrtc_hidden = []

# CustomTkinter veri dosyalarını bul
ctk_path = os.path.dirname(importlib.import_module('customtkinter').__file__)

# Bundle certifi CA file for TLS
try:
    import certifi as _certifi
    _cacert = _certifi.where()
    _certifi_datas = [(_cacert, 'certifi')] if _cacert and os.path.isfile(_cacert) else []
except Exception:
    _certifi_datas = []

a = Analysis(
    ['client.py'],
    pathex=[],
    binaries=[],
    datas=[('certs/*.ico', 'certs'), ('certs/*.png', 'certs'), ('certs/*.bmp', 'certs'), ('client_config.json', '.'), ('client_lang.json', '.'), ('client_memory_restart.py', '.'), ('client_daemon_ipc.py', '.'), ('client_lifecycle.py', '.'), ('client_update_ui.py', '.'), ('client_winproc.py', '.'), ('client_remote_session.py', '.'), ('memory_restart.ps1', '.'), ('scripts/update-and-install.ps1', 'scripts'), ('client_presence.py', '.'), ('client_power_presence.py', '.'), ('client_process_priority.py', '.'), ('client_resources.py', '.'), ('client_control_ws.py', '.'), ('client_gui.py', '.'), ('client_gui_lock.py', '.'), ('client_uninstall_gate.py', '.'), ('client_logon_challenge.py', '.'), ('client_eventlog.py', '.'), ('client_threat_engine.py', '.'), ('client_alerts.py', '.'), ('client_auto_response.py', '.'), ('client_remote_commands.py', '.'), ('client_silent_hours.py', '.'), ('client_ransomware_shield.py', '.'), ('client_system_health.py', '.'), ('client_self_protection.py', '.'), ('client_performance.py', '.'), ('client_guardian_service.py', '.'), ('client_operator_stop.py', '.'), ('client_tamper.py', '.'), ('client_autologon.py', '.'), ('client_network_guard.py', '.'), ('client_server_management.py', '.'), (os.path.join(ctk_path, 'assets'), 'customtkinter/assets')] + _certifi_datas,
    hiddenimports=['client_memory_restart', 'client_presence', 'client_power_presence', 'client_process_priority', 'client_resources', 'client_control_ws', 'client_daemon_ipc', 'client_lifecycle', 'client_update_ui', 'client_winproc', 'client_remote_session', 'client_rdp_nla', 'client_honeypots', 'client_service_manager', 'client_gui', 'client_gui_lock', 'client_uninstall_gate', 'client_logon_challenge', 'client_eventlog', 'client_threat_engine', 'client_alerts', 'client_auto_response', 'client_remote_commands', 'client_remote_desktop', 'client_rd_adaptive', 'client_rd_media', 'client_rd_session_helper', 'client_server_management', 'client_silent_hours', 'client_ransomware_shield', 'client_system_health', 'client_self_protection', 'client_performance', 'client_guardian_service', 'client_operator_stop', 'client_tamper', 'client_autologon', 'client_network_guard', 'client_integrity', 'client_command_envelope', 'client_resilience_p1', 'client_offline_queue', 'client_identity_correlation', 'client_device_identity', 'client_operator_keys', 'customtkinter', 'darkdetect', 'paramiko', 'psutil', 'websocket', 'websocket.websocket', 'win32event', 'win32api', 'winerror', 'win32security', 'ntsecuritycon', 'win32serviceutil', 'win32service', 'servicemanager', 'certifi', 'cryptography'] + _webrtc_hidden,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=['rthook_ssl_certs.py'],
    excludes=_webrtc_excludes,
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='honeypot-client',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['certs\\honeypot_256.ico'],
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name='honeypot-client',
)
