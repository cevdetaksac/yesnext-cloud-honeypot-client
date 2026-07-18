# -*- mode: python ; coding: utf-8 -*-
import os, importlib

# CustomTkinter veri dosyalarını bul
ctk_path = os.path.dirname(importlib.import_module('customtkinter').__file__)

# Bundle certifi CA file into onefile so TLS works after _MEI temp cleanup
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
    datas=[('certs/*.ico', 'certs'), ('certs/*.png', 'certs'), ('certs/*.bmp', 'certs'), ('client_config.json', '.'), ('client_lang.json', '.'), ('client_memory_restart.py', '.'), ('client_daemon_ipc.py', '.'), ('client_lifecycle.py', '.'), ('memory_restart.ps1', '.'), ('scripts/kill-honeypot.ps1', 'scripts'), ('scripts/update-and-install.ps1', 'scripts'), ('client_gui.py', '.'), ('client_gui_lock.py', '.'), ('client_logon_challenge.py', '.'), ('client_eventlog.py', '.'), ('client_threat_engine.py', '.'), ('client_alerts.py', '.'), ('client_auto_response.py', '.'), ('client_remote_commands.py', '.'), ('client_silent_hours.py', '.'), ('client_ransomware_shield.py', '.'), ('client_system_health.py', '.'), ('client_self_protection.py', '.'), ('client_performance.py', '.'), (os.path.join(ctk_path, 'assets'), 'customtkinter/assets')] + _certifi_datas,
    hiddenimports=['client_memory_restart', 'client_daemon_ipc', 'client_lifecycle', 'client_honeypots', 'client_service_manager', 'client_gui', 'client_gui_lock', 'client_logon_challenge', 'client_eventlog', 'client_threat_engine', 'client_alerts', 'client_auto_response', 'client_remote_commands', 'client_remote_desktop', 'client_silent_hours', 'client_ransomware_shield', 'client_system_health', 'client_self_protection', 'client_performance', 'customtkinter', 'darkdetect', 'paramiko', 'psutil', 'websocket', 'websocket.websocket', 'win32event', 'win32api', 'winerror', 'win32security', 'ntsecuritycon', 'certifi'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=['rthook_ssl_certs.py'],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='honeypot-client',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,  # UPX disabled to prevent python312.dll issues
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['certs\\honeypot_256.ico'],
)
