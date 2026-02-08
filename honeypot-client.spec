# -*- mode: python ; coding: utf-8 -*-
import os, importlib

# CustomTkinter veri dosyalarını bul
ctk_path = os.path.dirname(importlib.import_module('customtkinter').__file__)

a = Analysis(
    ['client.py'],
    pathex=[],
    binaries=[],
    datas=[('certs/*.ico', 'certs'), ('certs/*.png', 'certs'), ('certs/*.bmp', 'certs'), ('client_config.json', '.'), ('client_lang.json', '.'), ('client_memory_restart.py', '.'), ('memory_restart.ps1', '.'), ('client_gui.py', '.'), (os.path.join(ctk_path, 'assets'), 'customtkinter/assets')],
    hiddenimports=['client_memory_restart', 'client_honeypots', 'client_service_manager', 'client_gui', 'customtkinter', 'darkdetect', 'paramiko', 'psutil', 'win32event', 'win32api', 'winerror'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
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
