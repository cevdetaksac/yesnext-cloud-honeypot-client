# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['client.py'],
    pathex=[],
    binaries=[(r'C:\Windows\System32\win32service.pyd', '.')],
    datas=[('service_wrapper.py', '.'), ('client_config.json', '.'), ('client_lang.json', '.')],
    hiddenimports=['unicodedata', 'win32timezone', 'win32api', 'win32serviceutil', 'win32service', 'win32event', 'servicemanager', 'winerror', 'pywintypes', 'pythoncom'],
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
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    uac_admin=True,
    icon='certs/honeypot.ico',
)
