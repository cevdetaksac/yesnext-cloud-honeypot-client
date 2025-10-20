# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['client.py'],
    pathex=[],
    binaries=[],
    datas=[('certs/*.ico', 'certs'), ('certs/*.png', 'certs'), ('certs/*.bmp', 'certs'), ('client_config.json', '.'), ('client_lang.json', '.'), ('client_auto_restart.py', '.'), ('client_memory_optimizer.py', '.'), ('client_emergency_patch.py', '.')],
    hiddenimports=['client_auto_restart', 'client_memory_optimizer', 'client_emergency_patch', 'psutil', 'win32event', 'win32api', 'winerror'],
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
