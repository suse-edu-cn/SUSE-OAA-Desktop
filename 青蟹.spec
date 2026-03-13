# -*- mode: python ; coding: utf-8 -*-

a = Analysis(
    ['OAA.py'],
    pathex=[],
    binaries=[],
    datas=[('logo.png', '.')],  # 依然保持 logo.png 的包含关系
    hiddenimports=[],
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
    [],  # <--- 这里由原来的 a.binaries, a.datas 改为空列表 []
    exclude_binaries=True, # <--- 新增这一行，表示二进制文件不打入 exe 内部
    name='青蟹',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['青蟹.ico'],
)

# <--- 新增 COLLECT 结构，它负责把所有文件收集到一个文件夹里
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='青蟹', # 这里是生成的文件夹名称
)