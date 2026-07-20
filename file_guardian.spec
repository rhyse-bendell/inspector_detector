# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_all, collect_data_files, collect_submodules

hiddenimports = []
datas = [('sandbox/Start-FileGuardianInSandbox.ps1', '.')]
binaries = []
for package in ('pypdf', 'PIL', 'oletools', 'olefile', 'defusedxml'):
    package_datas, package_binaries, package_hiddenimports = collect_all(package)
    datas += package_datas
    binaries += package_binaries
    hiddenimports += package_hiddenimports
hiddenimports += collect_submodules('tkinter')
hiddenimports += ['PIL.Image', 'PIL.ExifTags', 'oletools.olevba', 'defusedxml.ElementTree']

a = Analysis(['app.py'], pathex=[], binaries=binaries, datas=datas, hiddenimports=hiddenimports, hookspath=[], hooksconfig={}, runtime_hooks=[], excludes=[], noarchive=False, optimize=0)
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, [], exclude_binaries=True, name='FileGuardian', console=True)
coll = COLLECT(exe, a.binaries, a.datas, strip=False, upx=True, upx_exclude=[], name='FileGuardian')
