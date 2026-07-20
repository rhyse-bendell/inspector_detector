# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_submodules
hiddenimports = collect_submodules('pypdf') + collect_submodules('PIL') + collect_submodules('oletools') + collect_submodules('defusedxml') + ['tkinter','tkinter.ttk','tkinter.filedialog','tkinter.messagebox']
a = Analysis(['app.py'], pathex=[], binaries=[], datas=[], hiddenimports=hiddenimports, hookspath=[], hooksconfig={}, runtime_hooks=[], excludes=[], noarchive=False)
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, [], exclude_binaries=True, name='FileGuardian', console=False)
coll = COLLECT(exe, a.binaries, a.datas, strip=False, upx=True, upx_exclude=[], name='FileGuardian')
