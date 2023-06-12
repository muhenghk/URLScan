# -*- mode: python ; coding: utf-8 -*-


block_cipher = None


a = Analysis(
   ['start.py',
'D:\\desktop\\URLScan\\core\\__init__.py',
'D:\\desktop\\URLScan\\core\\common.py',
'D:\\desktop\\URLScan\\core\\crawl.py',
'D:\\desktop\\URLScan\\scan\\__init__.py',
'D:\\desktop\\URLScan\\scan\\domain_scan.py',
'D:\\desktop\\URLScan\\scan\\ip_scan.py',
'D:\\desktop\\URLScan\\scan\\ping_scan.py',
'D:\\desktop\\URLScan\\scan\\port_scan.py',
'D:\\desktop\\URLScan\\scan\\whois_scan.py',
'D:\\desktop\\URLScan\\webscan\\__init__.py',
'D:\\desktop\\URLScan\\webscan\\SQL_inject.py',
'D:\\desktop\\URLScan\\webscan\\Webshell_check.py',
'D:\\desktop\\URLScan\\webscan\\XSS_check.py'],
    pathex=['D:\\desktop\\URLScan','D:\\desktop\\URLScan\\core'],
    binaries=[],
    datas=[('D:\\desktop\\URLScan\\data','data')],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='start',
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
)
coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='start',
)
