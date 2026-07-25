import zipfile, re, sys
patterns = [b'GET_SIGNATURES', b'getPackageInfo', b'signatures', b'SignatureVerifier', b'tamper', b'PMSigner', b'PackageUtils', b'isDebuggable', b'checkSignature', b'verifySignature', b'PackageManager.SIGNATURE', b'SignatureCheck']
matches = {}
with zipfile.ZipFile(r'C:\Users\kevin\monografia\dast_lab\out\yoosee_merged.apk') as z:
    for name in z.namelist():
        if name.endswith('.dex'):
            data = z.read(name)
            for p in patterns:
                rx = re.compile(re.escape(p), re.IGNORECASE)
                for m in rx.finditer(data):
                    matches.setdefault(p.decode(), []).append((name, m.start()))
print('=== Anti-tampering scan (ocurrencias por patron) ===')
for p in sorted(matches.keys()):
    files = set(f for f,_ in matches[p])
    print(f'{p:30s} -> {len(matches[p]):3d} hits en {len(files)} archivos: {sorted(files)[:3]}')
print()
print('Total patrones detectados:', len(matches))
