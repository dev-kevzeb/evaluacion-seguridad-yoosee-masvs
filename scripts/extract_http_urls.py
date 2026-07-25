#!/usr/bin/env python3
# MASTG-TEST-0233 - Extractor de URLs http:// hardcodeadas en el APK
# Uso: python extract_http_urls.py base.apk
import sys
import re

if len(sys.argv) < 2:
    print("Uso: python extract_http_urls.py <ruta_al_apk>")
    sys.exit(1)

apk_path = sys.argv[1]
print(f"[*] Analizando {apk_path} ...")

try:
    with open(apk_path, "rb") as f:
        data = f.read()
except FileNotFoundError:
    print(f"[!] No se encuentra el archivo: {apk_path}")
    sys.exit(1)

# Regex: http:// seguido de chars validos en una URL (hasta espacio, comilla, <, >, etc.)
# Captura URLs de 6+ chars para evitar falsos positivos tipo "http://x" sueltos
pattern = re.compile(rb"http://[a-zA-Z0-9.\-_/:%?&=#~+]{4,400}")
raw_matches = pattern.findall(data)

# Limpiar y deduplicar
urls = set()
for m in raw_matches:
    try:
        u = m.decode("utf-8", errors="ignore").rstrip(".,;:)")
        # Filtrar falsos positivos comunes en binarios (rutas locales, etc.)
        if "schemas.android.com" in u or "www.w3.org" in u:
            continue
        if "xmlns" in u.lower():
            continue
        urls.add(u)
    except Exception:
        pass

# Ordenar
urls = sorted(urls)

print(f"\n[+] {len(urls)} URLs unicas con esquema http:// encontradas\n")
for i, u in enumerate(urls, 1):
    print(f"  {i:3d}. {u}")

# Agrupar por dominio
print(f"\n[+] Agrupadas por dominio:")
from collections import Counter
domains = Counter()
for u in urls:
    m = re.match(r"http://([^/]+)/?", u)
    if m:
        domains[m.group(1)] += 1

for d, c in sorted(domains.items(), key=lambda x: -x[1]):
    print(f"  {c:3d}x  {d}")
