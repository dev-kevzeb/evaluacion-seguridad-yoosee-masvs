"""Reflow Tabla 2.5 y Tabla 2.6 con H-01..H-11"""
import re

path = r'C:\Users\kevin\monografia\monografia-v5-capii-capiii.md'
with open(path, 'r', encoding='utf-8') as f:
    content = f.read()

# Reemplazar Tabla 2.5 (la nueva con 11 hallazgos)
old_t25 = [
    '**Tabla 2.5.** Hallazgos consolidados con su valoraci' + chr(0xF3) + 'n CVSS v3.1.',
    '',
    '| ID Hallazgo | Lineamiento MASTG | Resultado | Activos | CVSS v3.1 | Severidad |',
    '|---|---|---|---|---|---|',
    '| H-01 | MASTG-TEST-0212 (hardcoded keys) | NO CUMPLE | ACT-01, ACT-04 | 9.9 | Cr' + chr(0xED) + 'tica |',
    '| H-02 | MASTG-TEST-0235 (cleartext) | NO CUMPLE | ACT-01, ACT-02, ACT-03 | 7.4 | Alta |',
    '| H-03 | MASTG-TEST-0208 (keysize cert) | NO CUMPLE | ACT-04 | 8.1 | Alta-Cr' + chr(0xED) + 'tica |',
    '| H-04 | MASTG-TEST-0221/0232/0350 (algoritmos/modos) | NO CUMPLE | ACT-01, ACT-04 | 7.2 | Alta |',
    '| H-05 | MASTG-TEST-0287 (SharedPrefs sin cifrar) | NO CUMPLE | ACT-01, ACT-02, ACT-04 | 7.2 | Alta |',
    '| H-06 | MASTG-TEST-0304 (SQLite sin cifrar) | NO CUMPLE | ACT-02, ACT-04 | 7.2 | Alta |',
    '| H-07 | MASTG-TEST-0207 (sandbox sin cifrado) | NO CUMPLE | ACT-01, ACT-02, ACT-04, ACT-05 | 6.2 | Media-Alta |',
    '| H-08 | MASTG-TEST-0200/0201/0202 (almacen externo) | CUMPLE PARCIAL | ACT-05 | 6.5 | Media-Alta |',
    '| H-09 | MASTG-TEST-0231 (logs) | [PENDIENTE] | ACT-01, ACT-02, ACT-04 | (--|--|',
    '| H-10 | MASTG-TEST-0204/0205 (PRNG) | [PENDIENTE] | ACT-04 | --|--|',
    '| H-11 | MASTG-TEST-0312 (provider) | [PENDIENTE] | ACT-04 | --|--|',
    '| H-12 | MASTG-TEST-0307/0308 (prop' + chr(0xF3) + 'sito clave) | [PENDIENTE] | ACT-04 | --|--|',
    '| H-13 | MASTG-TEST-0233 (URLs http) | [PENDIENTE] | ACT-04 | --|--|',
    '| H-14 | MASTG-TEST-0285/0286 (CA user/minSdk) | [PENDIENTE] | ACT-01, ACT-02, ACT-03 | --|--|',
    '| H-15 | MASTG-TEST-0282/0283/0284 (TrustManager) | [PENDIENTE] | ACT-01, ACT-03 | --|--|',
    '| H-16 | MASTG-TEST-0217/0218 (TLS) | [PENDIENTE] | ACT-01, ACT-02, ACT-03 | --|--|',
    '| H-17 | MASTG-TEST-0242/0244 (pinning) | [PENDIENTE] | ACT-03, ACT-04 | --|--|',
    '| H-18 | MASTG-TEST-0295 (GMS provider) | [PENDIENTE] | ACT-03, ACT-04 | --|--|',
    '| H-19 | MASTG-TEST-0262 (backup) | CUMPLE | ACT-01, ACT-02, ACT-04 | 0.0 | Informativa |',
]
old_t25_str = '\n'.join(old_t25)

# Nueva Tabla 2.5
new_t25 = [
    '**Tabla 2.5.** Hallazgos consolidados con su valoraci' + chr(0xF3) + 'n CVSS v3.1.',
    '',
    '| ID | Lineamiento | MASTG-TEST IDs | Resultado | Activos cubiertos | CVSS v3.1 | Severidad |',
    '|---|---|---|---|---|---|---|',
    '| H-01 | L01 Almacenamiento en sandbox sin cifrado (SharedPrefs + SQLite) | `0287` + `0304` | NO CUMPLE | ACT-01, ACT-02, ACT-04 | 7.4 | Alta |',
    '| H-02 | L01 (subsidiario) Cifrado en sandbox L2 | `0207` | NO CUMPLE | ACT-01, ACT-02, ACT-04, ACT-05 | 6.2 | Media-Alta |',
    '| H-03 | L02 Fuga a almacenamiento externo | `0202` + `0200` | CUMPLE PARCIAL | ACT-04, ACT-05 | 6.5 | Media-Alta |',
    '| H-04 | L04 Fuga de tokens en logs | `0231` | [PENDIENTE DAST] | ACT-01, ACT-02, ACT-04 | -- | -- |',
    '| H-05 | L05 Secretos hardcodeados en el binario | `0212` | NO CUMPLE | ACT-01, ACT-04 | 9.9 | Cr' + chr(0xED) + 'tica |',
    '| H-06 | L06 Tama' + chr(0xF1) + 'o de clave de firma obsoleto | `0208` | NO CUMPLE | ACT-04 | 8.1 | Alta-Cr' + chr(0xED) + 'tica |',
    '| H-07 | L07 Algoritmos y modos criptogr' + chr(0xE1) + 'ficos rotos | `0221` + `0232` + `0350` | NO CUMPLE | ACT-01, ACT-04 | 7.2 | Alta |',
    '| H-08 | L08 Tr' + chr(0xE1) + 'fico en claro habilitado | `0235` + `0236` | NO CUMPLE | ACT-01, ACT-02, ACT-03 | 7.4 | Alta |',
    '| H-09 | L09 URLs HTTP hardcoded en el binario | `0233` | [PENDIENTE DAST] | ACT-04 | -- | -- |',
    '| H-10 | L10 Protocolos TLS inseguros | `0217` + `0218` | [PENDIENTE DAST] | ACT-01, ACT-02, ACT-03 | -- | -- |',
    '| H-11 | L11 Validaci' + chr(0xF3) + 'n de cadena TLS y cert pinning | `0282`+`0283`+`0284`+`0285`+`0286`+`0242`+`0244` | [PENDIENTE DAST] | ACT-01, ACT-02, ACT-03, ACT-04 | -- | -- |',
    '| H-12 | L03 Configuraci' + chr(0xF3) + 'n de backups (referencia informativa) | `0262` + `0216` | CUMPLE | ACT-01, ACT-02, ACT-04 | 0.0 | Informativa |',
    '',
    '**Notas:**',
    '',
    '- **L03 (Backups, H-12)** no es un hallazgo de incumplimiento sino una validaci' + chr(0xF3) + 'n de cumplimiento: `allowBackup="false"` bloquea `adb backup`, retornando un archivo de 47 bytes sin contenido del sandbox. Se incluye en la tabla para evidenciar que el lineamiento fue evaluado.',
    '- **Los 7 IDs MASTG-TEST descartados** (0201, 0204, 0205, 0295, 0307, 0308, 0312) no aparecen como hallazgos individuales en esta tabla. Su justificaci' + chr(0xF3) + 'n se documenta en \u00a72.4.1 y se enumeran como trabajo futuro en \u00a72.7.',
    '- **Hallazgos marcados `[PENDIENTE DAST]`** requieren la ejecuci' + chr(0xF3) + 'n de un procedimiento DAST documentado en la subsecci' + chr(0xF3) + 'n \u00a72.5.x correspondiente. Su captura se completa en la sesi' + chr(0xF3) + 'n extendida posterior.',
]
new_t25_str = '\n'.join(new_t25)

assert old_t25_str in content, 'old_t25 not found'
content = content.replace(old_t25_str, new_t25_str)
print('Tabla 2.5 actualizada')

# Reemplazar Tabla 2.6
old_t26 = [
    '**Tabla 2.6.** Tabla consolidada de cumplimiento MASVS por dimensi' + chr(0xF3) + 'n.',
    '',
    '| Dimensi' + chr(0xF3) + 'n MASVS | Pruebas ejecutadas | Cumplen | No cumplen | Pendientes DAST | % Cumplimiento (parcial) |',
    '|---|---|---|---|---|---|',
    '| MASVS-STORAGE | 6 | 1 (0262) | 3 (0207, 0287, 0304) | 1 (0231), 1 (0200/0201) | 17 % confirmado |',
    '| MASVS-CRYPTO | 6 | 0 | 3 (0208, 0212, 0221/0232) | 3 (0204/0205, 0312, 0307/0308) | 0 % confirmado |',
    '| MASVS-NETWORK | 7 | 0 (endpoints reputaci' + chr(0xF3) + 'n OK) | 1 (0235) | 6 (0233, 0282-0286, 0217, 0218, 0242, 0244, 0295) | 0 % confirmado |',
    '| **Totales** | **19** | **1** | **7** | **10** | **5 %** confirmado |',
    '',
    'La baja tasa de cumplimiento confirmado (5 %) y el alto n' + chr(0xFA) + 'mero de hallazgos cr' + chr(0xED) + 'ticos-alto ya detectados por SAST evidencian una postura de seguridad d' + chr(0xE9) + 'bil del binario que ser' + chr(0xE1) + ' reforzada con la propuesta de mitigaci' + chr(0xF3) + 'n del Cap' + chr(0xED) + 'tulo III, tras completar la ejecuci' + chr(0xF3) + 'n DAST pendiente.',
]
old_t26_str = '\n'.join(old_t26)

new_t26 = [
    '**Tabla 2.6.** Tabla consolidada de cumplimiento MASVS por dimensi' + chr(0xF3) + 'n, post-reflow de 11 lineamientos.',
    '',
    '| Dimensi' + chr(0xF3) + 'n MASVS | Lineamientos (L) | Cumplen | No cumplen | Pendientes DAST | Tasa de cumplimiento confirmado |',
    '|---|---|---|---|---|---|',
    '| MASVS-STORAGE (L01' + chr(0x2013) + 'L04) | 4 | 1 (L03 backups) | 3 (L01' + chr(0xD7) + '2 + L02) | 1 (L04 logs) | 17 % confirmado |',
    '| MASVS-CRYPTO (L05' + chr(0x2013) + 'L07) | 3 | 0 | 3 (L05 + L06 + L07) | 0 | 0 % confirmado (100 % No CUMPLE) |',
    '| MASVS-NETWORK (L08' + chr(0x2013) + 'L11) | 4 | 0 (1 parcial: endpoints reputaci' + chr(0xF3) + 'n OK) | 1 (L08) | 3 (L09 + L10 + L11) | 0 % confirmado |',
    '| **Totales** | **11** | **1** | **7** | **4** | **9 % confirmado** |',
    '',
    'La baja tasa de cumplimiento confirmado (9 %) y la concentraci' + chr(0xF3) + 'n de hallazgos cr' + chr(0xED) + 'ticos-altos en la dimensi' + chr(0xF3) + 'n CRYPTO evidencian una postura de seguridad d' + chr(0xE9) + 'bil del binario, principalmente debida a la fragmentaci' + chr(0xF3) + 'n criptogr' + chr(0xE1) + 'fica, el hardcoding de secretos y la obsolescencia del certificado de firma. Estos resultados fundamentan la propuesta de mitigaci' + chr(0xF3) + 'n del Cap' + chr(0xED) + 'tulo III.',
]
new_t26_str = '\n'.join(new_t26)

assert old_t26_str in content, 'old_t26 not found'
content = content.replace(old_t26_str, new_t26_str)
print('Tabla 2.6 actualizada')

with open(path, 'w', encoding='utf-8', newline='') as f:
    f.write(content)
print('OK guardado')
