"""Reemplazar §2.7 Conclusiones para mencionar 11 hallazgos"""
import re

path = r'C:\Users\kevin\monografia\monografia-v5-capii-capiii.md'
with open(path, 'r', encoding='utf-8') as f:
    content = f.read()

old_27 = '''## 2.7. Conclusiones del Cap\u00edtulo

El diagn\u00f3stico client-side de la aplicaci\u00f3n Yoosee v6.44.1 revela una postura de seguridad d\u00e9bil en sus tres dimensiones evaluadas. Los hallazgos cr\u00edticos detectados mediante an\u00e1lisis est\u00e1tico \u00adsecretos hardcodeados (243, incluyendo llaves de Google/Facebook/Firebase), firma del APK con SHA1withRSA de 1024 bits, fragmentaci\u00f3n criptogr\u00e1fica con MD5 y rutinas AES custom, ausencia de cifrado en SharedPreferences y SQLite, y habilitaci\u00f3n de tr\u00e1fico en claro (`usesCleartextTraffic=true`)\u00ad fundamentan la necesidad urgente de una propuesta de mitigaci\u00f3n t\u00e9cnica.

La verificaci\u00f3n SAST ya confirma el incumplimiento de 7 lineamientos MASTG (3 en STORAGE, 3 en CRYPTO, 1 en NETWORK) frente a only 1 lineamiento cumplido (backup disabled). Los 10 lineamientos restantes requieren confirmaci\u00f3n DAST mediante Frida, Objection y Burp Suite, cuyos procedimientos quedaron documentados en este cap\u00edtulo y cuyo Hallazgo se completar\u00e1 tras la ejecuci\u00f3n en laboratorio. La matriz de riesgo post-diagn\u00f3stico ubica el hallazgo H-01 (hardcoded keys) en la celda cr\u00edtica/cr\u00edtica del mapa de calor, lo cual fundamenta la priorizaci\u00f3n de mitigaci\u00f3n en el Cap\u00edtulo III.

Estos resultados fundamentan la necesidad de la propuesta de mitigaci\u00f3n t\u00e9cnica que se desarrolla en el Cap\u00edtulo III, donde cada lineamiento incumplido recibir\u00e1 su recomendaci\u00f3n espec\u00edfica de remediaci\u00f3n.'''

# Construyo old_27 usando concatenación con chars para evitar el problema de escape
old_27 = '## 2.7. Conclusiones del Cap' + chr(0xED) + 'tulo\n\n'
# Necesito encontrar la seccion actual - busco desde ## 2.7 hasta ## (fin de cap o siguiente seccion)
import re
m = re.search(r'^## 2\.7\..*?(?=^---|\Z)', content, re.M | re.S)
assert m, 'No encontrado ## 2.7'
old_27_text = m.group(0)

# Nueva conclusion
new_27 = '## 2.7. Conclusiones del Cap' + chr(0xED) + 'tulo\n\n'
new_27 += 'El diagn' + chr(0xF3) + 'stico client-side de la aplicaci' + chr(0xF3) + 'n Yoosee v6.44.1 sobre el dispositivo f' + chr(0xED) + 'sico Poco X5 5G (Android 14) revela una postura de seguridad d' + chr(0xE9) + 'bil en sus tres dimensiones evaluadas. De los 11 lineamientos MASTG seleccionados, **7 fueron ejecutados con resultado documentado** y **4 quedaron con Hallazgo DAST pendiente** de captura en una sesi' + chr(0xF3) + 'n extendida posterior. La verificaci' + chr(0xF3) + 'n SAST y DAST ya confirma el incumplimiento de **7 lineamientos NO CUMPLE** (H-01 a H-08) y el cumplimiento de **1 lineamiento de validaci' + chr(0xF3) + 'n informativa** (H-12 backups). Los 4 hallazgos marcados como `[PENDIENTE DAST]` (H-04 logs, H-09 URLs HTTP, H-10 TLS protocols, H-11 cert pinning/TrustManager) tienen su procedimiento de captura DAST documentado paso a paso en sus respectivas subsecciones \u00a72.5.4, \u00a72.5.9, \u00a72.5.10 y \u00a72.5.11, y la metodolog' + chr(0xED) + 'a es repetible y verificable por un tercero.\n\n'
new_27 += '**Hallazgos cr' + chr(0xED) + 'ticos identificados:**\n\n'
new_27 += '- **H-05 (Secretos hardcodeados, CVSS 9.9, Cr' + chr(0xED) + 'tica):** 243 secretos en texto claro dentro del binario, incluyendo `google_api_key`, `facebook_token`, `firebase_database_url` y bloques ASN.1 DER con material criptogr' + chr(0xE1) + 'fico embebido. Compromete la infraestructura cloud de Yoosee.\n'
new_27 += '- **H-06 (Firma obsoleta, CVSS 8.1, Alta-Cr' + chr(0xED) + 'tica):** APK firmado con `SHA1withRSA` y llave de 1024 bits. NIST deprec' + chr(0xF3) + ' SHA-1 desde 2011; llave RSA-1024 factorizable con c' + chr(0xE1) + 'lculo en cloud.\n'
new_27 += '- **H-01 (Almacenamiento sin cifrar, CVSS 7.4, Alta):** Tokens de sesi' + chr(0xF3) + 'n (`anonymousAppDeviceGUID`, `user_ids`, `com.facebook.appevents.SessionInfo.sessionId`), contraseñas de emparejamiento de c' + chr(0xE1) + 'mara (en `jacontact.pwd`) y bases de datos completas sin cifrar (sin `SQLCipher` ni `EncryptedSharedPreferences`).\n'
new_27 += '- **H-08 (Cleartext habilitado, CVSS 7.4, Alta):** `usesCleartextTraffic="true"` permite HTTP en claro hacia cualquier dominio. El SDK Tencent Bugly (`android.bugly.qq.com`) expl' + chr(0xED) + 'citamente configurado para cleartext.\n'
new_27 += '- **H-07 (Algoritmos/modos rotos, CVSS 7.2, Alta):** MD5 (`SameMD5.java`), implementaciones custom de AES (`AESUtils`, `AesFlushingCipher`) con alta probabilidad de modos ECB o IVs est' + chr(0xE1) + 'ticos.\n'
new_27 += '- **H-03 (Fuga a ext storage, CVSS 6.5, Media-Alta):** Permisos `WRITE_EXTERNAL_STORAGE` y `MOUNT_UNMOUNT_FILESYSTEMS` declarados.\n'
new_27 += '- **H-02 (Cifrado sandbox L2, CVSS 6.2, Media-Alta):** Datos sensibles en texto claro dentro del sandbox sin envoltura de cifrado (reforza H-01).\n'
new_27 += '\nLa matriz de riesgo post-diagn' + chr(0xF3) + 'stico (Tabla 2.5) ubica **H-05 (CVSS 9.9) y H-06 (CVSS 8.1)** en la celda Cr' + chr(0xED) + 'tico \u00d7 Cr' + chr(0xED) + 'tico del mapa de calor (Figura 2.22), lo cual fundamenta la priorizaci' + chr(0xF3) + 'n de mitigaci' + chr(0xF3) + 'n del Cap' + chr(0xED) + 'tulo III.\n\n'
new_27 += '**Verificaci' + chr(0xF3) + 'n SAST del framework de defensa:**\n\n'
new_27 += '- **MASVS-NETWORK-2 (Certificate Pinning) y GMS Provider:** L11 tiene captura DAST pendiente. La ausencia de certificate pinning ya fue indicada en la v4 (parche actual no incluye `<pin-set>` en la NSC; un atacante con Burp + bypass con `objection android sslpinning disable` podr' + chr(0xED) + 'a interceptar HTTPS sin requerir bypass previo).\n'
new_27 += '- **MASVS-STORAGE-1 (Almacenamiento seguro):** El parche actual **s' + chr(0xED) + ' tiene una debilidad deliberada**: para habilitar la instrumentaci' + chr(0xF3) + 'n DAST, `extractNativeLibs="true"` qued' + chr(0xF3) + ' activado en `AndroidManifest.xml`. En un release de producci' + chr(0xF3) + 'n, este flag debe volver a `false` (ver mitigaci' + chr(0xF3) + 'n \u00a73.2.2 y \u00a73.5).\n\n'
new_27 += '**Trabajo futuro (lineamientos MASTG descartados):**\n\n'
new_27 += 'Los 7 IDs MASTG-TEST descartados en \u00a72.4.1 por criterio de costo-beneficio son: `MASTG-TEST-0201` (hooks de almacenamiento externo, redundante con 0200), `MASTG-TEST-0204/0205` (PRNG d' + chr(0xE9) + 'bil, com' + chr(0xFA) + 'n en apps Java), `MASTG-TEST-0312` (provider deprecated, sin uso expl' + chr(0xED) + 'cito en JADX), `MASTG-TEST-0307/0308` (prop' + chr(0xF3) + 'sito de clave Keystore, L2 nicho), y `MASTG-TEST-0295` (GMS Security Provider, valor demostrativo bajo). Su ejecuci' + chr(0xF3) + 'n en una versi' + chr(0xF3) + 'n extendida de la auditor' + chr(0xED) + 'a sumar' + chr(0xED) + 'a **2 puntos** al cumplimiento confirmado (debido a que `MASTG-TEST-0312` y `MASTG-TEST-0295` resultar' + chr(0xED) + 'an CUMPLE con alta probabilidad dado el an' + chr(0xE1) + 'lisis SAST previo), llevando la tasa a **27 % confirmado**.\n\n'
new_27 += 'Estos resultados fundamentan la necesidad de la propuesta de mitigaci' + chr(0xF3) + 'n t' + chr(0xE9) + 'cnica que se desarrolla en el Cap' + chr(0xED) + 'tulo III, donde cada lineamiento incumplido (H-01 a H-08) recibir' + chr(0xE1) + ' su recomendaci' + chr(0xF3) + 'n espec' + chr(0xED) + 'fica de remediaci' + chr(0xF3) + 'n con un roadmap priorizado en 3 tiers (Quick Wins / Mediano Plazo / Largo Plazo).\n'

content = content.replace(old_27_text, new_27)
print('§2.7 Conclusiones reemplazada')

with open(path, 'w', encoding='utf-8', newline='') as f:
    f.write(content)
print('OK guardado')
