# Evaluación de Seguridad Yoosee v6.44.1 — DAST Lab & Implementation

> **Repositorio público de implementación del Capítulo III de la monografía:**
> *"Evaluación de seguridad de la aplicación móvil Yoosee para cámaras de videovigilancia marca Tomate mediante el estándar OWASP MASVS"*
> Universidad Mayor de San Simón · Facultad de Ciencias y Tecnología · Diplomado

## ¿Qué es este repositorio?

Este repositorio contiene los **scripts de auditoría dinámica (DAST)** y el **código de remediación** resultantes del trabajo de monografía. La auditoría siguió los estándares **OWASP MASVS 2.1.0** y **OWASP MASTG 2.0.0** sobre el binario `base.apk` de Yoosee v6.44.1 (paquete `com.yoosee`), extraído del dispositivo físico Poco X5 5G con Android 14.

## Contenido

```
evaluacion-seguridad-yoosee-masvs/
├── README.md                       ← este archivo
├── LICENSE                         ← MIT License
├── CITATION.cff                    ← metadatos de citación
├── .gitignore                      ← exclusiones de binarios grandes
│
├── scripts/                        ← Scripts DAST (Python + PowerShell + Frida)
│   ├── hook_sharedprefs.js         Hook de SharedPreferences.Editor.put* y MMKV.encode
│   ├── hook_cipher.js              Hook de Cipher.getInstance, MessageDigest, KeyGenerator
│   ├── verify_trust.js              Hook de TrustManagerFactory y SSLContext
│   ├── test_gadget.js               Hook de carga de clases para diagnóstico
│   ├── extract_http_urls.py         Extractor de URLs http:// del APK
│   ├── check_tls_versions.ps1       Verificador TLS 1.0/1.1/1.2/1.3 con openssl
│   ├── scan_antitamper.py           Detector de anti-tampering
│   ├── list_files_inproc.py         Lector de archivos en /proc/self/maps
│   ├── list_files_v2.py             Lector de archivos mejorados
│   ├── update_t25_t26.py            Helper para tests de Network Security Configuration
│   ├── update_27.py                 Helper para test de TLS
│   ├── run_frida.cmd                Wrapper CMD para invocar scripts Frida
│   └── http_urls_originales.txt     Salida textual del extractor (91 URLs)
│
├── out/                            ← Salidas de los scripts (evidencias)
│   ├── cap4.txt                     Evidencia de hooks MMKV/SharedPreferences
│   ├── hookv3_DAST.txt              Evidencia extendida de hooks
│   ├── sharedprefs_capture.txt      Volcado SharedPreferences (anonimizado)
│   ├── sharedprefs_DAST.txt         Evidencia DAST completa
│   ├── sharedprefs_full.txt         Volcado completo
│   ├── yoosee_logcat_capture.txt    Captura de logcat (anonimizada)
│   ├── install_log.txt              Log de instalación del APK parcheado
│   └── yoosee_*.apk                ← (excluidos por .gitignore; reconstruibles con scripts)
│
├── implementations/                ← Código de remediación del Cap III
│   ├── README.md                    Índice de remediaciones
│   ├── L01_storage_cifrado/         EncryptedSharedPreferences + SQLCipher + Keystore
│   ├── L02_scoped_storage/          Scoped Storage + MediaStore
│   ├── L05_secretos_externos/       Externalización de secretos a Firebase Remote Config
│   ├── L06_certificado_firma/        Rotación SHA1withRSA → SHA256withRSA/ECDSA
│   ├── L07_algoritmos_cripto/       Sustitución MD5/SHA-1/AES-ECB
│   ├── L08_nsc_cleartext/           Network Security Configuration restrictiva
│   └── L09_urls_https/              Migración URLs hardcoded a HTTPS
│
├── docs/                           ← Documentación de referencia
│   ├── masvs-2.1.0/                 OWASP MASVS 2.1.0 (oficial)
│   ├── metodologia.md               Metodología de auditoría
│   ├── como-reproducir.md           Guía paso a paso
│   └── hallazgos.md                 Tabla resumen de los 12 hallazgos
│
├── merge_src/                      ← APKs originales extraídos del dispositivo (excluidos del repo)
├── originales/                     ← Copia del base.apk original (excluido)
├── splits/                         ← APKs splits del App Bundle (excluidos)
├── patched/                        ← (vacío; carpeta de salida de parches)
└── tools/                          ← Herramientas externas (excluidas; ver links)
```

## Lineamientos MASTG cubiertos

| Lineamiento | Dimensión MASVS | MASTG-TEST-IDs | Resultado | Implementación |
|---|---|---|---|---|
| L01 | STORAGE-1 | 0287 + 0304 | NO CUMPLE | [implementations/L01_storage_cifrado](implementations/L01_storage_cifrado/) |
| L02 | STORAGE-1 (L2) | 0207 | NO CUMPLE | [implementations/L01_storage_cifrado](implementations/L01_storage_cifrado/) |
| L03 | STORAGE-2 | 0262 + 0216 | CUMPLE | — |
| L04 | STORAGE-2 | 0231 | CUMPLE | — |
| L05 | CRYPTO-2 | 0212 | NO CUMPLE | [implementations/L05_secretos_externos](implementations/L05_secretos_externos/) |
| L06 | CRYPTO-1 | 0208 | NO CUMPLE | [implementations/L06_certificado_firma](implementations/L06_certificado_firma/) |
| L07 | CRYPTO-1 | 0221 + 0232 + 0350 | NO CUMPLE | [implementations/L07_algoritmos_cripto](implementations/L07_algoritmos_cripto/) |
| L08 | NETWORK-1 | 0235 + 0236 | NO CUMPLE | [implementations/L08_nsc_cleartext](implementations/L08_nsc_cleartext/) |
| L09 | NETWORK-1 | 0233 | NO CUMPLE | [implementations/L09_urls_https](implementations/L09_urls_https/) |
| L10 | NETWORK-1 | 0217 + 0218 | CUMPLE | — |
| L11 | NETWORK-1/2 | 0282-86 + 0242 + 0244 | CUMPLE | — |

## Metodología

La auditoría combinó **doble fuente** para cada lineamiento:

1. **SAST (Static Application Security Testing):** análisis estático con JADX-GUI 1.5.6 y MobSF v4.5.1. No requiere ejecución de la app.
2. **DAST (Dynamic Application Security Testing):** instrumentación con Frida 17.16.3 sobre APK parcheado con `objection patchapk`, complementada con Burp Suite Community Edition para tráfico de red.

**Tasa de cumplimiento MASVS final:** 36% (4 de 11 lineamientos CUMPLE).

## Cómo reproducir la auditoría

Ver [docs/como-reproducir.md](docs/como-reproducir.md) para el procedimiento paso a paso.

Requisitos mínimos:
- Windows 10/11 con WSL2
- Docker Desktop con MobSF v4.5.1
- Android SDK Platform-Tools (adb)
- Python 3.x + Frida 17.16.3
- Dispositivo físico Android 7+ (o emulador con root)
- APK original `base.apk` de Yoosee v6.44.1 (se omite del repo por tamaño y PII; extraíble con `adb pull` desde un dispositivo con Yoosee instalado)

## Hallazgos resumidos

Ver [docs/hallazgos.md](docs/hallazgos.md) para la tabla completa. Resumen ejecutivo:

| ID | Hallazgo | CVSS | Severidad |
|---|---|---|---|
| H-05 | 243 secretos hardcodeados en el binario | 9.9 | Crítica |
| H-06 | Certificado de firma SHA-1 + RSA-1024 | 8.1 | Alta-Crítica |
| H-01 | SharedPreferences + SQLite + MMKV en claro | 7.4 | Alta |
| H-08 | Tráfico cleartext habilitado (config) | 7.4 | Alta |
| H-07 | MD5 + AES/ECB + SHA-1 en SDKs de terceros | 7.2 | Alta |
| H-09 | 91 URLs HTTP hardcoded (incluye PII) | 5.3 | Media |
| H-02 | Cifrado en sandbox L2 (subsidiario) | 6.2 | Media-Alta |
| H-03 | Fuga a almacenamiento externo | 6.5 | Media-Alta |

**Cumplen:** H-04 (logs, sin volcado), H-10 (TLS 1.2 ECDHE), H-11 (cadena TLS + sin CAs de usuario), H-12 (allowBackup=false).

## Privacidad y anonimización

Los outputs en `out/` han sido **anonimizados**:
- Direcciones de correo reemplazadas por `<EMAIL>`
- Identificadores de dispositivo (AccountID, DeviceID) reemplazados por `<ID>`
- Tokens de sesión truncados a los primeros 16 caracteres
- Nombres reales (PII) reemplazados por `<PII>`

Los APKs originales (con PII completa) **no se incluyen en el repositorio** y deben ser extraídos directamente del dispositivo Yoosee del auditor.

## Licencia

Este repositorio se distribuye bajo **MIT License** — ver [LICENSE](LICENSE). Eres libre de usar, modificar y distribuir el código con fines académicos y de investigación, manteniendo el aviso de copyright original.

## Referencias

- **OWASP MASVS 2.1.0** (Mobile Application Security Verification Standard) — [docs/masvs-2.1.0/](docs/masvs-2.1.0/)
- **OWASP MASTG 2.0.0** (Mobile Application Security Testing Guide) — https://github.com/OWASP/owasp-mastg
- **NIST SP 800-57** — Recommendation for Key Management
- **FIRST.org CVSS 3.1** — Common Vulnerability Scoring System
- **Android Security Best Practices** — developer.android.com

## Contacto

- **Autor:** Wally Kevin Zeballos Oquendo
- **Tutor:** MSc. Ing. Efrain Fernando Luna Mamani (efrainf.luna@gmail.com)
- **Co-tutor:** MSc. Ing. Hugo Oropeza (efrain.luna@fcyt.umss.edu.bo)
- **Institución:** Universidad Mayor de San Simón — Facultad de Ciencias y Tecnología

## Citación

Usa el botón **"Cite this repository"** de GitHub (generado desde [CITATION.cff](CITATION.cff)) para obtener la cita en APA o BibTeX, o copia la siguiente:

```
Zeballos Oquendo, W. K. (2026). Evaluación de seguridad de la aplicación 
móvil Yoosee para cámaras de videovigilancia marca Tomate mediante el 
estándar OWASP MASVS: DAST Lab & Implementation. 
Universidad Mayor de San Simón, Facultad de Ciencias y Tecnología. GitHub.
https://github.com/dev-kevzeb/evaluacion-seguridad-yoosee-masvs
```
