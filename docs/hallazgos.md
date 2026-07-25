# Tabla Resumen de Hallazgos (H-01 a H-12)

> Monografía: *"Evaluación de seguridad de la aplicación móvil Yoosee para cámaras de videovigilancia marca Tomate mediante el estándar OWASP MASVS"*
> Autor: Wally Kevin Zeballos Oquendo · UMSS · 2026

Esta tabla consolida los 12 hallazgos de la auditoría de Yoosee v6.44.1. Cada hallazgo está documentado en detalle en `monografia-capituloII.md` (no incluido en este repo por ser contenido de la monografía).

## Tabla consolidada

| ID | Hallazgo | MASTG-TEST | MASVS | CVSS | Severidad | Carpeta de remediación |
|---|---|---|---|---|---|---|
| H-01 | SharedPreferences + SQLite + MMKV en claro | 0287 + 0304 | STORAGE-1 | 7.4 | Alta | [L01](../implementations/L01_storage_cifrado/) |
| H-02 | Cifrado en sandbox L2 (subsidiario) | 0207 | STORAGE-1 | 6.2 | Media-Alta | [L01](../implementations/L01_storage_cifrado/) |
| H-03 | Fuga a almacenamiento externo | 0200 + 0202 | STORAGE-2 | 6.5 | Media-Alta | [L02](../implementations/L02_scoped_storage/) |
| H-04 | Fuga de tokens en logs | 0231 | STORAGE-2 | 0.0 | Informativa | — (CUMPLE) |
| H-05 | 243 secretos hardcodeados en el binario | 0212 | CRYPTO-2 | 9.9 | Crítica | [L05](../implementations/L05_secretos_externos/) |
| H-06 | Certificado SHA-1 + RSA-1024 | 0208 | CRYPTO-1 | 8.1 | Alta-Crítica | [L06](../implementations/L06_certificado_firma/) |
| H-07 | MD5 + AES/ECB + SHA-1 en SDKs | 0221 + 0232 + 0350 | CRYPTO-1 | 7.2 | Alta | [L07](../implementations/L07_algoritmos_cripto/) |
| H-08 | Tráfico cleartext habilitado (config) | 0235 + 0236 | NETWORK-1 | 7.4 | Alta | [L08](../implementations/L08_nsc_cleartext/) |
| H-09 | 91 URLs HTTP hardcoded (con PII) | 0233 | NETWORK-1 | 5.3 | Media | [L09](../implementations/L09_urls_https/) |
| H-10 | Protocolos TLS inseguros | 0217 + 0218 | NETWORK-1 | 0.0 | Informativa | — (CUMPLE) |
| H-11 | Cadena TLS y pinning | 0282-86 + 0242 + 0244 | NETWORK-1/2 | 0.0 | Informativa | — (CUMPLE) |
| H-12 | allowBackup=false (backups) | 0262 + 0216 | STORAGE-2 | 0.0 | Informativa | — (CUMPLE) |

## Distribución por dimensión

| Dimensión | Total | CUMPLE | NO CUMPLE | Tasa |
|---|---|---|---|---|
| STORAGE (L01-L04) | 4 | 2 (L03, L04) | 2 (L01, L02) | 50% |
| CRYPTO (L05-L07) | 3 | 0 | 3 (L05, L06, L07) | 0% |
| NETWORK (L08-L11) | 4 | 2 (L10, L11) | 2 (L08, L09) | 50% |
| **TOTAL** | **11** | **4** | **7** | **36%** |

## Distribución por severidad CVSS

```
Crítica (9.0-10.0) ──────── ████ H-05 (9.9)
Alta-Crítica (8.0-8.9) ──── ████ H-06 (8.1)
Alta (7.0-7.9) ─────────── ████████ H-01 (7.4) H-08 (7.4) H-07 (7.2)
Media-Alta (6.0-6.9) ───── ████████ H-03 (6.5) H-02 (6.2)
Media (4.0-5.9) ────────── ████ H-09 (5.3)
Baja (0.1-3.9) ─────────── (ninguno)
Informativa (0.0) ──────── ████████ H-04 H-10 H-11 H-12
```

## Hallazgos críticos prioritarios (Top 3)

### H-05 — 243 secretos hardcodeados (CVSS 9.9 Crítica)

La API key de Google (`AIzaSyDHz9JJCWU7D_ZBD2LNc-ETRp07vX4JXLM`), el token de Facebook, la URL de Firebase, y bloques ASN.1 DER con material criptográfico embebido. Compromete directamente la infraestructura cloud del fabricante.

**Detección:** MobSF → Code Analysis → Possible Hardcoded Secrets (243 detecciones).
**Carpetas:** `implementations/L05_secretos_externos/`

### H-06 — Certificado de firma obsoleto (CVSS 8.1 Alta-Crítica)

APK firmada con SHA-1 (deprecado por NIST en 2011) y RSA-1024 (factorizable con cómputo actual). Permite a un atacante generar APKs maliciosas con firma válida.

**Detección:** MobSF → Signer Certificate.
**Carpetas:** `implementations/L06_certificado_firma/`

### H-01 — Almacenamiento en claro (CVSS 7.4 Alta)

Los hooks de Frida capturaron 13 escrituras en claro con email, token de 156 caracteres hex, y otros datos sensibles. Tres tablas SQLite almacenan contraseñas de emparejamiento de cámara sin cifrar.

**Detección:** `scripts/hook_sharedprefs.js` con Frida.
**Carpetas:** `implementations/L01_storage_cifrado/`

## Mapa de calor (probabilidad × impacto)

```
                        Probabilidad
                   Baja   Media   Alta   Crítica
        Crítica   │       │       │  H-05 │
        Alta      │       │ H-02  │  H-01 H-08 H-07 │
Impacto  Media     │       │ H-09  │  H-03 H-06 │
        Baja      │ H-04  │       │       │
```

(Los hallazgos CUMPLE — H-10, H-11, H-12 — quedan fuera de la zona de riesgo porque CVSS=0.0.)

## Lineamientos descartados (7 IDs)

| ID | Razón |
|---|---|
| MASTG-TEST-0201 | Redundante con 0200 |
| MASTG-TEST-0204 | PRNG débil (común en Java, bajo riesgo) |
| MASTG-TEST-0205 | PRNG débil (idem) |
| MASTG-TEST-0295 | GMS Security Provider (valor demostrativo bajo) |
| MASTG-TEST-0307 | Propósito único de clave Keystore (L2 nicho) |
| MASTG-TEST-0308 | Propósito único de clave Keystore (L2 nicho) |
| MASTG-TEST-0312 | Provider deprecated (sin uso en JADX) |

Quedan listados como **trabajo futuro** en la monografía (§2.7).
