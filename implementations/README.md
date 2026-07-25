# Implementaciones de Remediación (Cap III)

> Monografía: *"Evaluación de seguridad de la aplicación móvil Yoosee para cámaras de videovigilancia marca Tomate mediante el estándar OWASP MASVS"*
> Autor: Wally Kevin Zeballos Oquendo · UMSS · 2026

Esta carpeta contiene los snippets de código de remediación para los **8 hallazgos NO CUMPLE** del Capítulo III de la monografía. Cada subcarpeta corresponde a un lineamiento MASTG y contiene:

- `README.md` — descripción del hallazgo, código de remediación, procedimiento de verificación post-mitigación
- `*.kt`, `*.xml`, `*.gradle` — snippets de código (no son proyectos completos, son referencias de implementación)

## Estructura

| Lineamiento | MASTG-TEST | Hallazgo | Carpeta | Tier |
|---|---|---|---|---|
| L01 | 0287 + 0304 | H-01 + H-02 (storage sin cifrado) | [L01_storage_cifrado/](L01_storage_cifrado/) | Largo Plazo |
| L02 | 0207 | (subsidiario de H-01) | [L01_storage_cifrado/](L01_storage_cifrado/) | Largo Plazo |
| L03 | 0262 + 0216 | H-12 (CUMPLE, validación) | — | — |
| L04 | 0231 | H-04 (CUMPLE) | — | — |
| L05 | 0212 | H-05 (secretos hardcoded) | [L05_secretos_externos/](L05_secretos_externos/) | Quick Win + Mediano |
| L06 | 0208 | H-06 (firma obsoleta) | [L06_certificado_firma/](L06_certificado_firma/) | Mediano |
| L07 | 0221 + 0232 + 0350 | H-07 (algoritmos rotos) | [L07_algoritmos_cripto/](L07_algoritmos_cripto/) | Mediano |
| L08 | 0235 + 0236 | H-08 (cleartext) | [L08_nsc_cleartext/](L08_nsc_cleartext/) | Quick Win |
| L09 | 0233 | H-09 (URLs hardcoded) | [L09_urls_https/](L09_urls_https/) | Quick Win + Mediano |
| L10 | 0217 + 0218 | H-10 (CUMPLE) | — | — |
| L11 | 0282-86 + 0242 + 0244 | H-11 (CUMPLE) | — | — |

## Principio rector: Defense-in-Depth

Cada remediación se aplica con un control primario reforzado por un control secundario:

- **L01** (storage): EncryptedSharedPreferences (primario) + SQLCipher (secundario) + Android Keystore con TEE (terciario)
- **L05** (secretos): Firebase Remote Config (no sensibles) + BuildConfigField desde CI/CD (sensibles)
- **L07** (algoritmos): sustitución por AES-GCM-256 (primario) + delegación a Android Keystore (secundario)
- **L08** (cleartext): `usesCleartextTraffic=false` (primario) + NSC restrictiva sin excepciones (secundario)

## Tiers de implementación (Roadmap)

```
Quick Win (1-3 días)    →  L08, L05 (parcial), L09 (parcial), L02 (Scoped Storage)
Mediano Plazo (2-4 sem)  →  L05 completo, L06, L07, L09 completo
Largo Plazo (1-3 meses)  →  L01 + L02 (EncryptedSharedPreferences + SQLCipher + Keystore)
```

## Verificación post-mitigación

Cada `README.md` de lineamiento incluye un procedimiento concreto de **verificación post-mitigación** (comando `grep`, script Frida, sesión Burp) que un auditor puede ejecutar para confirmar que el control quedó implementado. La métrica objetivo del roadmap completo es llevar la tasa de cumplimiento MASVS confirmado del **36%** (línea base) a **≥ 80%** (9/11 lineamientos).

## Limitación operativa

La remediación de **L05, L07** depende de la cooperación de los proveedores de SDKs de terceros (Tencent para Bugly, ByteDance para Pangle, InMobi para TradPlus, MBridge). El fabricante Gwell (Shenzhen, China) no controla directamente estas dependencias, por lo que la meta del 80% requiere una acción coordinada de release con cada proveedor upstream. Sin esa coordinación, la dimensión CRYPTO no sale de su estado actual (0% de cumplimiento).
