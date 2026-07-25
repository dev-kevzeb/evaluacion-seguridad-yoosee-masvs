# Metodología de la Auditoría

> Monografía: *"Evaluación de seguridad de la aplicación móvil Yoosee para cámaras de videovigilancia marca Tomate mediante el estándar OWASP MASVS"*
> Autor: Wally Kevin Zeballos Oquendo · UMSS · 2026

Este documento describe la metodología completa aplicada en la auditoría de Yoosee v6.44.1. Está pensada para auditores que deseen **reproducir** los resultados o aplicar la misma metodología a otra app móvil IoT.

## Marco internacional: OWASP MASVS + MASTG

| Componente | Documento | Función | Ejemplo |
|---|---|---|---|
| Control objetivo | **OWASP MASVS 2.1.0** (Mobile Application Security Verification Standard) | Define QUÉ se debe verificar | MASVS-STORAGE-1: "The app securely stores sensitive data" |
| Test/procedimiento | **OWASP MASTG 2.0.0** (Mobile Application Security Testing Guide) | Define CÓMO se verifica | MASTG-TEST-0287: "Make sure that no sensitive data is stored in the SharedPreferences" |
| Debilidad | **OWASP MASWE** (Mobile Application Security Weaknesses) | Catálogo de fallos | MASWE-0006: "Sensitive Data Stored Unencrypted" |
| Puntuación | **CVSS 3.1** (FIRST.org) | Cuantificar severidad de 0.0 a 10.0 | `AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` = 7.4 (Alta) |

**Analogía:** MASVS es la norma ISO de seguridad alimentaria (qué debe cumplir un restaurante); MASTG es la guía del inspector sanitario (cómo verificarlo); MASWE es el catálogo de infracciones posibles; CVSS es la escala de severidad.

## Tres dimensiones evaluadas

De las 8 dimensiones que tiene MASVS (STORAGE, CRYPTO, NETWORK, AUTH, PLATFORM, CODE, RESILIENCE, PRIVACY), esta auditoría se centró en las **3 más críticas** para una app IoT de videovigilancia:

| Dimensión | Justificación de inclusión | Justificación de exclusión de las otras 5 |
|---|---|---|
| **STORAGE** | Privacidad del video, credenciales, tokens | AUTH/PLATFORM/CODE/RESILIENCE/PRIVACY aplican a apps con autenticación de usuarios, interacciones con el SO, ofuscación, persistencia post-instalación o compliance de privacidad — secundario en una app IoT donde lo crítico es el video y las credenciales. |
| **CRYPTO** | Integridad de credenciales y comunicaciones | |
| **NETWORK** | MitM en la red Wi-Fi, eavesdropping del stream de video | |

## Estrategia: 3 dimensiones → 5 activos → 11 lineamientos

```
OWASP MASVS              Activos del sistema          Lineamientos MASTG-TEST
(dimensiones)            (qué protegemos)            (cómo verificamos)
─────────────────        ────────────────────         ──────────────────────
MASVS-STORAGE-1  ──→  ACT-01 credenciales    ──→  L01 (0287+0304)
                      ACT-02 tokens              L04 (0231)
                      ACT-05 capturas            L02 (0207)
                                                 L03 (0262+0216)

MASVS-CRYPTO-1   ──→  ACT-01 credenciales    ──→  L06 (0208)
                      ACT-02 tokens              L07 (0221+0232+0350)
                      ACT-04 cámara              L05 (0212)

MASVS-NETWORK-1  ──→  ACT-01 credenciales    ──→  L08 (0235+0236)
                      ACT-02 tokens              L09 (0233)
                      ACT-03 video               L10 (0217+0218)
                      ACT-04 cámara              L11 (0282-86+0242+0244)
```

**Resultado:** **11 lineamientos ejecutados** (4 STORAGE + 3 CRYPTO + 4 NETWORK).

## Doble fuente: SAST + DAST

Para cada lineamiento se aplicaron **ambas técnicas**:

### SAST (Static Application Security Testing)
- **Herramientas:** JADX-GUI 1.5.6, MobSF v4.5.1
- **Qué hace:** decompila el APK, analiza el código fuente descompilado, busca patrones (URLs, llamadas a APIs inseguras, secretos hardcoded)
- **Ventaja:** ve TODO el código, incluyendo rutas no ejecutadas en runtime
- **Desventaja:** genera falsos positivos, no captura comportamiento dinámico

### DAST (Dynamic Application Security Testing)
- **Herramientas:** Frida 17.16.3 (instrumentación), Burp Suite Community (tráfico de red)
- **Qué hace:** ejecuta la app en un dispositivo físico, intercepta métodos Java/nativos en runtime con hooks, captura tráfico de red
- **Ventaja:** ve lo que REALMENTE pasa; los hooks capturan valores reales (no suposiciones)
- **Desventaja:** solo lo que se ejecuta durante la sesión de prueba; puede haber código dormido

### Por qué ambas son necesarias
- **SAST** sin DAST: detecta "esto PODRÍA ser un problema" pero no confirma que se explote.
- **DAST** sin SAST: confirma "esto SÍ se explota" pero no ve código que no se ejecutó.
- **SAST + DAST:** cobertura completa. La intersección (lo que ambas confirman) es el hallazgo sólido.

## Criterio de descarte de los 7 MASTG-TEST IDs

Se descartaron 7 IDs por criterio de costo-beneficio, justificado en §2.4.1 de la monografía:

| ID | Razón del descarte |
|---|---|
| `0201` | Redundante con `0200` (misma superficie) |
| `0204`, `0205` | PRNG débil (común en toda app Java; bajo riesgo real para Yoosee) |
| `0312` | Provider deprecated (sin uso explícito en JADX) |
| `0307`, `0308` | Propósito único de clave Keystore (L2 nicho) |
| `0295` | GMS Security Provider (valor demostrativo bajo) |

Estos quedan listados como **trabajo futuro** en §2.7.

## CVSS 3.1: cuantificación del riesgo

CVSS asigna un puntaje de 0.0 a 10.0 según 8 métricas. Tres son de exploitabilidad:

- **AV** (Attack Vector): Network (N), Adjacent Network (A), Local (L), Physical (P)
- **AC** (Attack Complexity): Low (L), High (H)
- **PR** (Privileges Required): None (N), Low (L), High (H)

Tres son de impacto:

- **C** (Confidentiality): None (N), Low (L), High (H)
- **I** (Integrity): None (N), Low (L), High (H)
- **A** (Availability): None (N), Low (L), High (H)

Más:

- **S** (Scope): Unchanged (U), Changed (C)
- **UI** (User Interaction): None (N), Required (R)

**Escala de severidad:**

| Puntaje | Severidad |
|---|---|
| 0.0 | Informativo |
| 0.1 – 3.9 | Baja |
| 4.0 – 6.9 | Media |
| 7.0 – 8.9 | Alta |
| 9.0 – 10.0 | Crítica |

**Vector de ejemplo** (H-01 almacenamiento sin cifrado): `AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` = **7.4 (Alta)**.

**Cálculo:** la fórmula es estandarizada por FIRST y se calcula automáticamente en https://www.first.org/cvss/calculator/3.1. No es subjetiva del auditor.

## Hallazgos consolidados

Ver [hallazgos.md](hallazgos.md) para la tabla completa con las 12 entradas (H-01 a H-12).
