# L06 — Rotación del Certificado de Firma (subsana H-06)

## Hallazgo a subsanar

**MASTG-TEST-IDs:** 0208
**MASVS control:** MASVS-CRYPTO-1 (The app verifies the integrity of the platform)
**MASWE weakness:** MASWE-0002 (Use of a Broken or Risky Cryptographic Algorithm)
**Activos afectados:** ACT-04 (integridad de la app distribuida)

**Hallazgo verificado:** MobSF `Signer Certificate` muestra que Yoosee v6.44.1 está firmado con `SHA1withRSA` y una clave RSA de 1024 bits. NIST deprecó SHA-1 en 2011 (transición completa a SHA-256 en 2030, pero ya no se recomienda para nuevas aplicaciones). RSA-1024 es factorizable con recursos de cómputo en cloud actuales (proyecto CADO-NFS, 2017: ~70 días de CPU para un solo par de claves).

**CVSS v3.1:** `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H` = **8.1 (Alta-Crítica)**.

## Mitigación propuesta

Generar un nuevo keystore de release con `SHA256withRSA` y RSA-2048 (mínimo NIST), o preferentemente `SHA256withECDSA` con curva P-256 (más eficiente, misma seguridad con claves más cortas). Coordinar la rotación con Google Play para actualizar la firma de la app distribuida.

### Script de generación del keystore

**`tools/regenerate_keystore.sh` (Bash/Git Bash):**
```bash
#!/usr/bin/env bash
# regenerate_keystore.sh
# Genera un nuevo keystore de release para Yoosee v6.44.2+
# Cumple: SHA256withRSA 2048 bits o SHA256withECDSA P-256

set -euo pipefail

KEYSTORE_FILE="yoosee-release.keystore"
KEY_ALIAS="yoosee"
VALIDITY_DAYS=10000
DNAME="CN=Yoosee Release, O=Gwell, C=CN"

# Opción A: SHA256withRSA 2048 bits (estándar actual, máxima compatibilidad)
echo "==> Generando keystore con SHA256withRSA 2048..."
keytool -genkeypair -v \
    -keystore "$KEYSTORE_FILE" \
    -alias "$KEY_ALIAS" \
    -keyalg RSA \
    -keysize 2048 \
    -validity $VALIDITY_DAYS \
    -sigalg SHA256withRSA \
    -dname "$DNAME" \
    -storepass "${KEYSTORE_PASSWORD:?ERROR: definir KEYSTORE_PASSWORD en env}" \
    -keypass "${KEY_PASSWORD:?ERROR: definir KEY_PASSWORD en env}"

echo "==> Keystore generado: $KEYSTORE_FILE"
echo "==> Verificar:"
keytool -list -v -keystore "$KEYSTORE_FILE" -storepass "$KEYSTORE_PASSWORD" | head -20
```

**`tools/regenerate_keystore_ecdsa.sh` (opción preferente):**
```bash
#!/usr/bin/env bash
# Versión con ECDSA P-256 (más eficiente, misma seguridad)
set -euo pipefail

KEYSTORE_FILE="yoosee-release.keystore"
KEY_ALIAS="yoosee"
VALIDITY_DAYS=10000
DNAME="CN=Yoosee Release, O=Gwell, C=CN"

echo "==> Generando keystore con SHA256withECDSA P-256..."
keytool -genkeypair -v \
    -keystore "$KEYSTORE_FILE" \
    -alias "$KEY_ALIAS" \
    -keyalg EC \
    -groupname secp256r1 \
    -validity $VALIDITY_DAYS \
    -sigalg SHA256withECDSA \
    -dname "$DNAME" \
    -storepass "${KEYSTORE_PASSWORD:?ERROR: definir KEYSTORE_PASSWORD en env}" \
    -keypass "${KEY_PASSWORD:?ERROR: definir KEY_PASSWORD en env}"
```

### Rotación de la app en Google Play

**Procedimiento para el fabricante Gwell:**

1. **Generar el nuevo keystore** con uno de los scripts anteriores.
2. **Vincular el nuevo keystore con Google Play App Signing:**
   - Ir a Google Play Console → Tu app → Configuración → Integridad de la app
   - Subir el nuevo certificado público (.pem o .der)
   - Google Play firmará las actualizaciones futuras con la clave de firma de la app (que controla Google)
3. **Compilar el nuevo APK** firmado con el nuevo keystore:
   ```bash
   cd dast_lab
   cp yoosee-release.keystore tools/  # NO commit este archivo
   ./gradlew assembleRelease \
       -Pandroid.injected.signing.store.file=tools/yoosee-release.keystore \
       -Pandroid.injected.signing.store.password="$KEYSTORE_PASSWORD" \
       -Pandroid.injected.signing.key.alias=yoosee \
       -Pandroid.injected.signing.key.password="$KEY_PASSWORD"
   ```
4. **Republicar el APK** en Google Play (track de producción o staged rollout del 10% primero).
5. **Esperar 7-14 días** para la revisión de Google Play.
6. **Monitorear** durante 48 horas post-rollout por si hay crash reports.

### Rotación de claves asimétricas en runtime (claves generadas con KeyPairGenerator)

Para claves asimétricas nuevas generadas en runtime (no las del keystore, sino las que la app crea con `KeyPairGenerator`), exigir tamaño mínimo:

**`KeyRotationManager.kt`:**
```kotlin
package com.yoosee.security

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator

object KeyRotationManager {
    
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    
    fun generateSigningKeyPair(alias: String) {
        val keyGenSpec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        )
            .setKeySize(2048)  // RSA mínimo NIST 2024
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
            .build()
        
        val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEYSTORE)
        kpg.initialize(keyGenSpec)
        kpg.generateKeyPair()
    }
    
    fun generateECKeyPair(alias: String) {
        // ECDSA P-256 (recomendado para nuevas apps)
        val keyGenSpec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        )
            .setKeySize(256)
            .setDigests(KeyProperties.DIGEST_SHA256)
            .build()
        
        val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
        kpg.initialize(keyGenSpec)
        kpg.generateKeyPair()
    }
}
```

## Verificación post-mitigación

### Verificación 1: Nuevo algoritmo de firma (MASTG-TEST-0208)

```bash
# Re-escanear con MobSF
docker run -it --rm -p 8000:8000 opensecurity/mobsf:latest
# Cargar el nuevo APK
# Verificar sección "Signer Certificate":
# - Signature Algorithm: SHA256withRSA (o SHA256withECDSA)
# - Bit size: 2048 (RSA) o 256 (ECDSA)
# - Validity: al menos hasta 2030
```

### Verificación 2: Línea de comandos

```bash
# Verificar el certificado con apksigner
$ANDROID_HOME/build-tools/36.0.0/apksigner verify --verbose --print-certs out/yoosee_v2.apk
# Resultado esperado (snippet):
# Verifies
# Verified using v2 scheme (APK Signature Scheme v2): true
# Number of signers: 1
# Signer #1 certificate DN: CN=Yoosee Release, O=Gwell, C=CN
# Signer #1 certificate SHA-256: <hash>
# Signer #1 certificate MD5: <hash>
# Signed using: RSA (bit size 2048) ← ESTO ES LO QUE VERIFICAMOS
# Digest: SHA-256
```

### Verificación 3: La app sigue funcionando

```bash
# Instalar el nuevo APK firmado
adb install -r out/yoosee_v2.apk
# La app debe arrancar sin crash
# Verificar que la firma del APK es reconocida por Google Play
```

## Métrica objetivo

Tras la rotación, L06 debe pasar de **NO CUMPLE Alta-Crítica** (CVSS 8.1) a **CUMPLE** (CVSS 0.0), llevando el cumplimiento de 36% a ~45%.
