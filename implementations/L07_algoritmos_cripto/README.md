# L07 — Sustitución de Algoritmos y Modos Criptográficos Rotos (subsana H-07)

## Hallazgo a subsanar

**MASTG-TEST-IDs:** 0221 + 0232 + 0350
**MASVS control:** MASVS-CRYPTO-1 (The app uses strong cryptography)
**MASWE weakness:** MASWE-0005 (Use of a Broken or Risky Cryptographic Algorithm)
**Activos afectados:** ACT-01 (credenciales), ACT-04 (cámara, configuraciones)

**Hallazgo verificado:** el script `scripts/hook_cipher.js` (Frida) interceptó en runtime:
- **4 invocaciones `AES/ECB/PKCS5Padding`** (modo ECB, inseguro)
- **15+ invocaciones `MessageDigest.getInstance("MD5")`** (MD5 es criptográficamente roto desde 2004)
- **4 invocaciones `MessageDigest.getInstance("SHA-1")`** (SHA-1 es roto desde 2017, colisión SHAttered)
- **2 invocaciones `SecretKeySpec` con `HmacSHA1` y llaves de 256/288 bits**

Las clases responsables identificadas en JADX:
- `com.mbridge.msdk.foundation.tools.SameMD5.java` (MBridge SDK)
- `com.tradplus.ads.base.network.AESUtils.java` (TradPlus SDK)
- `com.mbridge.msdk.playercommon.crypto.AesFlushingCipher.java` (MBridge SDK)

**Causa raíz:** fragmentación criptográfica. Cada SDK de terceros usa su propia implementación en lugar de delegar al Android Keystore.

**CVSS v3.1:** `AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` = **7.2 (Alta)**.

## Mitigación propuesta (3 sustituciones)

### 1. Hashing: eliminar MD5 y SHA-1, sustituir por SHA-256

**`HashingUtils.kt`:**
```kotlin
package com.yoosee.security

import java.security.MessageDigest
import java.security.NoSuchAlgorithmException

object HashingUtils {
    
    /**
     * Genera un hash SHA-256 (256 bits, 64 caracteres hex).
     * Reemplaza todos los usos de MD5 y SHA-1.
     */
    @Throws(NoSuchAlgorithmException::class)
    fun sha256(input: ByteArray): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(input)
        return digest.digest()
    }
    
    fun sha256Hex(input: String): String {
        return sha256(input.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
    }
    
    /**
     * Genera un hash SHA-256 con salt (recomendado para passwords).
     */
    fun sha256WithSalt(input: String, salt: ByteArray): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(salt)
        digest.update(input.toByteArray(Charsets.UTF_8))
        return digest.digest()
    }
    
    /**
     * Para escenarios de alta criticidad (firma de auditoría, etc.),
     * usar SHA-3 si está disponible.
     */
    fun sha3_256(input: ByteArray): ByteArray? {
        return try {
            val digest = MessageDigest.getInstance("SHA3-256")
            digest.update(input)
            digest.digest()
        } catch (e: NoSuchAlgorithmException) {
            null
        }
    }
}
```

**Eliminar del código:**
```bash
# Buscar y reemplazar cualquier invocación a MD5 o SHA-1
grep -rn "MessageDigest.getInstance(\"MD5\")\|MessageDigest.getInstance(\"SHA-1\")\|MessageDigest.getInstance(\"SHA1\")" \
    implementations/ scripts/
# Resultado esperado: 0 ocurrencias
```

### 2. Cifrado simétrico: eliminar AES/ECB, sustituir por AES-GCM-256

**`CryptoUtils.kt`:**
```kotlin
package com.yoosee.security

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

object CryptoUtils {
    
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val GCM_TAG_LENGTH_BITS = 128
    private const val GCM_IV_LENGTH_BYTES = 12
    
    /**
     * Genera una clave AES-256 en el Android Keystore.
     * La clave NO es exportable; queda protegida por el TEE/StrongBox si está disponible.
     */
    fun generateAESKey(alias: String): SecretKey {
        val keyGenSpec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setKeySize(256)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setRandomizedEncryptionRequired(true)  // fuerza IV aleatorio
            .setIsStrongBoxBacked(true)  // usar TEE si está disponible
            .build()
        
        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE
        )
        keyGenerator.init(keyGenSpec)
        return keyGenerator.generateKey()
    }
    
    /**
     * Cifra con AES-GCM-256 (AEAD: cifrado autenticado).
     * IV de 12 bytes aleatorio por cifrado.
     * Tag de autenticación de 128 bits.
     */
    fun encryptAES_GCM(plaintext: ByteArray, key: SecretKey): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val iv = ByteArray(GCM_IV_LENGTH_BYTES).also { SecureRandom().nextBytes(it) }
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv))
        val ciphertext = cipher.doFinal(plaintext)
        // Formato: [12 bytes IV][N bytes ciphertext + 16 bytes tag]
        return iv + ciphertext
    }
    
    fun decryptAES_GCM(ciphertextWithIv: ByteArray, key: SecretKey): ByteArray {
        val iv = ciphertextWithIv.copyOfRange(0, GCM_IV_LENGTH_BYTES)
        val ciphertext = ciphertextWithIv.copyOfRange(GCM_IV_LENGTH_BYTES, ciphertextWithIv.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv))
        return cipher.doFinal(ciphertext)
    }
}
```

**Eliminar del código:**
```bash
# Buscar y reemplazar AES/ECB (modo inseguro)
grep -rn "AES/ECB\|getInstance(\"AES\")" implementations/ scripts/
# Resultado esperado: 0 ocurrencias de AES/ECB o getInstance("AES") sin modo explícito
# (AES solo o AES/ECB = ECB por default, ambos inseguros)
```

### 3. HMAC: eliminar HmacSHA1, sustituir por HmacSHA256

**`MacUtils.kt`:**
```kotlin
package com.yoosee.security

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

object MacUtils {
    
    private const val HMAC_ALGORITHM = "HmacSHA256"
    
    fun computeHmacSha256(message: ByteArray, key: ByteArray): ByteArray {
        val mac = Mac.getInstance(HMAC_ALGORITHM)
        mac.init(SecretKeySpec(key, HMAC_ALGORITHM))
        return mac.doFinal(message)
    }
}
```

**Eliminar del código:**
```bash
grep -rn "HmacSHA1\|HmacSHA-1" implementations/ scripts/
# Resultado esperado: 0 ocurrencias
```

## Acción crítica: coordinar con proveedores de SDKs

**Limitación operativa importante:** la fragmentación criptográfica está en SDKs de terceros. El fabricante Gwell (Shenzhen, China) controla el código de Yoosee, pero las clases específicas están en:
- `com.mbridge.msdk.foundation.tools.SameMD5` (MBridge SDK — propiedad de ByteDance)
- `com.tradplus.ads.base.network.AESUtils` (TradPlus SDK — propiedad de InMobi/TradPlus)
- `com.mbridge.msdk.playercommon.crypto.AesFlushingCipher` (MBridge SDK)

**Opciones para el fabricante:**

1. **Opción A (preferida): solicitar actualización a los proveedores.** Contactar a ByteDance (MBridge) e InMobi (TradPlus) para que las próximas versiones de sus SDKs reemplacen MD5/SHA-1/AES-ECB por SHA-256/AES-GCM-256. Es un issue de seguridad conocido de estos SDKs.

2. **Opción B (táctica): remover los SDKs.** Si los SDKs no son críticos para la funcionalidad core, eliminarlos. Las funciones afectadas serían:
   - MBridge: mediación de anuncios y tracking de conversiones
   - TradPlus: plataforma de mediation de ads
   - Estas funciones NO son críticas para la app de cámara IoT, por lo que su remoción es viable.

3. **Opción C (workaround): aislar los SDKs.** Si los SDKs no pueden removerse ni actualizarse, aislar su uso: encriptar los datos antes de que pasen por los SDKs, y nunca pasarles credenciales reales (solo IDs opacos).

## Verificación post-mitigación

### Verificación 1: SAST (MASTG-TEST-0221)

```bash
# Buscar algoritmos inseguros en el código fuente
cd dast_lab
grep -rn "MD5\|DES\|RC4\|Blowfish\|HmacSHA1" implementations/
# Resultado esperado: 0 ocurrencias (excluyendo comentarios y tests)
```

### Verificación 2: SAST (MASTG-TEST-0232)

```bash
# Buscar AES/ECB (modo inseguro)
grep -rn "AES/ECB\|getInstance(\"AES\")" implementations/ scripts/
# Resultado esperado: 0 ocurrencias
```

### Verificación 3: DAST runtime (MASTG-TEST-0350)

```bash
# Adjuntar Frida con el script actualizado
cd scripts
frida -U -n Gadget -l hook_cipher.js

# Realizar el flujo de login y preview
# Resultado esperado: 0 líneas con prefijo [!] BROKEN
# (todas las invocaciones deben ser AES/GCM, SHA-256, HmacSHA256, etc.)
```

### Verificación 4: Inspección de las clases de los SDKs

```bash
# Decompilar el nuevo APK y buscar las 3 clases identificadas
jadx-gui out/yoosee_v2.apk
# Buscar:
#   com.mbridge.msdk.foundation.tools.SameMD5.java
#   com.tradplus.ads.base.network.AESUtils.java
#   com.mbridge.msdk.playercommon.crypto.AesFlushingCipher.java
# Resultado esperado: 0 archivos (SDKs removidos) o reescritos con SHA-256/AES-GCM
```

## Métrica objetivo

Tras la sustitución, L07 debe pasar de **NO CUMPLE Alta** (CVSS 7.2) a **CUMPLE** (CVSS 0.0), llevando el cumplimiento de 36% a ~55-60%. **Limitación:** si los SDKs de terceros no actualizan, la meta es inalcanzable sin remover los SDKs.
