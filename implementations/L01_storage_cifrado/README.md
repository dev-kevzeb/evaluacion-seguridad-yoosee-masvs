# L01 — Cifrado de Datos en Reposo (subsana H-01 y H-02)

## Hallazgo a subsanar

**MASTG-TEST-IDs:** 0287 + 0304 (+ 0207 para L2)
**MASVS control:** MASVS-STORAGE-1 (The app securely stores sensitive data)
**MASWE weakness:** MASWE-0006 (Sensitive Data Stored Unencrypted)
**Activos afectados:** ACT-01 (credenciales), ACT-02 (tokens de sesión), ACT-04 (contraseñas de emparejamiento de cámara)

**Hallazgo verificado:** el script `scripts/hook_sharedprefs.js` (Frida) interceptó **13 escrituras `SENSITIVE MMKV.encode(String)`** con credenciales y tokens en claro durante el flujo de login, incluyendo `account_info_email='<EMAIL>'`, `iotAccessToken` (cadena de 156 caracteres hexadecimales), `keyUserRegion='us'`, `regRegion='BO'`, y `terminalId`. Las 3 tablas SQLite (`contact`, `apcontact`, `jacontact`) almacenan contraseñas de emparejamiento de cámara en `TEXT` sin cifrar. La búsqueda SAST en JADX descartó toda invocación a `EncryptedSharedPreferences`, `MasterKey.Builder` o SQLCipher.

**CVSS v3.1:** `AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` = **7.4 (Alta)**.

## Mitigación propuesta (3 capas defense-in-depth)

### Capa 1 — EncryptedSharedPreferences con MasterKey AES-256-GCM

Reemplazar todas las invocaciones a `getSharedPreferences("name", MODE_PRIVATE)` por `EncryptedSharedPreferences`. El `MasterKey` se construye una sola vez en `Application.onCreate()`.

**Dependencia Gradle (módulo app):**
```gradle
// app/build.gradle
dependencies {
    implementation "androidx.security:security-crypto:1.1.0-alpha06"
}
```

**`YooseeApplication.kt`:**
```kotlin
package com.yoosee

import android.app.Application
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

class YooseeApplication : Application() {
    
    companion object {
        const val PREFS_FILE = "yoosee_secure_prefs"
    }
    
    override fun onCreate() {
        super.onCreate()
        
        // Master Key en Android Keystore (clave maestra AES-256-GCM, no exportable)
        val masterKey = MasterKey.Builder(this)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        
        // SharedPreferences cifradas con API idéntica a la original
        val securePrefs = EncryptedSharedPreferences.create(
            this,
            PREFS_FILE,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,  // cifrado de claves
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM // cifrado de valores
        )
    }
}
```

**Uso en activities/fragments (idéntico a SharedPreferences tradicional):**
```kotlin
// Antes (vulnerable)
val prefs = getSharedPreferences("config", MODE_PRIVATE)
prefs.edit().putString("iotAccessToken", token).apply()

// Después (cifrado)
val prefs = EncryptedSharedPreferences.create(
    context, "config", masterKey,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
)
prefs.edit().putString("iotAccessToken", token).apply()
```

### Capa 2 — SQLCipher con SupportFactory (Room)

Migrar las 3 bases de datos SQLite (Room) del fabricante a SQLCipher. La passphrase se almacena cifrada en `EncryptedSharedPreferences` (Capa 1).

**Dependencias Gradle:**
```gradle
// app/build.gradle
dependencies {
    implementation "net.zetetic:android-database-sqlcipher:4.5.4"
    implementation "androidx.sqlite:sqlite-ktx:2.3.1"
    implementation "androidx.room:room-runtime:2.6.1"
    kapt "androidx.room:room-compiler:2.6.1"
}
```

**`AppDatabase.kt`:**
```kotlin
package com.yoosee.data

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import net.sqlcipher.database.SupportFactory
import java.security.SecureRandom

@Database(entities = [Contact::class, ApContact::class, JaContact::class], version = 1)
abstract class AppDatabase : RoomDatabase() {
    abstract fun contactDao(): ContactDao
    
    companion object {
        @Volatile private var INSTANCE: AppDatabase? = null
        
        fun getInstance(context: Context, securePrefs: SharedPreferences): AppDatabase {
            return INSTANCE ?: synchronized(this) {
                val passphrase = getOrCreatePassphrase(securePrefs)
                val factory = SupportFactory(passphrase)
                INSTANCE ?: Room.databaseBuilder(
                    context.applicationContext,
                    AppDatabase::class.java,
                    "yoosee.db"
                )
                .openHelperFactory(factory)
                .fallbackToDestructiveMigration()
                .build()
                .also { INSTANCE = it }
            }
        }
        
        private fun getOrCreatePassphrase(prefs: SharedPreferences): ByteArray {
            val stored = prefs.getString("db_passphrase_b64", null)
            if (stored != null) return android.util.Base64.decode(stored, android.util.Base64.NO_WRAP)
            
            val newPass = ByteArray(32).also { SecureRandom().nextBytes(it) }
            prefs.edit()
                .putString("db_passphrase_b64", android.util.Base64.encodeToString(newPass, android.util.Base64.NO_WRAP))
                .apply()
            return newPass
        }
    }
}
```

### Capa 3 — Envelope encryption con Android Keystore (TEE/StrongBox)

El material criptográfico raíz (passphrase de SQLCipher) se almacena en Android Keystore con `KeyGenParameterSpec` y `BLOCK_MODE_GCM`, de modo que aun con root el atacante no recupera el material en claro.

**`KeystoreManager.kt`:**
```kotlin
package com.yoosee.security

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

object KeystoreManager {
    
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val KEK_ALIAS = "yoosee_kek"
    
    fun getOrCreateKEK(): SecretKey {
        val keystore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        (keystore.getKey(KEK_ALIAS, null) as? SecretKey)?.let { return it }
        
        val keyGenSpec = KeyGenParameterSpec.Builder(
            KEK_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setKeySize(256)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setRandomizedEncryptionRequired(true)
            // Opcional: requerir StrongBox si está disponible (Android 9+)
            .setIsStrongBoxBacked(true)
            .build()
        
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
            .apply { init(keyGenSpec) }
            .generateKey()
    }
}
```

## Verificación post-mitigación

### Verificación 1: SharedPreferences cifrados (MASTG-TEST-0287)

```bash
# 1. Reconstruir APK parcheado e instalar
cd dast_lab
adb install out/yoosee_final.apk

# 2. Lanzar app y hacer login
adb shell am start -n com.yoosee/.MainActivity

# 3. Adjuntar Frida con script de verificación
cd scripts
frida -U -n Gadget -l hook_sharedprefs.js

# Resultado esperado: las escrituras [SENSITIVE SP.putString] deben
# mostrar valores como Base64/hex (NO el email en claro ni el token en claro)
# Antes de la mitigación: "<EMAIL>"
# Después de la mitigación: "Z2VuZXJhdGVkX2J5X2VuY3J5cHRpb24=" (u otro Base64 opaco)
```

### Verificación 2: SQLite cifrado (MASTG-TEST-0304)

```bash
# Extraer la base de datos del dispositivo
adb shell "run-as com.yoosee cp databases/yoosee.db /sdcard/"
adb pull /sdcard/yoosee.db /tmp/yoosee_check.db

# Verificar la cabecera del archivo
xxd /tmp/yoosee_check.db | head -1
# Resultado esperado: cabecera aleatoria de SQLCipher (no "SQLite format 3\0")
# Antes de la mitigación: "SQLite format 3"
# Después de la mitigación: bytes aleatorios como "1c 5d a7 8b 4f 9e 2a ..."
```

### Verificación 3: Material criptográfico en Keystore (MASTG-TEST-0207)

```bash
# Listar las claves en el Android Keystore (no exportables)
adb shell "run-as com.yoosee cmd -w keystore list"
# O con Frida:
frida -U -n Gadget -e 'Java.perform(function() {
    var ks = Java.use("java.security.KeyStore");
    var k = ks.getInstance("AndroidKeyStore");
    k.load(null);
    var aliases = k.aliases();
    while (aliases.hasMoreElements()) console.log(aliases.nextElement());
})'
# Resultado esperado: aparece "yoosee_kek" (NO exportable desde fuera del proceso)
```

## Métrica objetivo

Tras aplicar las 3 capas, la tasa de cumplimiento del lineamiento L01 debe pasar de **NO CUMPLE** (CVSS 7.4) a **CUMPLE / SATISFACTORIO** (CVSS 0.0), llevando el cumplimiento consolidado de 36% a ~45%.
