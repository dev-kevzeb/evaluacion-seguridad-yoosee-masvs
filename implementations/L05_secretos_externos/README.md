# L05 — Externalización de Secretos Hardcodeados (subsana H-05)

## Hallazgo a subsanar

**MASTG-TEST-IDs:** 0212
**MASVS control:** MASVS-CRYPTO-2 (The app performs key management properly)
**MASWE weakness:** MASWE-0009 (Use of Hard-coded Cryptographic Key)
**Activos afectados:** ACT-01 (credenciales de cuenta), ACT-04 (configuración de backend)

**Hallazgo verificado:** MobSF v4.5.1 identificó **243 secretos hardcoded** en el binario, incluyendo:
- `google_api_key=AIzaSyDHz9JJCWU7D_ZBD2LNc-ETRp07vX4JXLM`
- `facebook_token=af15c314b4be3a173481ce6a94cacbe6`
- `firebase_database_url=https://yoosee-5d3bb.firebaseio.com`
- Bloques ASN.1 DER con material criptográfico embebido (claves privadas del fabricante)

Esto compromete directamente la infraestructura cloud del fabricante: cualquier analista con JADX puede extraer las credenciales y acceder a los servicios cloud de Yoosee.

**CVSS v3.1:** `AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` = **9.9 (Crítica)**.

## Mitigación propuesta (dos estrategias combinadas)

### Estrategia A: Secretos operacionales a Firebase Remote Config

Para secretos no sensibles que cambian con frecuencia (claves de API públicas de Firebase, endpoints), usar Firebase Remote Config. Esto evita que las claves aparezcan como literales en el binario distribuido.

**Paso 1: Configurar Remote Config en Firebase Console**
- En https://console.firebase.google.com, ir a Remote Config
- Crear los parámetros con sus valores (NO las claves secretas, solo las operacionales):
  - `firebase_database_url` = "https://yoosee-5d3bb.firebaseio.com"
  - `analytics_endpoint` = "https://api.tradplusad.com/..."
  - `cdn_base_url` = "https://cdn.yoosee.co/"

**Paso 2: Modificar `build.gradle` (módulo app)**
```gradle
android {
    defaultConfig {
        // Eliminar TODAS las constantes hardcoded de keys
        // Las keys operacionales se cargan vía Firebase Remote Config
        
        // Para keys sensibles inyectadas vía CI/CD, ver Estrategia B
        buildConfigField "String", "FIREBASE_PROJECT_ID",  "\"${System.env.FIREBASE_PROJECT_ID}\""
    }
    buildFeatures {
        buildConfig = true
    }
}

dependencies {
    implementation platform("com.google.firebase:firebase-bom:32.7.0")
    implementation "com.google.firebase:firebase-config-ktx"
    implementation "com.google.firebase:firebase-analytics-ktx"
}
```

**Paso 3: Cargar las claves en runtime**
```kotlin
package com.yoosee.config

import android.util.Log
import com.google.firebase.Firebase
import com.google.firebase.remoteconfig.FirebaseRemoteConfig
import com.google.firebase.remoteconfig.FirebaseRemoteConfigSettings

class ConfigService {

    companion object {
        private const val TAG = "ConfigService"
        private const val KEY_FIREBASE_DB_URL = "firebase_database_url"
        private const val KEY_ANALYTICS_URL = "analytics_endpoint"
        private const val KEY_CDN_URL = "cdn_base_url"
    }

    private val remoteConfig: FirebaseRemoteConfig by lazy {
        Firebase.remoteConfig.apply {
            setConfigSettingsAsync(FirebaseRemoteConfigSettings.Builder()
                .setMinimumFetchIntervalInSeconds(3600)
                .build())
        }
    }

    fun fetchConfig(onReady: (Map<String, String>) -> Unit) {
        remoteConfig.fetchAndActivate()
            .addOnCompleteListener { task ->
                if (task.isSuccessful) {
                    val config = mapOf(
                        KEY_FIREBASE_DB_URL to remoteConfig.getString(KEY_FIREBASE_DB_URL),
                        KEY_ANALYTICS_URL to remoteConfig.getString(KEY_ANALYTICS_URL),
                        KEY_CDN_URL to remoteConfig.getString(KEY_CDN_URL)
                    )
                    onReady(config)
                } else {
                    Log.w(TAG, "Remote config fetch failed; using fallback hardcoded values", task.exception)
                    onReady(FALLBACK_CONFIG)
                }
            }
    }

    companion object {
        // Solo para fallback en caso de fallo de red al primer arranque
        // Estos NO son secretos, son URLs operacionales
        private val FALLBACK_CONFIG = mapOf(
            KEY_FIREBASE_DB_URL to "https://yoosee-default.firebaseio.com",
            KEY_ANALYTICS_URL to "https://analytics.yoosee.com",
            KEY_CDN_URL to "https://cdn.yoosee.com"
        )
    }
}
```

### Estrategia B: Secretos sensibles vía CI/CD + BuildConfig

Para secretos sensibles (tokens de servicio, claves de push) que NO deben estar en Firebase, inyectar vía `BuildConfigField` desde variables de entorno del CI/CD.

**`app/build.gradle`:**
```gradle
android {
    defaultConfig {
        // Secretos sensibles inyectados desde variables de entorno del CI/CD
        // GitHub Actions: secrets.STORAGE_BUCKET_KEY, secrets.MAPBOX_TOKEN, etc.
        // El .gitignore debe excluir .env.properties
        def sensitiveProperties = new Properties()
        try {
            sensitiveProperties.load(new FileInputStream(file("../sensitive.properties")))
        } catch (Exception e) {
            // Las propiedades sensibles solo se cargan en build de release con CI
        }
        
        buildConfigField "String", "STORAGE_BUCKET_KEY",
            "\"${sensitiveProperties.getProperty('STORAGE_BUCKET_KEY', '')}\""
        buildConfigField "String", "MAPBOX_TOKEN",
            "\"${sensitiveProperties.getProperty('MAPBOX_TOKEN', '')}\""
        buildConfigField "String", "PUSH_API_KEY",
            "\"${sensitiveProperties.getProperty('PUSH_API_KEY', '')}\""
    }
    buildFeatures {
        buildConfig = true
    }
}
```

**Uso:**
```kotlin
// ANTES (vulnerable - hardcoded en el APK)
val apiKey = "AIzaSyDHz9JJCWU7D_ZBD2LNc-ETRp07vX4JXLM"

// DESPUÉS (no aparece en el APK)
val apiKey = BuildConfig.MAPS_API_KEY  // o STORAGE_BUCKET_KEY, etc.
```

**Configuración del CI/CD (GitHub Actions ejemplo):**
```yaml
# .github/workflows/android-release.yml
- name: Build release APK
  env:
    STORAGE_BUCKET_KEY: ${{ secrets.STORAGE_BUCKET_KEY }}
    MAPBOX_TOKEN: ${{ secrets.MAPBOX_TOKEN }}
    PUSH_API_KEY: ${{ secrets.PUSH_API_KEY }}
  run: |
    echo "STORAGE_BUCKET_KEY=$STORAGE_BUCKET_KEY" > ../sensitive.properties
    echo "MAPBOX_TOKEN=$MAPBOX_TOKEN" >> ../sensitive.properties
    ./gradlew assembleRelease
    rm ../sensitive.properties
```

## Verificación post-mitigación

### Verificación 1: Secretos eliminados del código fuente (MASTG-TEST-0212)

```bash
# Buscar en el código fuente
cd dast_lab
grep -rn "AIzaSyD\|firebase_database_url\|facebook_token\|MIIFMA0GCSq" \
    implementations/ scripts/
# Resultado esperado: 0 ocurrencias

# Re-decopilar y volver a buscar
jadx out/yoosee_final.apk
grep -rn "AIzaSyD\|firebase_database_url\|facebook_token" out/yoosee_final_jadx/
# Resultado esperado: 0 ocurrencias
```

### Verificación 2: MobSF Hardcoded Secrets count

```bash
# Levantar MobSF
docker run -it --rm -p 8000:8000 opensecurity/mobsf:latest

# Cargar el nuevo APK
# Verificar que la sección "Code Analysis → Possible Hardcoded Secrets"
# muestre 0 secretos detectados (o solo secretos no sensibles, < 5)
```

### Verificación 3: Variables CI/CD funcionan

```bash
# Sin las variables, el build debe fallar o usar fallback seguro
unset STORAGE_BUCKET_KEY
./gradlew assembleRelease
# El APK resultante debe tener STORAGE_BUCKET_KEY = "" (string vacío, no error)
# La app al iniciar debe detectar el string vacío y mostrar error al usuario
```

## Métrica objetivo

Tras la externalización, L05 debe pasar de **NO CUMPLE Crítica** (CVSS 9.9) a **NO CUMPLE Baja o CUMPLE** (CVSS 0.0-3.9), llevando el cumplimiento de 36% a ~45-50% (dependiendo de cuántos secretos se externalicen realmente — los ASN.1 DER son claves privadas que requieren acción legal del fabricante).
