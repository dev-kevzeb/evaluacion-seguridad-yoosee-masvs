# L02 — Scoped Storage (subsana H-03)

## Hallazgo a subsanar

**MASTG-TEST-IDs:** 0200 + 0202
**MASVS control:** MASVS-STORAGE-2 (The app prevents leakage of sensitive data outside the app container)
**Activos afectados:** ACT-04 (cámaras), ACT-05 (capturas)

**Hallazgo verificado:** el `AndroidManifest.xml` declara los permisos `android.permission.READ_EXTERNAL_STORAGE` y `android.permission.MOUNT_UNMOUNT_FILESYSTEMS`, y la búsqueda JADX confirmó invocaciones a `Environment.getExternalStorageDirectory()` que exponen el sandbox a fuga de datos a almacenamiento externo compartido. Una app maliciosa con el permiso `READ_EXTERNAL_STORAGE` puede leer las capturas de vídeo que Yoosee guardó en `/sdcard/`.

**CVSS v3.1:** `AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` = **6.5 (Media-Alta)**.

## Mitigación propuesta

Adoptar **Scoped Storage** (Android 10+) usando `MediaStore` con `RELATIVE_PATH`, que aísla los archivos de la app en un sandbox visible para el usuario pero inaccesible a otras apps sin el permiso restringido `MANAGE_EXTERNAL_STORAGE`. Eliminar los permisos `WRITE_EXTERNAL_STORAGE` y `MOUNT_UNMOUNT_FILESYSTEMS` del manifiesto.

### Paso 1: Limpiar el AndroidManifest.xml

**Diff en `app/src/main/AndroidManifest.xml`:**
```xml
<!-- ANTES (vulnerable) -->
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"
                 android:maxSdkVersion="32" />
<uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"
                 android:maxSdkVersion="29" />
<uses-permission android:name="android.permission.MOUNT_UNMOUNT_FILESYSTEMS" />

<!-- DESPUÉS (Scoped Storage) -->
<!-- Eliminar los 3 permisos. Android 10+ usa MediaStore con RELATIVE_PATH, sin permisos. -->
<!-- Para Android 9 y anteriores, mantener READ_EXTERNAL_STORAGE pero SOLO con maxSdkVersion="28" -->
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"
                 android:maxSdkVersion="28" />
```

### Paso 2: Sustituir Environment.getExternalStorageDirectory() por MediaStore o sandbox privado

**`CaptureRepository.kt`:**
```kotlin
package com.yoosee.storage

import android.content.ContentValues
import android.content.Context
import android.graphics.Bitmap
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import java.io.File

class CaptureRepository(private val context: Context) {

    /**
     * Guarda una captura (frame del preview de cámara) en el almacenamiento
     * de la app, sin permisos externos.
     * 
     * Opción A (recomendada): sandbox privado en /data/data/com.yoosee/files/.
     * Las capturas sólo son accesibles por la propia app; si el dispositivo
     * está rooteado, el atacante aún puede accederlas, pero ninguna app
     * de terceros (sin root) puede leerlas.
     */
    fun saveToAppSandbox(bitmap: Bitmap, captureId: Long): File {
        val capturesDir = File(context.filesDir, "captures").apply { mkdirs() }
        val file = File(capturesDir, "capture_${captureId}.jpg")
        file.outputStream().use { os ->
            bitmap.compress(Bitmap.CompressFormat.JPEG, 90, os)
        }
        return file
    }

    /**
     * Opción B: guarda en MediaStore (visible para el usuario en la app
     * "Galería" pero aislado del acceso de otras apps).
     * Requiere API 29+ (Android 10+).
     */
    fun saveToMediaStore(bitmap: Bitmap, displayName: String): Uri? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            // Para Android 9 y anteriores, fallback al sandbox privado
            return null
        }

        val resolver = context.contentResolver
        val values = ContentValues().apply {
            put(MediaStore.Images.Media.DISPLAY_NAME, displayName)
            put(MediaStore.Images.Media.MIME_TYPE, "image/jpeg")
            put(MediaStore.Images.Media.RELATIVE_PATH, "Pictures/Yoosee")
            put(MediaStore.Images.Media.IS_PENDING, 1)
        }

        val uri = resolver.insert(MediaStore.Images.Media.EXTERNAL_CONTENT_URI, values)
            ?: return null

        try {
            resolver.openOutputStream(uri)?.use { os ->
                bitmap.compress(Bitmap.CompressFormat.JPEG, 90, os)
            }
            values.clear()
            values.put(MediaStore.Images.Media.IS_PENDING, 0)
            resolver.update(uri, values, null, null)
        } catch (e: Exception) {
            resolver.delete(uri, null, null)
            throw e
        }
        return uri
    }
}
```

### Paso 3: Migrar la lectura de capturas existentes

**`GalleryFragment.kt`:**
```kotlin
// ANTES (vulnerable en Android 10+)
val capturesDir = File(
    Environment.getExternalStorageDirectory(),
    "DCIM/Yoosee"
)
val files = capturesDir.listFiles { f -> f.extension == "jpg" }

// DESPUÉS (Scoped Storage)
private val projection = registerForActivityResult(
    ActivityResultContracts.RequestPermission()
) { /* handle */ }

private fun loadCaptures() {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
        // Android 10+: usar MediaStore directamente, sin permisos
        val projection = arrayOf(
            MediaStore.Images.Media._ID,
            MediaStore.Images.Media.DISPLAY_NAME,
            MediaStore.Images.Media.RELATIVE_PATH
        )
        val selection = "${MediaStore.Images.Media.RELATIVE_PATH} LIKE ?"
        val selectionArgs = arrayOf("Pictures/Yoosee%")
        context.contentResolver.query(
            MediaStore.Images.Media.EXTERNAL_CONTENT_URI,
            projection, selection, selectionArgs,
            "${MediaStore.Images.Media.DATE_ADDED} DESC"
        )?.use { cursor ->
            while (cursor.moveToNext()) {
                val id = cursor.getLong(0)
                val uri = ContentUris.withAppendedId(MediaStore.Images.Media.EXTERNAL_CONTENT_URI, id)
                // procesar uri...
            }
        }
    } else {
        // Android 9 y anteriores: usar getExternalStoragePublicDirectory
        // con WRITE_EXTERNAL_STORAGE (degradación graceful)
        // ...
    }
}
```

## Verificación post-mitigación

### Verificación 1: Permisos removidos del manifiesto (MASTG-TEST-0200)

```bash
# Decompilar el nuevo APK
cd dast_lab
jadx-gui out/yoosee_final.apk  # o apktool

# Buscar permisos
grep -E "READ_EXTERNAL_STORAGE|WRITE_EXTERNAL_STORAGE|MOUNT_UNMOUNT" \
    resources/AndroidManifest.xml
# Resultado esperado: 0 ocurrencias de WRITE_EXTERNAL_STORAGE y MOUNT_UNMOUNT_FILESYSTEMS
# (READ_EXTERNAL_STORAGE solo con maxSdkVersion="28" si se mantiene para Android 9)
```

### Verificación 2: Capturas en sandbox (MASTG-TEST-0202)

```bash
# Tras tomar una captura, verificar que está en el sandbox privado
adb shell "run-as com.yoosee ls -la files/captures/"
# Resultado esperado: archivos .jpg en /data/data/com.yoosee/files/captures/

# Verificar que NO hay archivos en /sdcard
adb shell "ls -la /sdcard/DCIM/Yoosee/ 2>/dev/null"
# Resultado esperado: "No such file or directory" (ya no se escribe en /sdcard)

# Intentar acceder desde otra app con READ_EXTERNAL_STORAGE
adb shell pm grant com.example.malicious android.permission.READ_EXTERNAL_STORAGE
adb shell "content query --uri content://media/external/images/media \
    --projection _id:_display_name --where \"_data LIKE '%/Yoosee%'\""
# Resultado esperado: 0 filas (las capturas no son visibles para otras apps)
```

## Métrica objetivo

Tras la migración a Scoped Storage, L02 debe pasar de **NO CUMPLE** (CVSS 6.5) a **CUMPLE / SATISFACTORIO** (CVSS 0.0), llevando el cumplimiento de 36% a ~45%.
