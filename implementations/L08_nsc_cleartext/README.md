# L08 — Deshabilitar Tráfico en Claro (subsana H-08)

## Hallazgo a subsanar

**MASTG-TEST-IDs:** 0235 + 0236
**MASVS control:** MASVS-NETWORK-1 (The app secures all network traffic)
**MASWE weakness:** MASWE-0004 (Cleartext Transmission of Sensitive Information)
**Activos afectados:** ACT-01 (credenciales), ACT-02 (tokens), ACT-03 (video)

**Hallazgo verificado:** el `AndroidManifest.xml` declara `android:usesCleartextTraffic="true"`, anulando la protección por defecto de Android contra tráfico HTTP. La Network Security Configuration declara `cleartextTrafficPermitted="true"` específicamente para `android.bugly.qq.com` (SDK Bugly de Tencent). En la sesión DAST con Burp, los 16 endpoints de Yoosee negociaron TLS 1.2 ECDHE correctamente (Bugly eligió HTTPS en runtime), pero la vulnerabilidad de configuración es real y latente: cualquier release futura o regresión podría exponer tráfico en claro.

**CVSS v3.1:** `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N` = **7.4 (Alta)**.

## Mitigación propuesta (2 cambios)

### Cambio 1: Modificar AndroidManifest.xml

**`app/src/main/AndroidManifest.xml`:**
```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.yoosee">

    <application
        android:allowBackup="false"
        android:icon="@mipmap/ic_launcher"
        android:label="@string/app_name"
        android:networkSecurityConfig="@xml/network_security_config"
        android:usesCleartextTraffic="false"
        ...>

        <!-- Activities, services, etc. -->
    </application>
</manifest>
```

**Cambio crítico:** `android:usesCleartextTraffic="false"` (era `"true"`).

### Cambio 2: Reescribir res/xml/network_security_config.xml

**`app/src/main/res/xml/network_security_config.xml`:**
```xml
<?xml version="1.0" encoding="utf-8"?>
<!--
  Network Security Configuration restrictiva para Yoosee v6.44.2+

  Decisiones:
  - base-config: cleartext PROHIBIDO globalmente (false)
  - trust-anchors: solo CAs del sistema (system); NO CAs de usuario
  - Sin domain-config con cleartextTrafficPermitted=true
  - Bugly SDK (Tencent) DEBE migrar a HTTPS; si no puede, el parche de L08 es parcial.
-->
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system"/>
            <!-- No se incluye <certificates src="user"/> para evitar MitM con CAs instaladas -->
        </trust-anchors>
    </base-config>

    <!-- Si Bugly u otro SDK requiere diagnóstico por HTTP, migrarlo a HTTPS -->
    <!-- y NO crear excepciones de dominio para cleartext -->

    <!-- Opcional: pinning de los endpoints core (defense-in-depth) -->
    <!--
    <domain-config>
        <domain includeSubdomains="true">openapi-iot.cloudlinks.cn</domain>
        <pin-set expiration="2027-12-31">
            <pin digest="SHA-256">AAAA...SHA256_DEL_CERT_DE_PRODUCCION</pin>
            <pin digest="SHA-256">BBBB...SHA256_DEL_CERT_DE_BACKUP</pin>
        </pin-set>
    </domain-config>
    <domain-config>
        <domain includeSubdomains="true">api1.cloudlinks.cn</domain>
        <pin-set expiration="2027-12-31">
            <pin digest="SHA-256">CCCC...SHA256</pin>
        </pin-set>
    </domain-config>
    -->
</network-security-config>
```

### Verificación con código de los SDKs

**Si Bugly SDK se queja de no poder usar HTTP para diagnóstico, forzar HTTPS en el SDK:**

**`BuglyConfig.kt`:**
```kotlin
package com.yoosee.crash

import android.content.Context
import com.tencent.bugly.crashreport.CrashReport
import com.tencent.bugly.crashreport.CrashReport.UserStrategy

class BuglyConfig(private val context: Context) {
    fun init() {
        val strategy = UserStrategy(context).apply {
            // Forzar HTTPS para el reporte de crashes
            httpScheme = "https"  // Bugly soporta https desde 2019
            // No habilitar modo de debug que usa HTTP
            isUploadProcess = true
        }
        CrashReport.initCrashReport(context, "YOUR_BUGLY_APP_ID", strategy)
    }
}
```

## Verificación post-mitigación

### Verificación 1: SAST del manifiesto (MASTG-TEST-0235)

```bash
# Decompilar el nuevo APK
cd dast_lab
jadx out/yoosee_v2.apk

# Buscar en el manifest
grep -A 1 "usesCleartextTraffic" resources/AndroidManifest.xml
# Resultado esperado: usesCleartextTraffic="false"
# (antes era "true")

grep -A 5 "network-security-config" resources/AndroidManifest.xml
# Resultado esperado: android:networkSecurityConfig="@xml/network_security_config"
```

### Verificación 2: Inspección de la NSC (MASTG-TEST-0235)

```bash
# Verificar la NSC descompilada
cat resources/res/xml/network_security_config.xml
# Resultado esperado: <base-config cleartextTrafficPermitted="false">
#                    <trust-anchors><certificates src="system"/></trust-anchors>
# Sin <domain-config> con cleartextTrafficPermitted="true"
```

### Verificación 3: DAST runtime con Burp (MASTG-TEST-0236)

```bash
# 1. Asegurarse de que Burp está corriendo y la CA instalada (ver §2.2.5 del Cap II)
# 2. Lanzar el nuevo APK parcheado
adb install -r out/yoosee_v2.apk
adb shell monkey -p com.yoosee -c android.intent.category.LAUNCHER 1

# 3. En Burp: Proxy > HTTP history
# 4. Filtrar: protocol:http
# Resultado esperado: 0 peticiones http:// originadas por Yoosee
# (pueden aparecer peticiones del sistema operativo como connectivitycheck.gstatic.com,
# que son del sistema, no de la app)
```

### Verificación 4: Tráfico real con Wireshark o tcpdump

```bash
# Capturar todo el tráfico durante el flujo
adb shell tcpdump -i any -w /sdcard/capture.pcap &
# Realizar el flujo de login + preview
# Detener la captura
adb pull /sdcard/capture.pcap /tmp/

# Analizar con Wireshark
wireshark /tmp/capture.pcap
# Filtro: http && ip.src == 192.168.0.4  # la IP del Poco X5
# Resultado esperado: 0 paquetes HTTP originados por Yoosee
```

## Métrica objetivo

Tras la modificación, L08 debe pasar de **NO CUMPLE Alta** (CVSS 7.4) a **CUMPLE** (CVSS 0.0), llevando el cumplimiento de 36% a ~50%.
