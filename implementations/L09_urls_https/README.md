# L09 — Migración de URLs Hardcoded a HTTPS (subsana H-09)

## Hallazgo a subsanar

**MASTG-TEST-IDs:** 0233
**MASVS control:** MASVS-NETWORK-1 (The app secures all network traffic)
**MASWE weakness:** MASWE-0004 (Cleartext Transmission of Sensitive Information)
**Activos afectados:** ACT-01 (credenciales), ACT-04 (cámaras y backends)

**Hallazgo verificado:** el script `scripts/extract_http_urls.py` extrajo **91 URLs `http://`** del binario `base.apk` de Yoosee v6.44.1. De esas, **52 son endpoints reales** distribuidos en:

- **16 endpoints de Cloudlinks** (api1, api2, api3-cloud-links, api4-cloud-links, customersystem)
  - 4 son de **recuperación de contraseña en claro**: `Password/CheckPhoneVKey.ashx`, `Password/GetAccountByEmail.ashx`, `Password/GetAccountByPhoneNO.ashx`, `Password/ResetPWD.ashx`
- **6 endpoints Bugly/Tencent** (uc.api.china-m2m.com, china-m2m.com, 4 dominios zztfly.com)
- **4 endpoints Alipay** (mclient.alipay.com x3, wappaygw.alipay.com)
- **2 URLs de `share.yoosee.co`** con **PII hardcoded** (nombre real `蔡志勇`, `DeviceID=<DEVICE_ID>`, `ExpireTime=<EXPIRE_TS>`)
- **14 subdominios de Applovin** (red de anuncios)
- **1 endpoint LAN** (`http://192.168.1.222/Alarm/AlarmRecordEx.ashx`)
- Otros: Vungle, Weimob, Pangle, Applovin

**El listado completo está en `scripts/http_urls_originales.txt` (anonimizado).**

**CVSS v3.1:** `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N` = **5.3 (Media)**.

## Mitigación propuesta (3 acciones)

### Acción 1: Migrar las URLs internas de Cloudlinks y Alipay a HTTPS

Todos los endpoints de Cloudlinks (`api1.cloudlinks.cn`, `api2.cloudlinks.cn`, `api3.cloud-links.net`, `api4.cloud-links.net`, `customersystem.cloudlinks.cn`, `share.yoosee.co`) y Alipay (`mclient.alipay.com`, `wappaygw.alipay.com`) tienen soporte HTTPS según se verificó en §2.5.10 (TLS 1.2 ECDHE). Solo hay que cambiar el esquema de las URLs hardcoded.

**Migración de URLs (ejemplo de grep y reemplazo):**
```bash
# Buscar todas las ocurrencias
cd dast_lab
grep -rn '"http://api1.cloudlinks.cn' out/yoosee_v2_jadx/
grep -rn '"http://mclient.alipay.com' out/yoosee_v2_jadx/
grep -rn '"http://share.yoosee.co' out/yoosee_v2_jadx/

# Reemplazar sistemáticamente http:// por https:// para los dominios internos
# (NO reemplazar http://192.168.1.222 — es una IP LAN, no se cifra con TLS)
# (NO reemplazar http://connectivitycheck.gstatic.com — es del SO, no de la app)
```

**Estrategia de código recomendada — centralizar URLs en una constante:**

**`ApiEndpoints.kt`:**
```kotlin
package com.yoosee.network

/**
 * Endpoints centralizados de Yoosee. Todos en HTTPS.
 * Cualquier URL hardcoded en otras clases debe ser refactorizada
 * para usar estas constantes.
 */
object ApiEndpoints {
    
    // Cloudlinks (fabricante Gwell)
    const val CLOUDLINKS_API_1 = "https://api1.cloudlinks.cn"
    const val CLOUDLINKS_API_2 = "https://api2.cloudlinks.cn"
    const val CLOUDLINKS_API_3 = "https://api3.cloud-links.net"
    const val CLOUDLINKS_API_4 = "https://api4.cloud-links.net"
    const val CLOUDLINKS_DSASINK = "https://datasink.cloudlinks.cn"
    const val CLOUDLINKS_SAAS_PLAYBACK = "https://saas-playback.cloudlinks.cn"
    const val CLOUDLINKS_OPENAPI_IOT = "https://openapi-iot.cloudlinks.cn"
    const val CLOUDLINKS_CUSTOMER = "https://customservicesystem.cloudlinks.cn"
    const val CLOUDLINKS_TRADE = "https://trade.cloudlinks.cn"
    
    // Password recovery (los 4 endpoints sensibles)
    const val PASSWORD_RECOVERY_CHECK_PHONE = "$CLOUDLINKS_API_1/Password/CheckPhoneVKey.ashx"
    const val PASSWORD_RECOVERY_GET_BY_EMAIL = "$CLOUDLINKS_API_1/Password/GetAccountByEmail.ashx"
    const val PASSWORD_RECOVERY_GET_BY_PHONE = "$CLOUDLINKS_API_1/Password/GetAccountByPhoneNO.ashx"
    const val PASSWORD_RECOVERY_RESET = "$CLOUDLINKS_API_1/Password/ResetPWD.ashx"
    
    // Alipay (pagos)
    const val ALIPAY_MOBILE_CASHIER = "https://mclient.alipay.com/cashier/mobilepay.htm"
    const val ALIPAY_MOBILE_INTERFACE = "https://mclient.alipay.com/home/exterfaceAssign.htm"
    const val ALIPAY_MOBILE_SERVICE = "https://mclient.alipay.com/service/rest.htm"
    const val ALIPAY_WEB_SERVICE = "https://wappaygw.alipay.com/service/rest.htm"
    
    // Web del fabricante
    const val WEBSITE = "https://www.yoosee.co/index.html"
    const val SHARE_BASE = "https://share.yoosee.co/share/"
    
    // Endpoint LAN (intencionalmente HTTP, es una IP local)
    const val LAN_ALARM_SERVER = "http://192.168.1.222/Alarm/AlarmRecordEx.ashx"
}
```

### Acción 2: Eliminar las 2 URLs de `share.yoosee.co` con PII hardcoded

Las dos URLs detectadas son:
```
http://share.yoosee.co/share/?Type=2&InviteCode=<INVITE_CODE>&SharerName=蔡志勇&AppVersion=3014729&DeviceID=<DEVICE_ID>&Permission=1&ExpireTime=<EXPIRE_TS>
http://share.yoosee.co/share/?Type=2&InviteCode=<INVITE_CODE>&SharerName=<SHARER_ID>&AppVersion=3014729&DeviceID=<DEVICE_ID>&Permission=1&ExpireTime=<EXPIRE_TS>
```

**Causa raíz:** un tester del fabricante dejó credenciales de prueba en el código de producción. El `SharerName` es el nombre de un usuario real (en chino o numérico) y el `DeviceID` es de un dispositivo de prueba.

**Solución:** eliminar estas URLs del APK. El equipo de desarrollo del fabricante debe:

1. **Borrar los literales** del código fuente (probablemente en `ShareActivity.kt` o `ShareManager.java`).
2. **Generar las URLs en runtime** con datos del usuario actual:
   ```kotlin
   // ShareActivity.kt
   fun buildShareUrl(inviteCode: String, sharerName: String, appVersion: Int, deviceId: String): String {
       val params = buildString {
           append("?Type=2")
           append("&InviteCode=$inviteCode")
           append("&SharerName=${URLEncoder.encode(sharerName, "UTF-8")}")
           append("&AppVersion=$appVersion")
           append("&DeviceID=$deviceId")
           append("&Permission=1")
           // ExpireTime se genera en runtime con +30 días
           val expire = System.currentTimeMillis() / 1000 + 30L * 24 * 3600
           append("&ExpireTime=$expire")
       }
       return ApiEndpoints.SHARE_BASE + params
   }
   ```
3. **Implementar code review** obligatorio que prohíba literales con datos personales en builds de release.

### Acción 3: Migrar las URLs de SDKs de terceros

Los SDKs de Applovin, Vungle, Pangle tienen sus propios endpoints. Si usan HTTP, **migrar a HTTPS** o, si no ofrecen HTTPS, **remover el SDK**.

**Estrategia de remoción selectiva:**
- `Applovin` (14 subdominios HTTP): red de anuncios. Si el fabricante no monetiza activamente con Applovin, **remover el SDK** completo. Sus funciones son de mediación publicitaria, no críticas para una app de cámara IoT.
- `Vungle`, `Pangle`, `Weimob`:同样是 SDKs de ads/analytics. Evaluar caso por caso.

## Verificación post-mitigación

### Verificación 1: Conteo de URLs HTTP internas (MASTG-TEST-0233)

```bash
# Re-ejecutar el script
cd dast_lab
python scripts/extract_http_urls.py out/yoosee_v2.apk > out_v2/http_urls_v2.txt

# Contar
wc -l out_v2/http_urls_v2.txt
# Resultado esperado: << 52 (idealmente ≤ 10, solo las inevitables)

# Listar las URLs reales (no falsos positivos)
grep -v "schemas\|www.w3\|xmlns\|whatwg\|ns.adobe\|tizen\|crbug\|hostname\|localhost\|example\|clips" \
    out_v2/http_urls_v2.txt
# Resultado esperado: solo los inevitables (Applovin si se mantiene, LAN alarm, posiblemente otros SDKs)
```

### Verificación 2: Verificación específica de Cloudlinks y Alipay

```bash
# Buscar URLs internas en claro (deben ser 0)
grep -E "http://(api[1-4]\.cloudlinks\.cn|api[1-4]\.cloud-links\.net|saas-playback\.cloudlinks\.cn|datasink\.cloudlinks\.cn|openapi-iot\.cloudlinks\.cn|customservicesystem\.cloudlinks\.cn|trade\.cloudlinks\.cn|mclient\.alipay\.com|wappaygw\.alipay\.com|share\.yoosee\.co|www\.yoosee\.co)" \
    out/yoosee_v2_jadx/
# Resultado esperado: 0 ocurrencias
```

### Verificación 3: Verificación de ausencia de PII hardcoded

```bash
# Buscar los nombres PII conocidos
grep -rE "蔡志勇|<SHARER_ID>|<DEVICE_ID>|<INVITE_CODE>" \
    out/yoosee_v2_jadx/
# Resultado esperado: 0 ocurrencias
```

## Métrica objetivo

Tras la migración, L09 debe pasar de **NO CUMPLE Media** (CVSS 5.3) a **CUMPLE** (CVSS 0.0) si se migran todos los endpoints internos y se eliminan las URLs con PII. Si los SDKs de Applovin/Vungle/Pangle no se pueden migrar ni remover, el cumplimiento es parcial: el lineamiento queda como **CUMPLE PARCIAL** con CVSS residual ~2.0 (low). El cumplimiento consolidado subiría de 36% a ~50-55%.
