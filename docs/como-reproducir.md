# Cómo Reproducir la Auditoría

> Monografía: *"Evaluación de seguridad de la aplicación móvil Yoosee para cámaras de videovigilancia marca Tomate mediante el estándar OWASP MASVS"*
> Autor: Wally Kevin Zeballos Oquendo · UMSS · 2026

Esta guía explica cómo replicar la auditoría de Yoosee v6.44.1 sobre el mismo binario (o sobre otra app móvil IoT equivalente) usando las herramientas y scripts de este repositorio.

## Requisitos

### Hardware
- Host con **Windows 10/11** (o Linux/macOS) con mínimo **16 GB RAM** y **50 GB de disco libre**
- **Dispositivo físico Android 7+** (se recomienda 10+). Probado con **Poco X5 5G con Android 14**.
- Cable USB para conectar el dispositivo al host.

### Software

| Herramienta | Versión usada | Instalación |
|---|---|---|
| Python | 3.10+ | https://www.python.org/ |
| Frida | 17.16.3 | `pip install frida-tools frida==17.16.3` |
| JADX-GUI | 1.5.6 | https://github.com/skylot/jadx/releases |
| MobSF | v4.5.1 | Docker: `docker run -it --rm -p 8000:8000 opensecurity/mobsf:latest` |
| Burp Suite | Community | https://portswigger.net/burp/communitydownload |
| Android SDK Platform-Tools | última | https://developer.android.com/studio/releases/platform-tools |
| openssl | 1.1+ | (viene con Git for Windows) |
| PowerShell | 5.1+ | (viene con Windows 10/11) |
| WSL2 | última | (viene con Windows 10/11) |
| Docker Desktop | última | https://www.docker.com/products/docker-desktop/ |

### Opcionales
- **Git for Windows** (incluye openssl en `C:\Program Files\Git\usr\bin\`)
- **objection** (wrapper de Frida): `pip install objection`

## Procedimiento paso a paso

### Paso 0: Extraer el APK de Yoosee del dispositivo

```powershell
# Habilitar depuración USB en el dispositivo
# Ajustes > Acerca del teléfono > tocar 7 veces "Número de compilación"
# Ajustes > Opciones de desarrollador > activar "Depuración USB"
# Conectar por USB y autorizar la depuración

# Verificar conexión
adb devices

# Extraer el APK del dispositivo (asumiendo com.yoosee instalado)
adb -s <device_serial> shell pm path com.yoosee
# Devuelve: package:/data/app/~~XXX==/com.yoosee-YYY==/base.apk

adb -s <device_serial> pull /data/app/~~XXX==/com.yoosee-YYY==/base.apk original.apk
```

### Paso 1: Análisis estático con MobSF

```powershell
# Iniciar MobSF
docker run -it --rm -p 8000:8000 opensecurity/mobsf:latest

# Abrir http://localhost:8000 en el navegador
# Login: mobsf / mobsf
# Subir original.apk
# Esperar el análisis (1-3 minutos)
# Revisar el reporte:
#   - Security Score: 40/100 (línea base)
#   - Signer Certificate: SHA1withRSA 1024 bits
#   - Hardcoded Secrets: 243 secretos
#   - Network Security: cleartext habilitado
```

### Paso 2: Análisis estático manual con JADX-GUI

```powershell
# Abrir JADX-GUI
jadx-gui

# File > Open File > seleccionar original.apk
# Esperar la decompilación (1-3 minutos para APKs grandes)

# Navegar el árbol de paquetes
#   com.gwell.  → SDK del fabricante
#   com.mbridge.  → MBridge SDK (cifrado roto)
#   com.tradplus.  → TradPlus SDK (cifrado roto)
#   com.alipay.  → Alipay SDK
#   com.huawei.  → Huawei Mobile Services

# Búsquedas globales con Ctrl+Shift+F:
#   "http://"      → 91 URLs hardcoded (L09)
#   "SSLContext"   → llamadas TLS (L11)
#   "MessageDigest.getInstance" → algoritmos hash (L07)
#   "getSharedPreferences" → persistencia (L01)
#   "Environment.getExternalStorage" → ext storage (L02)
```

### Paso 3: Preparar el APK parcheado con Frida Gadget

```powershell
# 1. Reempaquetar los splits del App Bundle en un APK monolítico
java -Xmx4g -jar tools/APKEditor.jar m -i merge_src/ -o out/yoosee_merged.apk

# 2. Inyectar el Frida Gadget
objection patchapk -s out/yoosee_merged.apk -a arm64 -V 17.16.3 -N

# 3. Corregir la ruta del gadget a arm64-v8a (bug de objection con arm64)
# (ver implementations/L08_nsc_cleartext/README.md para el script de corrección)

# 4. Firmar el APK con el keystore de debug
keytool -genkeypair -v -keystore tools/debug.keystore \
    -storepass android -alias androiddebugkey -keypass android \
    -keyalg RSA -keysize 2048 -validity 10000 \
    -dname "CN=Android Debug,O=Android,C=US"
$ANDROID_HOME/build-tools/36.0.0/apksigner sign \
    --ks tools/debug.keystore --ks-pass pass:android \
    --key-pass pass:android \
    --out out/yoosee_patched.apk out/yoosee_patched_aligned.apk

# 5. Instalar
adb -s <device_serial> uninstall com.yoosee
adb -s <device_serial> install -r out/yoosee_patched.apk
```

### Paso 4: Análisis dinámico con Frida

```powershell
# 1. Configurar Burp Suite
# Proxy > Proxy settings > Edit > Bind to address: All interfaces, Port: 8080
# Importar CA de Burp en el dispositivo
adb -s <device_serial> shell "settings put global http_proxy 192.168.0.7:8080"

# 2. Lanzar Yoosee (queda pausada en el logo por frida-gadget on_load: wait)
adb -s <device_serial> shell monkey -p com.yoosee -c android.intent.category.LAUNCHER 1

# 3. Adjuntar Frida con el script de L01
cd scripts
frida -U -n Gadget -l hook_sharedprefs.js

# 4. En el dispositivo, hacer el flujo de login
#    (la app se reanuda automáticamente al adjuntar Frida)

# 5. En la consola de Frida, ver las escrituras [SENSITIVE SP.putString]
#    Estas son las credenciales capturadas (luego anonimizar)
```

### Paso 5: Análisis de URLs HTTP (L09)

```powershell
# Ejecutar el script extractor
cd dast_lab
python scripts/extract_http_urls.py original.apk > analysis_output/http_urls.txt

# Revisar
type analysis_output/http_urls.txt

# Categorizar manualmente (ver el README de L09)
# - Cloudlinks internos → migrar a HTTPS
# - SDKs de terceros → evaluar remoción
# - PII hardcoded → eliminar del código
```

### Paso 6: Verificación TLS (L10)

```powershell
# Ejecutar el verificador de versiones TLS
powershell -ExecutionPolicy Bypass -File scripts/check_tls_versions.ps1

# Resultado esperado: 0 endpoints aceptan TLS 1.0/1.1
# 9/11 aceptan TLS 1.2
# 0/11 aceptan TLS 1.3
```

## Tiempo total estimado

- Extracción del APK: 5 min
- Análisis MobSF: 15 min
- Análisis JADX manual: 2-4 horas
- Patching del APK: 30 min
- Sesión Frida + login: 30 min
- Análisis de URLs: 5 min
- Verificación TLS: 2 min
- Análisis de cadena TLS: 30 min
- Documentación de hallazgos: 2-3 horas

**Total: ~6-9 horas de trabajo activo**, distribuibles en 1-2 días.

## Limitaciones y consideraciones

1. **El dispositivo debe estar rooteado** solo si se quiere ejecutar `frida-server` directamente. El método `objection patchapk` permite evitar root.
2. **Los APKs pueden ser muy grandes** (Yoosee v6.44.1 = 123 MB). La decompilación en JADX puede tardar varios minutos.
3. **El análisis es destructivo en algunos casos** (e.g., `am crash com.yoosee` para forzar un crash que dispare Bugly). Hacer un snapshot del dispositivo antes.
4. **PII en los outputs**: anonimizar antes de compartir o publicar (ver guía de privacidad en README.md raíz).
