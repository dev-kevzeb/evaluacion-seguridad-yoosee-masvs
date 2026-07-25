// Verifica que la app confia en CA de usuario (NSC con certificates src="user")
// Lista TrustManagers activos y comprueba si las CAs de usuario son aceptadas
Java.perform(function () {
    console.log("[+] Iniciando verificacion de TrustManagers en com.yoosee");

    // 1) Mostrar NSC configurada en el manifest
    try {
        var ctx = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext();
        var pm = ctx.getPackageManager();
        var pkgInfo = pm.getPackageInfo("com.yoosee", 0);
        var appInfo = pkgInfo.applicationInfo.value;
        var nscResId = appInfo.networkSecurityConfigRes.value;
        console.log("[+] networkSecurityConfigRes = " + nscResId);
        if (nscResId !== 0) {
            console.log("    La app tiene NSC declarada (resId=" + nscResId + ")");
        } else {
            console.log("    La app NO tiene NSC declarada (usa defaults del sistema)");
        }
    } catch (e) {
        console.log("[-] Error leyendo manifest: " + e);
    }

    // 2) Hook TrustManagerFactory.getInstance para ver que proveedores se usan
    try {
        var TMF = Java.use("javax.net.ssl.TrustManagerFactory");
        TMF.getInstance.overload("java.lang.String").implementation = function (algorithm) {
            console.log("[TrustManagerFactory.getInstance] algorithm=" + algorithm);
            return this.getInstance(algorithm);
        };
        TMF.getInstance.overload("java.lang.String", "java.lang.String").implementation = function (algorithm, provider) {
            console.log("[TrustManagerFactory.getInstance] algorithm=" + algorithm + " provider=" + provider);
            return this.getInstance(algorithm, provider);
        };
        console.log("[+] Hook TrustManagerFactory.getInstance instalado");
    } catch (e) {
        console.log("[-] Error hookeando TrustManagerFactory: " + e);
    }

    // 3) Hook SSLContext.init para ver que TrustManagers se pasan
    try {
        var SSLContext = Java.use("javax.net.ssl.SSLContext");
        SSLContext.init.overload(
            "[Ljavax.net.ssl.KeyManager;",
            "[Ljavax.net.ssl.TrustManager;",
            "java.security.SecureRandom"
        ).implementation = function (km, tm, sr) {
            if (tm !== null) {
                for (var i = 0; i < tm.length; i++) {
                    console.log("[SSLContext.init] TrustManager[" + i + "] = " + tm[i].getClass().getName());
                }
            } else {
                console.log("[SSLContext.init] TrustManagers NULL (usa defaults)");
            }
            return this.init(km, tm, sr);
        };
        console.log("[+] Hook SSLContext.init instalado");
    } catch (e) {
        console.log("[-] Error hookeando SSLContext.init: " + e);
    }

    // 4) Hook CertPathValidator para detectar validaciones
    try {
        var CPV = Java.use("java.security.cert.CertPathValidator");
        CPV.getInstance.overload("java.lang.String").implementation = function (algorithm) {
            console.log("[CertPathValidator.getInstance] algorithm=" + algorithm);
            return this.getInstance(algorithm);
        };
        console.log("[+] Hook CertPathValidator.getInstance instalado");
    } catch (e) {
        console.log("[-] Error hookeando CertPathValidator: " + e);
    }

    console.log("[+] Hooks instalados. Realiza trafico HTTPS en la app (login,preview,captura)");
    console.log("[+] Si observas 'TrustManager com.android.org.conscrypt.TrustManagerImpl' -> usa defaults del sistema");
    console.log("[+] Si observas X509TrustManager custom o空的 checkServerTrusted -> bypass detectado");
});