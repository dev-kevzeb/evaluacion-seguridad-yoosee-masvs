Java.perform(function() {
    console.log("[+] Frida gadget conectado correctamente");
    console.log("[+] Process: " + Process.id);
    console.log("[+] Arch: " + Process.arch);
    console.log("[+] Platform: " + Process.platform);

    // Contar clases cargadas con 'SharedPreferences' (validacion SAST/DAST)
    var count = 0;
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            if (className.indexOf("SharedPreferences") !== -1) {
                count++;
                if (count <= 3) {
                    console.log("  [SharedPreferences class] " + className);
                }
            }
        },
        onComplete: function() {
            console.log("[+] Clases con 'SharedPreferences' encontradas: " + count);
            // Probar hook de Log.d como sanity check
            try {
                var Log = Java.use("android.util.Log");
                console.log("[+] android.util.Log accesible: " + (Log !== null));
            } catch(e) {
                console.log("[-] Error accediendo a android.util.Log: " + e);
            }
        }
    });
});
