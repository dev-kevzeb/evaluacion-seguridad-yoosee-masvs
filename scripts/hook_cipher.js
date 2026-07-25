// MASTG-TEST-0221/0232/0350 - Hook de algoritmos criptográficos rotos
// Detecta uso de DES, 3DES, RC4, Blowfish, AES/ECB, MD5, SHA-1
// Cada hook esta envuelto en try-catch para que un fallo no aborte el resto
Java.perform(function () {

    var brokenCiphers = {
        "DES": true, "DES/ECB": true, "DES/CBC": true, "DESede": true,
        "DESede/ECB": true, "3DES": true, "RC4": true, "Blowfish": true,
        "AES/ECB": true, "AES/ECB/PKCS5Padding": true, "AES/ECB/NoPadding": true
    };
    var brokenDigests = {
        "MD5": true, "MD2": true, "MD4": true, "SHA-1": true, "SHA1": true
    };

    function isBrokenCipher(t) {
        if (!t) return false;
        if (brokenCiphers[t]) return true;
        if (t === "AES") return true;  // default Java = AES/ECB/PKCS5Padding
        if (t.indexOf("/ECB") !== -1) return true;
        if (t.indexOf("DES/") === 0) return true;
        return false;
    }
    function isBrokenDigest(a) {
        return brokenDigests[a] === true;
    }

    // ===== 1) Cipher.getInstance(String) =====
    try {
        var Cipher = Java.use("javax.crypto.Cipher");
        Cipher.getInstance.overload("java.lang.String").implementation = function (transformation) {
            var t = transformation;
            if (isBrokenCipher(t)) {
                console.log("[!] BROKEN Cipher.getInstance transformation='" + t + "'");
            } else {
                console.log("[Cipher.getInstance] transformation='" + t + "'");
            }
            return this.getInstance(t);
        };
        console.log("[+] Hook Cipher.getInstance instalado");
    } catch (e) {
        console.log("[-] Error hook Cipher.getInstance: " + e);
    }

    // ===== 2) Cipher.init(int, Key) =====
    try {
        var Cipher2 = Java.use("javax.crypto.Cipher");
        Cipher2.init.overload("int", "java.security.Key").implementation = function (opmode, key) {
            var opName = (opmode === 1) ? "ENCRYPT" : (opmode === 2 ? "DECRYPT" : "mode=" + opmode);
            var algo = "<?>";
            var keyHex = "<no-encoding>";
            try {
                algo = key.getAlgorithm();
                var encoded = key.getEncoded();
                if (encoded !== null) {
                    var sb = "";
                    for (var i = 0; i < encoded.length; i++) {
                        var b = encoded[i] & 0xff;
                        sb += (b < 16 ? "0" : "") + b.toString(16);
                    }
                    keyHex = sb + " (" + (encoded.length * 8) + " bits)";
                }
            } catch (ke) { keyHex = "<error: " + ke + ">"; }
            console.log("[Cipher.init] op=" + opName + " keyAlgo=" + algo + " key=" + keyHex);
            return this.init(opmode, key);
        };
        console.log("[+] Hook Cipher.init instalado");
    } catch (e) {
        console.log("[-] Error hook Cipher.init: " + e);
    }

    // ===== 3) MessageDigest.getInstance(String) =====
    try {
        var MessageDigest = Java.use("java.security.MessageDigest");
        MessageDigest.getInstance.overload("java.lang.String").implementation = function (algorithm) {
            if (isBrokenDigest(algorithm)) {
                console.log("[!] BROKEN MessageDigest.getInstance algorithm='" + algorithm + "'");
            } else {
                console.log("[MessageDigest.getInstance] algorithm='" + algorithm + "'");
            }
            return this.getInstance(algorithm);
        };
        console.log("[+] Hook MessageDigest.getInstance instalado");
    } catch (e) {
        console.log("[-] Error hook MessageDigest.getInstance: " + e);
    }

    // ===== 4) SecretKeySpec(byte[], String) =====
    try {
        var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
        SecretKeySpec.$init.overload("[B", "java.lang.String").implementation = function (key, algorithm) {
            var keyLenBits = (key === null) ? 0 : (key.length * 8);
            var sb = "";
            if (key !== null) {
                for (var i = 0; i < key.length; i++) {
                    var b = key[i] & 0xff;
                    sb += (b < 16 ? "0" : "") + b.toString(16);
                }
            }
            console.log("[SecretKeySpec] algo='" + algorithm + "' keyLen=" + keyLenBits + " bits key=" + sb);
            return this.$init(key, algorithm);
        };
        console.log("[+] Hook SecretKeySpec instalado");
    } catch (e) {
        console.log("[-] Error hook SecretKeySpec: " + e);
    }

    // ===== 5) KeyGenerator.getInstance(String) =====
    try {
        var KeyGenerator = Java.use("javax.crypto.KeyGenerator");
        KeyGenerator.getInstance.overload("java.lang.String").implementation = function (algorithm) {
            if (algorithm === "DES" || algorithm === "DESede" || algorithm === "RC4" || algorithm === "Blowfish") {
                console.log("[!] BROKEN KeyGenerator.getInstance algorithm='" + algorithm + "'");
            } else {
                console.log("[KeyGenerator.getInstance] algorithm='" + algorithm + "'");
            }
            return this.getInstance(algorithm);
        };
        console.log("[+] Hook KeyGenerator.getInstance instalado");
    } catch (e) {
        console.log("[-] Error hook KeyGenerator.getInstance: " + e);
    }

    console.log("[+] === Hooks listos. Reproduce el flujo de login + preview en el dispositivo ===");
});
