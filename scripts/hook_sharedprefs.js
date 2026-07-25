// MASTG-TEST-0287 - Hook v3: SharedPreferences + MMKV + SQLite
// Captura persistencias de datos sensibles en runtime
Java.perform(function () {

    // ===== 1) SharedPreferences estandar =====
    var Context = Java.use("android.content.Context");
    Context.getSharedPreferences.overload("java.lang.String", "int").implementation = function (name, mode) {
        var modeName = (mode === 0) ? "MODE_PRIVATE" : (mode === 1 ? "MODE_WORLD_READABLE" : (mode === 2 ? "MODE_WORLD_WRITEABLE" : "MODE_" + mode));
        console.log("[getSharedPreferences] name='" + name + "' mode=" + modeName);
        return this.getSharedPreferences(name, mode);
    };
    var EditorImpl = Java.use("android.app.SharedPreferencesImpl$EditorImpl");

    function sensitive(k) {
        if (!k) return false;
        var kl = k.toString().toLowerCase();
        var patterns = ["token","pass","pwd","uid","did","secret","session","auth","key","user","account","email","phone","login","credential","accesstoken","refreshtoken","sn"];
        for (var i = 0; i < patterns.length; i++) {
            if (kl.indexOf(patterns[i]) !== -1) return true;
        }
        return false;
    }

    EditorImpl.putString.implementation = function (k, v) {
        var vs = (v == null) ? "<null>" : v.toString();
        if (sensitive(k)) {
            console.log("[SENSITIVE SP.putString] key='" + k + "' value='" + vs + "'");
        } else {
            console.log("[SP.putString] key='" + k + "' value='" + (vs.length > 80 ? vs.substring(0,80)+'...' : vs) + "'");
        }
        return this.putString(k, v);
    };
    EditorImpl.putInt.implementation = function (k, v) {
        if (sensitive(k)) console.log("[SENSITIVE SP.putInt] key='" + k + "' value=" + v);
        return this.putInt(k, v);
    };
    EditorImpl.putLong.implementation = function (k, v) {
        if (sensitive(k)) console.log("[SENSITIVE SP.putLong] key='" + k + "' value=" + v);
        return this.putLong(k, v);
    };
    EditorImpl.putBoolean.implementation = function (k, v) {
        if (sensitive(k)) console.log("[SENSITIVE SP.putBoolean] key='" + k + "' value=" + v);
        return this.putBoolean(k, v);
    };
    EditorImpl.putStringSet.implementation = function (k, v) {
        if (sensitive(k)) console.log("[SENSITIVE SP.putStringSet] key='" + k + "' values=" + v);
        return this.putStringSet(k, v);
    };
    EditorImpl.apply.implementation = function () { this.apply(); };
    EditorImpl.commit.implementation = function () { return this.commit(); };
    console.log("[+] Hooks SharedPreferences instalados");

    // ===== 2) MMKV - Tencent Memory-Mapped KV =====
    try {
        var MMKV = Java.use("com.tencent.mmkv.MMKV");
        console.log("[+] Clase MMKV encontrada");

        // Hook defaultMMKV()
        MMKV.defaultMMKV.overload().implementation = function () {
            var r = this.defaultMMKV();
            console.log("[MMKV.defaultMMKV] llamando");
            return r;
        };
        // Hook mmkvWithID(String mmapID)
        try {
            MMKV.mmkvWithID.overload("java.lang.String").implementation = function (id) {
                console.log("[MMKV.mmkvWithID] id='" + id + "'");
                return this.mmkvWithID(id);
            };
        } catch(e) {}
        try {
            MMKV.mmkvWithID.overload("java.lang.String", "int").implementation = function (id, mode) {
                console.log("[MMKV.mmkvWithID] id='" + id + "' mode=" + mode);
                return this.mmkvWithID(id, mode);
            };
        } catch(e) {}

        // Hook encode() para String
        try {
            MMKV.encode.overload("java.lang.String", "java.lang.String").implementation = function (k, v) {
                if (sensitive(k)) {
                    console.log("[SENSITIVE MMKV.encode(String)] key='" + k + "' value='" + v + "'");
                } else {
                    var vs = v == null ? "<null>" : v.toString();
                    console.log("[MMKV.encode(String)] key='" + k + "' value='" + (vs.length > 80 ? vs.substring(0,80)+'...' : vs) + "'");
                }
                return this.encode(k, v);
            };
        } catch(e) { console.log("[-] no encode(String,String): " + e); }

        // Hook encode() para int
        try {
            MMKV.encode.overload("java.lang.String", "int").implementation = function (k, v) {
                if (sensitive(k)) console.log("[SENSITIVE MMKV.encode(int)] key='" + k + "' value=" + v);
                return this.encode(k, v);
            };
        } catch(e) {}

        // Hook encode() para long
        try {
            MMKV.encode.overload("java.lang.String", "long").implementation = function (k, v) {
                if (sensitive(k)) console.log("[SENSITIVE MMKV.encode(long)] key='" + k + "' value=" + v);
                return this.encode(k, v);
            };
        } catch(e) {}

        // Hook encode() para boolean
        try {
            MMKV.encode.overload("java.lang.String", "boolean").implementation = function (k, v) {
                if (sensitive(k)) console.log("[SENSITIVE MMKV.encode(boolean)] key='" + k + "' value=" + v);
                return this.encode(k, v);
            };
        } catch(e) {}

        // Hook putString (alias de encode)
        try {
            MMKV.putString.overload("java.lang.String", "java.lang.String").implementation = function (k, v) {
                if (sensitive(k)) {
                    console.log("[SENSITIVE MMKV.putString] key='" + k + "' value='" + v + "'");
                } else {
                    var vs = v == null ? "<null>" : v.toString();
                    console.log("[MMKV.putString] key='" + k + "' value='" + (vs.length > 80 ? vs.substring(0,80)+'...' : vs) + "'");
                }
                return this.putString(k, v);
            };
        } catch(e) {}

        // Hook decodeString (lectura de datos sensibles)
        try {
            MMKV.decodeString.overload("java.lang.String").implementation = function (k) {
                var r = this.decodeString(k);
                if (sensitive(k)) {
                    console.log("[MMKV.decodeString] key='" + k + "' -> '" + r + "'");
                }
                return r;
            };
        } catch(e) {}
        try {
            MMKV.decodeString.overload("java.lang.String", "java.lang.String").implementation = function (k, def) {
                var r = this.decodeString(k, def);
                if (sensitive(k)) {
                    console.log("[MMKV.decodeString(def)] key='" + k + "' -> '" + r + "'");
                }
                return r;
            };
        } catch(e) {}

        console.log("[+] Hooks MMKV instalados");
    } catch (e) {
        console.log("[-] MMKV no accesible o no cargada aun: " + e);
    }

    // ===== 3) SQLite - SQLiteDatabase.execSQL / insert =====
    try {
        var SQLiteDB = Java.use("android.database.sqlite.SQLiteDatabase");
        SQLiteDB.execSQL.overload("java.lang.String").implementation = function (sql) {
            if (sql && (sql.indexOf("INSERT") !== -1 || sql.indexOf("UPDATE") !== -1 || sql.indexOf("CREATE TABLE") !== -1)) {
                var sqlShort = sql.length > 200 ? sql.substring(0,200)+'...' : sql;
                console.log("[SQLite.execSQL] " + sqlShort);
            }
            this.execSQL(sql);
        };
        SQLiteDB.execSQL.overload("java.lang.String", "[Ljava.lang.Object;").implementation = function (sql, args) {
            if (sql && (sql.indexOf("INSERT") !== -1 || sql.indexOf("UPDATE") !== -1)) {
                console.log("[SQLite.execSQL(args)] SQL=" + sql.substring(0,200) + " args=" + args);
            }
            this.execSQL(sql, args);
        };
        console.log("[+] Hooks SQLite instalados");
    } catch(e) {
        console.log("[-] SQLite hooks: " + e);
    }

    // ===== 4) Yoosee-specific SharedPreferencesManager del GWASDK =====
    try {
        var GWASharedPrefs = Java.use("com.gwell.GWASDK.utils.SharedPreferencesManager");
        console.log("[+] GWASDK.SharedPreferencesManager encontrado");
        // Listar y hookear putX setData-like methods
        var methods = GWASharedPrefs.class.getDeclaredMethods();
        for (var i = 0; i < methods.length; i++) {
            var m = methods[i];
            var mname = m.getName();
            if (mname === "put" || mname === "set" || mname === "putString" || mname === "setData" || mname === "save" || mname === "setString" || mname === "saveToken" || mname === "saveDid" || mname === "saveUid") {
                console.log("  [GWASharedPrefs metodo] " + mname + " con " + m.getParameterTypes().length + " args");
            }
        }
    } catch(e) {
        console.log("[-] GWASDK.utils.SharedPreferencesManager no disponible aun (lazy class load)");
    }

    console.log("[+] === Todos los hooks v3 instalados. Tu turno: flujo login/captura ===");
});