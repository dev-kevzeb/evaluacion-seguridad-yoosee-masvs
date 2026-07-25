"""Frida attach with Java runtime enabled"""
import frida, sys, time

def on_message(msg, data):
    if msg['type'] == 'send':
        print(msg['payload'])
    elif msg['type'] == 'error':
        print('[ERROR]', msg['stack'])

# Attach with Java runtime
device = frida.get_usb_device()
print('[*] device:', device)

# Find Gadget PID
ps = device.enumerate_processes()
gadget = None
for p in ps:
    if p.name == 'Gadget':
        gadget = p
        break
if not gadget:
    print('[-] Gadget not running')
    sys.exit(1)
print(f'[*] Gadget PID: {gadget.pid}')

# Spawn time option: v8 runtime
session = device.attach(gadget.pid)
script = session.create_script(r'''
'use strict';

rpc.exports = {
    listsp: function() {
        var File = Java.use('java.io.File');
        var activityThread = Java.use('android.app.ActivityThread');
        var ctx = activityThread.currentApplication().getApplicationContext();
        var pkg = ctx.getPackageName();
        var dataDir = ctx.getDataDir().getAbsolutePath();

        var out = [];
        out.push('package=' + pkg);
        out.push('dataDir=' + dataDir);

        var spDir = new File(dataDir + '/shared_prefs');
        out.push('sp_dir=' + spDir.getAbsolutePath() + ' exists=' + spDir.exists());
        if (spDir.exists() && spDir.isDirectory()) {
            var files = spDir.list();
            out.push('sp_files=' + files.length);
            for (var i = 0; i < files.length; i++) {
                var f = new File(spDir.getAbsolutePath() + '/' + files[i]);
                out.push('  ' + files[i] + '  ' + f.length() + ' bytes');
            }
        }

        var filesDir = new File(dataDir + '/files');
        if (filesDir.exists()) {
            var ff = filesDir.list();
            if (ff) {
                out.push('files count=' + ff.length);
                for (var j = 0; j < ff.length; j++) {
                    out.push('  f/' + ff[j]);
                }
            }
        }
        var dbDir = new File(dataDir + '/databases');
        if (dbDir.exists()) {
            var dd = dbDir.list();
            if (dd) {
                out.push('databases count=' + dd.length);
                for (var k = 0; k < dd.length; k++) {
                    out.push('  d/' + dd[k]);
                }
            }
        }
        return out.join('\n');
    },
    catsp: function(filename) {
        var File = Java.use('java.io.File');
        var activityThread = Java.use('android.app.ActivityThread');
        var ctx = activityThread.currentApplication().getApplicationContext();
        var dataDir = ctx.getDataDir().getAbsolutePath();
        var f = new File(dataDir + '/shared_prefs/' + filename);
        if (!f.exists()) return 'ERROR: file not found';
        var FileReader = Java.use('java.io.FileReader');
        var BufferedReader = Java.use('java.io.BufferedReader');
        var fr = FileReader.$new(f);
        var br = BufferedReader.$new(fr);
        var sb = Java.use('java.lang.StringBuilder').$new();
        var line;
        while ((line = br.readLine()) !== null) {
            sb.append(line);
            sb.append('\n');
        }
        br.close();
        fr.close();
        return sb.toString();
    }
};
''', runtime='v8')
script.on('message', on_message)
script.load()
print('[*] script loaded')

# Use rpc to call our export
api = script.exports_sync
print('[*] listing sandbox...')
result = api.listsp()
print(result)
print('---')
print('[*] reading Gwell.xml (first 800 chars)...')
try:
    cat = api.catsp('Gwell.xml')
    print(cat[:800])
except Exception as e:
    print('err:', e)
print('---')
print('[*] reading com.jwkj.preferences.xml (first 800 chars)...')
try:
    cat = api.catsp('com.jwkj.preferences.xml')
    print(cat[:800])
except Exception as e:
    print('err:', e)
