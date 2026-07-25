import frida, sys

def on_message(msg, data):
    if msg['type'] == 'send':
        print(msg['payload'])
    elif msg['type'] == 'error':
        print('[ERROR]', msg['stack'])

session = frida.get_usb_device().attach('Gadget')
script = session.create_script('''
Java.perform(function() {
    var ctx = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
    var filesDir = ctx.getFilesDir().getAbsolutePath();
    var pkg = ctx.getPackageName();
    var dataDir = ctx.getDataDir().getAbsolutePath();
    send('[*] package=' + pkg);
    send('[*] dataDir=' + dataDir);
    send('[*] filesDir=' + filesDir);

    var File = Java.use('java.io.File');
    var dir = File.$new(filesDir + '/../shared_prefs');
    send('[*] sp dir=' + dir.getAbsolutePath() + ' exists=' + dir.exists() + ' isDir=' + dir.isDirectory());
    var files = dir.list();
    if (files !== null) {
        send('[*] shared_prefs files count=' + files.length);
        for (var i = 0; i < files.length; i++) {
            var f = File.$new(dir.getAbsolutePath() + '/' + files[i]);
            send('  ' + files[i] + '  ' + f.length() + ' bytes');
        }
    } else {
        send('[-] list() returned null');
    }
    // Listar archivos del sandbox
    var allFiles = File.$new(filesDir + '/..').listFiles();
    if (allFiles !== null) {
        send('[*] sandbox entries:');
        for (var j = 0; j < allFiles.length; j++) {
            send('  ' + allFiles[j].getName() + '  isDir=' + allFiles[j].isDirectory());
        }
    }
});
''')
script.on('message', on_message)
script.load()
sys.stdout.flush()
import time
time.sleep(8)
session.detach()
print('done')
