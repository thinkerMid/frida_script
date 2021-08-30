import sys

import frida

import dexdump_script


def on_message(message, data):
    if message['type'] == 'send':
        print(message['payload'])
    else:
        print(message)

#修改你想要hook的app
app = 'com.xx.xx.xx'

dev = frida.get_remote_device()
pid = dev.spawn(app)
proc = dev.attach(pid)
script = proc.create_script(dexdump_script.dex_dump % app)
script.on('message', on_message)
script.load()
dev.resume(app)
sys.stdin.read()
