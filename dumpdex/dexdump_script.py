# %s: App package name
dex_dump = '''
var dex_count = 0
Interceptor.attach(
    Module.findExportByName(
        'libart.so',
        '_ZN3art7DexFile10OpenMemoryEPKhjRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPNS_6MemMapEPKNS_10OatDexFileEPS9_'
    ),
    {
        onEnter: function (args) {
            var begin = args[1]
            var address = parseInt(begin, 16) + 0x20
            var dex_size = Memory.readInt(ptr(address))
            dex_count++
            send('Dex' + dex_count + ' Size : ' + dex_size)
            var file = new File('/data/data/%s/classes' + (dex_count == 1 ? '' : dex_count) + '.dex', 'wb')
            file.write(Memory.readByteArray(begin, dex_size))
            file.flush()
            file.close()
        },
        onLeave: function (retval) {
        }
    }
);
'''
