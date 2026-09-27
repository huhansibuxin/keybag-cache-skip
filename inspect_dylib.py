import tarfile, glob, io, gzip
deb = glob.glob("D:/woekbude/keybag-cache-skip/ci_v3/*.deb")[0]
data = open(deb,"rb").read()
off=8
blob=None
while off < len(data):
    hdr=data[off:off+60]
    if len(hdr)<60: break
    name=hdr[0:16].split(b"/")[0].strip().decode("latin1")
    size=int(hdr[48:58].strip())
    content=data[off+60:off+60+size]
    if name.startswith("data.tar"):
        tf=tarfile.open(fileobj=io.BytesIO(content))
        for n in tf.getnames():
            if n.endswith(".dylib"):
                blob=tf.extractfile(n).read()
                print("dylib:", n, len(blob), "bytes")
    off+=60+size+(size&1)

open("D:/woekbude/keybag-cache-skip/extracted.dylib","wb").write(blob)

import lief
d = lief.parse("D:/woekbude/keybag-cache-skip/extracted.dylib")
print("=== LC_LOAD_DYLIB / deps ===")
try:
    for lib in d.libraries:
        print("   ", lib)
except Exception as e:
    print("   err", e)
print("=== undefined symbols (imports) ===")
try:
    for s in d.imported_symbols:
        print("   ", s.name)
except Exception as e:
    print("   err", e)
print("=== has __mod_init_func? ===")
for s in d.sections:
    print("   %-20s %#x %#x" % (s.name, s.virtual_address, s.size))
