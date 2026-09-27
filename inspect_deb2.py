import tarfile, glob, io
deb = glob.glob("D:/woekbude/keybag-cache-skip/ci_out_roothide_v2/*.deb")[0]
data = open(deb,"rb").read()
assert data[:8]==b"!<arch>\n", "not ar"
off=8
while off<len(data):
    hdr=data[off:off+60]; 
    if len(hdr)<60: break
    name=hdr[0:16].split(b"/")[0].strip().decode("latin1")
    size=int(hdr[48:58].strip())
    content=data[off+60:off+60+size]
    if name.startswith("data.tar"):
        tf=tarfile.open(fileobj=io.BytesIO(content))
        for n in tf.getnames():
            ti=tf.getmember(n); print(" ",n,ti.size,"bytes")
            if n.endswith(".plist"):
                raw=tf.extractfile(n).read()
                print("   PLIST:",raw.decode("latin1") if b"Execut" in raw or b"Filter" in raw else raw[:80])
    off+=60+size+(size&1)
