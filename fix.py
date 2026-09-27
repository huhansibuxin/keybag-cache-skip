import lief
for f in ["extracted_v4.dylib","extracted.dylib"]:
    try:
        d = lief.parse("D:/woekbude/keybag-cache-skip/"+f)
    except Exception as e:
        print(f, "ERR", e); continue
    print("===== %s =====" % f)
    has_chain=False; has_modin=False
    for c in d.commands:
        t=str(type(c))
        if "ChainedFixups" in t: has_chain=True; print("   command:", c)
        if "ModInit" in t: has_modin=True
    print("   has LC_DYLD_CHAINED_FIXUPS:", has_chain)
    secs=[s.name for s in d.sections]
    print("   has __mod_init_func:", "__mod_init_func" in secs)
    print("   sections:", secs)
    # strings
    raw=open("D:/woekbude/keybag-cache-skip/"+f,"rb").read()
    for probe in [b"KCS", b"keybagcacheskip", b"HOOKED", b"BAILED", b"CALLED"]:
        print("   contains %-18r : %s" % (probe.decode(), probe in raw))
