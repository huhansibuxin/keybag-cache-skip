import lief
d = lief.parse("D:/woekbude/keybag-cache-skip/extracted_v4.dylib")
print("=== ARCH/HEADER ===")
print("  cpu:", d.header.cpu_type, " filetype:", d.header.file_type)
print("=== LIBRARIES (LC_LOAD_DYLIB) ===")
for l in d.libraries:
    print("   ", l)
print("=== RPATH ===")
for c in d.commands:
    if "RPath" in str(type(c)):
        print("   ", c)
print("=== CODE SIGNATURE ===")
print("   has_code_signature:", d.has_code_signature if hasattr(d,"has_code_signature") else "n/a")
for c in d.commands:
    t = str(type(c))
    if "CodeSignature" in t or "Signature" in t:
        print("   ", c)
print("=== SECTIONS ===")
for s in d.sections:
    print("   %-24s %#x %#x" % (s.name, s.virtual_address, s.size))
