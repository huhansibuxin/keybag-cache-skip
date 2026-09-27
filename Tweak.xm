// KeybagCacheSkip
// ---------------------------------------------------------------------------
// Problem: on iOS 16 keybagd, on every launch, runs a routine @0x1000167cc which
// opens /private/var/keybags/backup/backup_keys_cache.sql3, runs `db_check_once`,
// then walks all data-volume keys and REPLACEs them into the cache (~1.27M rows /
// 306 MB). That pins CPU (~99%) for ~20-27 s per launch, and keybagd relaunches
// often (RunAtLoad + machservice on demand + `-t 15` idle exit), so the spike
// repeats. Visible in keybagd.log.0 as a recurring `db_check_once: ... is ok`
// line ~22-27 s after each launch, and the sql3 file's mtime updates each launch.
//
// Fix: make @0x1000167cc return NULL immediately. Its caller does `cbz w0`, so
// NULL makes keybagd skip storing a cache handle (the natural "no cache" state):
// no db open, no db_check_once, no 1.27M-row loop.
//
// ---------------------------------------------------------------------------
// v6 — WHY v1..v5 NEVER LOADED (root cause, proven on device 2026-09-28)
// ---------------------------------------------------------------------------
// The dylib was NEVER loaded into keybagd at all, so it could never log anything.
// Proof: a crash report of keybagd (bug_type 309, `killall -ABRT keybagd`) lists
// every non-shared-cache image in `usedImages`. Ours was absent, and so was
// libellekit — while `   Choicy.dylib` was present.
//
// Mechanism: this JB (roothide/RootHide) injects the jailbreak base libs
// (systemhook/roothideinit/roothidepatch/libroothide/forkfix) + the tweak manager
// `   Choicy.dylib` into keybagd, but **libellekit.dylib
// (= libsubstrate.dylib) cannot be loaded in keybagd**. Our old dylib hard-linked
//   LC_LOAD_DYLIB @loader_path/.jbroot/usr/lib/libsubstrate.dylib
// (pulled in by MSHookFunction), so `dlopen` of our tweak FAILED silently.
//
// Controlled experiment that nailed it: copied the substrate-free
// LocalStorageSkip.dylib over ours (same name, same Filter, so Choicy's
// allowedTweaks=["KeybagCacheSkip"] still matched) -> it was loaded into keybagd
// instantly (appeared in usedImages). Only variable = the substrate dependency.
// Same JB loads substrate-linked tweaks fine in other processes (mediaserverd
// proved TrollOpenCamera/SneakyCam/SneakySupport + libellekit all load), so this
// is specific to keybagd's dependency resolution.
//
// => The fix is the LocalStorageSkip recipe: reference ZERO substrate symbols so
//    the linker drops `-lsubstrate`, and do the patch by hand with only libSystem.
//    No MSHookFunction, no trampoline, no %hook. (Theos only emits the substrate
//    LC_LOAD_DYLIB when a substrate symbol is actually used.)
//
// Patching @0x1000167cc = overwrite the prologue with:
//     mov x0, #0     (0xD2800000)   ; return NULL
//     ret            (0xD65F03C0)
// That is exactly equivalent to our old replacement returning NULL, needs no
// trampoline, and the caller's `cbz w0` path is preserved. We clobber no
// callee-saved register and never touch x29/x30/sp, so plain `ret` is safe.
//
// Reverse-engineered from the device binary (sha1 0aad8913… == /rootfs/usr/libexec/keybagd):
//   * function entry  @0x1000167cc  (pacibsp; bytes 7F 23 03 D5)
//   * db_check_once   emit          @0x100016854 / 0x100016878  (inside 0x1000167cc)
//   * insert helper   @0x10000e7c0  (REPLACE INTO WrappedKeys VALUES(?,?,?,0))
//   * rebuild loop    @0x1000169d0  (x20 += 0x7c stride, x26 = row counter)
// ---------------------------------------------------------------------------

#import <mach-o/dyld.h>
#import <mach/mach.h>
#import <libkern/OSCacheControl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <dlfcn.h>

// ---- diagnostics ------------------------------------------------------------
// Keep the channel set that keybagd itself provably writes, so a single file
// presence answers "did the dylib load and did the ctor run?".
// From our SSH view these are /rootfs/private/var/keybags/backup/... (the device
// root is at /rootfs in the jailbreak shell; keybagd sees it as /).
static void kcs_log(const char *fmt, ...) {
    char buf[768];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    static const char *paths[] = {
        "/private/var/keybags/backup/kcs_marker.txt",  // keybagd writes here every launch
        "/var/keybags/backup/kcs_marker.txt",
        "/tmp/kcs_marker.txt",
        "/var/mobile/Library/Logs/kcs_marker.txt",
    };
    for (unsigned i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        FILE *f = fopen(paths[i], "a");
        if (f) {
            fprintf(f, "[KCS] %s\n", buf);
            fclose(f);
        }
    }
}

// Preferred (static) load address of the cache function in keybagd.
static const uintptr_t kCacheFnStatic = 0x1000167cc;

// This keybagd build's arm64e prologue decodes to `pacibsp`:
// instruction word 0xD503237F -> little-endian bytes 7F 23 03 D5.
static const unsigned char kCacheFnPrologue[4] = { 0x7f, 0x23, 0x03, 0xd5 };

// mov x0, #0 ; ret   (little-endian byte order handled by uint32 stores)
static const uint32_t kPatch[2] = { 0xD2800000u, 0xD65F03C0u };

static void kcs_bootstrap(void) {
    static int done = 0;
    if (done) return;
    done = 1;

    char img0[256] = "?";
    const char *n0 = _dyld_get_image_name(0);
    if (n0) {
        strncpy(img0, n0, sizeof(img0) - 1);
        img0[sizeof(img0) - 1] = 0;
    }

    Dl_info dli;
    memset(&dli, 0, sizeof(dli));
    const char *self = (dladdr((void *)kcs_bootstrap, &dli) && dli.dli_fname) ? dli.dli_fname : "?";

    uintptr_t slide = (uintptr_t)_dyld_get_image_vmaddr_slide(0);
    unsigned char *target = (unsigned char *)(kCacheFnStatic + slide);

    unsigned char head[8];
    memcpy(head, target, sizeof(head));
    int match = (memcmp(head, kCacheFnPrologue, 4) == 0);

    kcs_log("KCS-BOOT v6 pid=%d img0=%s slide=%#lx tweakinject_visible=%d self=%s",
            getpid(), img0, (unsigned long)slide,
            access("/usr/lib/TweakInject/KeybagCacheSkip.dylib", F_OK) == 0, self);
    kcs_log("KCS-TARGET target=%p bytes=%02x%02x%02x%02x%02x%02x%02x%02x prologue_match=%d",
            target, head[0], head[1], head[2], head[3], head[4], head[5], head[6], head[7],
            match);

    if (!match) {
        kcs_log("KCS-BAILED prologue mismatch -> not patching (keybagd differs from RE build)");
        return;
    }

    // Make the code page writable. VM_PROT_COPY gives us a COW private copy of
    // the signed __TEXT page, which is what every inline hooker does on iOS.
    long ps = getpagesize();
    uintptr_t page = (uintptr_t)target & ~((uintptr_t)ps - 1);
    kern_return_t kr = vm_protect(mach_task_self(), (vm_address_t)page, (vm_size_t)ps, FALSE,
                                  VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) {
        kcs_log("KCS-FAILED vm_protect kr=%d (page=%p)", kr, (void *)page);
        return;
    }

    memcpy(target, kPatch, sizeof(kPatch));
    sys_icache_invalidate(target, sizeof(kPatch));

    unsigned char after[8];
    memcpy(after, target, sizeof(after));
    kcs_log("KCS-PATCHED ok bytes=%02x%02x%02x%02x%02x%02x%02x%02x",
            after[0], after[1], after[2], after[3], after[4], after[5], after[6], after[7]);
}

%ctor { kcs_bootstrap(); }
