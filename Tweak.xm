// KeybagCacheSkip
// ---------------------------------------------------------------------------
// Problem: on iOS 16 keybagd, on every launch, runs a routine @0x1000167cc which
// opens /private/var/keybags/backup/backup_keys_cache.sql3, runs `db_check_once`,
// then walks all data-volume keys and REPLACEs them into the cache (~1.27M rows /
// 306 MB). That pins CPU (~99%) for ~20-27 s per launch, and keybagd relaunches
// often (RunAtLoad + machservice on demand + `-t 15` idle exit), so the spike
// repeats. Visible in keybagd.log.0 as a recurring `db_check_once: ... is ok`
// line ~18-27 s after each launch, and the sql3 file's mtime/size update each launch.
//
// Fix: make @0x1000167cc return NULL immediately. Its caller does `cbz w0`, so
// NULL makes keybagd skip storing a cache handle (the natural "no cache" state):
// no db open, no db_check_once, no 1.27M-row loop.
//
// ---------------------------------------------------------------------------
// v6 — WHY v1..v5 NEVER LOADED (root cause, proven on device 2026-09-28)
// ---------------------------------------------------------------------------
// The old dylib hard-linked LC_LOAD_DYLIB @loader_path/.jbroot/usr/lib/libsubstrate.dylib
// (pulled in by MSHookFunction) and **libellekit cannot be loaded in keybagd**,
// so dlopen() of our tweak FAILED silently -> zero logs, hook never ran.
// Proof + controlled experiment: see git history. Fix = zero substrate symbols
// (the LocalStorageSkip recipe) so the linker drops -lsubstrate.
//
// ---------------------------------------------------------------------------
// v7 — WHY v6 LOADED BUT STILL DID NOT PATCH (proven on device 2026-09-28)
// ---------------------------------------------------------------------------
// v6 was loaded and its ctor ran (marker file appeared), but it bailed out:
//     KCS-BOOT v6 pid=46229 img0=/usr/lib/systemhook-6E15938E68EC7D9F.dylib slide=0x103064000
//     KCS-TARGET target=0x20307a7cc bytes=e20313aae30314aa prologue_match=0
//     KCS-BAILED prologue mismatch
// Cause: `_dyld_get_image_name(0)` is NOT the main executable in this
// rootless/roothide jailbreak -- the injected `systemhook-<UUID>.dylib` occupies
// image index 0. So `_dyld_get_image_vmaddr_slide(0)` is systemhook's ASLR slide,
// not keybagd's -> target pointed into an unrelated mapping (sometimes a zero
// page). The prologue guard correctly refused to write (no collateral damage),
// hence the CPU spike and the rebuilt sql3 continued unchanged.
//
// Fix: locate the main executable by scanning dyld images for filetype ==
// MH_EXECUTE (with a name contains "keybagd" fallback), take ITS slide, and only
// then compute the target. v7 also dumps the full image list to the marker so a
// failure is diagnosable in one round trip.
//
// ---------------------------------------------------------------------------
// v8 — WHY v7 PATCHED CORRECTLY BUT CRASHED keybagd (proven on device 2026-09-28)
// ---------------------------------------------------------------------------
// v7 found the right address and wrote the patch (marker: KCS-CAND[0] match=1,
// KCS-PATCHED ok), but keybagd then entered a 10-second crash loop:
//     exception : EXC_BAD_ACCESS / SIGBUS
//     subtype   : KERN_PROTECTION_FAILURE at 0x1001bd864
//     thread    : dyld `start` -> keybagd +0x15864        (main entry!)
//     keybagd image base 0x1001a8000 + 0x15864 = 0x1001bd864  == the fault address
// Cause: **iOS enforces W^X**. v7 left the patched page mapped RWX (we only ever
// *added* WRITE; we never took it back). The instruction fetch that follows
// faults, and because the target (0x167cc) shares its 16 KB page (0x14000-0x17FFF)
// with main() (0x15864), the very first instruction of main() dies -- so keybagd
// crashed at startup and launchd relaunched it every 10 s ("starts then exits
// after a few seconds").
//
// Fix: restore the page to r-x (drop WRITE) IMMEDIATELY after memcpy, before any
// instruction on that page is fetched; then flush the icache; then verify both
// the written bytes and the region protection. If the restore fails we roll the
// original bytes back rather than risk an RWX page.
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
//   * main()          @0x100015864  (same 16 KB page as the target!)
// ---------------------------------------------------------------------------

#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach/mach.h>
#import <mach/vm_region.h>
#import <libkern/OSCacheControl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>

// ---- diagnostics ------------------------------------------------------------
// Keep the channel set that keybagd itself provably writes, so a single file
// presence answers "did the dylib load and did the ctor run?".
// NOTE: /var is a symlink to /private/var, so the two spellings are the SAME file
// (that is why v6 logged everything twice). Deduplicated here.
// From our SSH view these are /rootfs/private/var/... (device root == /rootfs).
static void kcs_log(const char *fmt, ...) {
    char buf[768];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    static const char *paths[] = {
        "/private/var/keybags/backup/kcs_marker.txt",  // keybagd writes here every launch
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

static void kcs_hex8(char *out, size_t n, const unsigned char *p) {
    snprintf(out, n, "%02x%02x%02x%02x%02x%02x%02x%02x",
             p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]);
}

// Preferred (static) load address of the cache function in keybagd.
static const uintptr_t kCacheFnStatic = 0x1000167cc;

// This keybagd build's arm64e prologue decodes to `pacibsp`:
// instruction word 0xD503237F -> little-endian bytes 7F 23 03 D5.
static const unsigned char kCacheFnPrologue[4] = { 0x7f, 0x23, 0x03, 0xd5 };

// mov x0, #0 ; ret
static const uint32_t kPatch[2] = { 0xD2800000u, 0xD65F03C0u };

#define KCS_MAXCAND 24

static void kcs_bootstrap(void) {
    static int done = 0;
    if (done) return;
    done = 1;

    uint32_t nimg = _dyld_image_count();
    kcs_log("KCS-BOOT v8 pid=%d dynimages=%u", getpid(), nimg);

    // Brief image table (first few only -- the full dump was needed for v6/v7 and
    // was blowing the marker file up to ~180 KB per launch).
    for (uint32_t i = 0; i < nimg && i < 6; i++) {
        const struct mach_header *h = _dyld_get_image_header(i);
        const char *nm = _dyld_get_image_name(i);
        kcs_log("KCS-IMG[%u] type=%u slide=%#lx name=%s",
                i,
                h ? (unsigned)h->filetype : 0u,
                (unsigned long)_dyld_get_image_vmaddr_slide(i),
                nm ? nm : "?");
    }

    // --- pick the main executable: filetype == MH_EXECUTE (fallback: name) ----
    // In this JB the injected systemhook dylib owns image index 0, so we must NOT
    // use index 0's slide. Prefer MH_EXECUTE; also collect any image whose
    // basename is/contains "keybagd" as a fallback candidate.
    uintptr_t cand[KCS_MAXCAND];
    const char *candname[KCS_MAXCAND];
    int nc = 0;

    int midx = -1;
    for (uint32_t i = 0; i < nimg; i++) {
        const struct mach_header *h = _dyld_get_image_header(i);
        if (h && h->filetype == MH_EXECUTE) { midx = (int)i; break; }
    }
    if (midx >= 0) {
        uintptr_t sl = (uintptr_t)_dyld_get_image_vmaddr_slide((uint32_t)midx);
        const char *nm = _dyld_get_image_name((uint32_t)midx);
        kcs_log("KCS-MAIN idx=%d slide=%#lx name=%s", midx, (unsigned long)sl, nm ? nm : "?");
        cand[nc] = kCacheFnStatic + sl; candname[nc] = nm ? nm : "?"; nc++;
    } else {
        kcs_log("KCS-WARN no MH_EXECUTE image found");
    }

    for (uint32_t i = 0; i < nimg && nc < KCS_MAXCAND; i++) {
        if ((int)i == midx) continue;
        const char *nm = _dyld_get_image_name(i);
        if (!nm) continue;
        if (!strstr(nm, "keybagd")) continue;
        uintptr_t sl = (uintptr_t)_dyld_get_image_vmaddr_slide(i);
        cand[nc] = kCacheFnStatic + sl; candname[nc] = nm; nc++;
    }

    // --- evaluate candidates; patch the first one whose prologue matches ------
    unsigned char *hit = NULL;
    const char *hitname = NULL;
    for (int c = 0; c < nc; c++) {
        unsigned char *t = (unsigned char *)cand[c];
        unsigned char head[8];
        char hx[24];
        memcpy(head, t, sizeof(head));
        kcs_hex8(hx, sizeof(hx), head);
        int m = (memcmp(head, kCacheFnPrologue, 4) == 0);
        kcs_log("KCS-CAND[%d] %p bytes=%s match=%d name=%s", c, (void *)t, hx, m, candname[c]);
        if (m && !hit) { hit = t; hitname = candname[c]; }
    }

    if (!hit) {
        kcs_log("KCS-BAILED no candidate matched prologue (see KCS-IMG list)");
        return;
    }
    kcs_log("KCS-HIT at %p via %s", (void *)hit, hitname ? hitname : "?");

    // --- write the patch -------------------------------------------------------
    long ps = getpagesize();
    uintptr_t page = (uintptr_t)hit & ~((uintptr_t)ps - 1);

    unsigned char orig[8];
    memcpy(orig, hit, sizeof(orig));

    // VM_PROT_COPY gives us a COW private copy of the signed __TEXT page, which
    // is what every inline hooker does on iOS (the file mapping itself is not
    // writable).
    kern_return_t kr = vm_protect(mach_task_self(), (vm_address_t)page, (vm_size_t)ps, FALSE,
                                  VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) {
        kcs_log("KCS-FAILED vm_protect(rwx) kr=%d (page=%p)", kr, (void *)page);
        return;
    }

    memcpy(hit, kPatch, sizeof(kPatch));

    // *** THE v7 CRASH FIX: iOS enforces W^X. ***
    // Drop WRITE before ANY instruction on this page is fetched. The target
    // (0x167cc) shares its 16 KB page with main() (0x15864), so leaving the page
    // RWX made keybagd fault on main()'s first instruction (SIGBUS /
    // KERN_PROTECTION_FAILURE) -> 10 s crash loop.
    kern_return_t kr2 = vm_protect(mach_task_self(), (vm_address_t)page, (vm_size_t)ps, FALSE,
                                   VM_PROT_READ | VM_PROT_EXECUTE);
    if (kr2 != KERN_SUCCESS) {
        kcs_log("KCS-WX-FAILED restore r-x kr=%d -> rolling back", kr2);
        vm_protect(mach_task_self(), (vm_address_t)page, (vm_size_t)ps, FALSE,
                   VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
        memcpy(hit, orig, sizeof(orig));
        sys_icache_invalidate(hit, sizeof(orig));
        vm_protect(mach_task_self(), (vm_address_t)page, (vm_size_t)ps, FALSE,
                   VM_PROT_READ | VM_PROT_EXECUTE);
        return;
    }
    sys_icache_invalidate(hit, sizeof(kPatch));

    // --- verify: bytes actually written + page protection is r-x (no W) --------
    unsigned char after[8];
    char hxa[24];
    memcpy(after, hit, sizeof(after));
    kcs_hex8(hxa, sizeof(hxa), after);

    vm_address_t qa = (vm_address_t)page;
    vm_size_t qs = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t icnt = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t obj = MACH_PORT_NULL;
    // NB: mach_vm_region() lives in <mach/mach_vm.h>, which the iOS SDK blocks
    // with `#error mach_vm.h unsupported`. vm_region_64() is the usable flavour
    // and is declared in <mach/vm_map.h> (pulled in by <mach/mach.h>).
    kern_return_t kr3 = vm_region_64(mach_task_self(), &qa, &qs, VM_REGION_BASIC_INFO_64,
                                     (vm_region_info_t)&info, &icnt, &obj);
    unsigned prot = (kr3 == KERN_SUCCESS) ? (unsigned)info.protection : 0xFFFFFFFFu;

    kcs_log("KCS-PATCHED ok at %p bytes=%s page=%p ps=%ld prot=%#x (want 0x5=r-x)",
            (void *)hit, hxa, (void *)page, ps, prot);
}

%ctor { kcs_bootstrap(); }
