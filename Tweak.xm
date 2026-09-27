// KeybagCacheSkip — turn keybagd's backup-keys cache rebuild into a no-op.
// ===========================================================================
// PROBLEM
//   On iOS 16 `/usr/libexec/keybagd` rebuilds
//   /private/var/keybags/backup/backup_keys_cache.sql3 on every launch: it walks
//   every data-volume key and REPLACEs them into `WrappedKeys` (~1.27M rows /
//   ~306 MB). That pins a CPU core near 100% for ~20 s and heats the device, and
//   keybagd is an on-demand `-t 15` daemon, so the spike keeps coming back.
//
// FIX
//   Patch the rebuild routine's entry (preferred/static address 0x1000167cc on
//   iOS 16.6.1, build 20G81) to `mov x0, #0 ; ret`. Its only caller does
//   `cbz w0`, so returning NULL means "no cache handle" — the natural "no cache"
//   state. The db is never opened, no rows are inserted, no spike.
//
// HARD-WON CONSTRAINTS (each one proven by a device crash/failure, 2026-09-28)
//   1. ZERO substrate symbols. keybagd cannot dlopen libellekit / libsubstrate,
//      so a tweak whose LC_LOAD_DYLIB references it fails to load *silently*
//      (loaded-by-nobody, zero logs). We therefore use no MSHookFunction / %hook
//      and touch only libSystem. `-Wl,-dead_strip_dylibs` + a CI assertion keep
//      the substrate dependency from sneaking back.
//   2. The slide must come from the MAIN EXECUTABLE. In this rootless/roothide
//      jailbreak the injected `systemhook-<UUID>.dylib` owns dyld image index 0,
//      so index 0 is NOT keybagd; using its slide lands the target in an
//      unrelated mapping. Scan for `filetype == MH_EXECUTE`.
//   3. iOS enforces W^X. After writing the patch the page MUST go back to r-x
//      *before any instruction on it is fetched* — the target shares its 16 KB
//      page with `main()`, so leaving it RWX kills the daemon on main()'s first
//      instruction (SIGBUS / KERN_PROTECTION_FAILURE) in a 10 s crash loop.
//   4. Guard on the prologue. Only patch when the bytes still decode to the
//      expected `pacibsp` (or to our own patch, for idempotency). On an unknown
//      build we bail and leave the daemon completely untouched rather than poke
//      garbage into a security daemon.
//
// v1.2.0 — SILENT RELEASE
//   v1.1.x wrote a diagnostic marker file on every single launch while we were
//   hunting the three root causes. That instrumentation is gone: this build
//   performs no file I/O at all. Everything it needs is decided in-process.
//   (The diagnostic lineage is preserved in the v1.1.2 tag in git history.)
// ===========================================================================

#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach/mach.h>
#import <libkern/OSCacheControl.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

// Preferred (static) load address of the rebuild routine in keybagd.
static const uintptr_t kCacheFnStatic = 0x1000167cc;

// Expected prologue of that routine on this build: `pacibsp`
// (instruction word 0xD503237F -> little-endian bytes 7F 23 03 D5).
static const unsigned char kPrologue[4] = { 0x7f, 0x23, 0x03, 0xd5 };

// Our patch, i.e. `mov x0, #0` (0xD2800000) followed by `ret` (0xD65F03C0).
static const uint32_t kPatch[2] = { 0xD2800000u, 0xD65F03C0u };

// First 4 bytes of an already-patched prologue -> lets us be idempotent.
static const unsigned char kPatchedHead[4] = { 0x00, 0x00, 0x80, 0xd2 };

// `mov x0,#0` zeroes x0, so the caller's `cbz w0` is guaranteed to take the
// NULL branch. We never touch x29/x30/sp, and because the target's own
// `pacibsp` is overwritten the return address is unsigned, so a bare `ret` is
// the correct pair (not `retab`).
static void kcs_apply(void) {
    static int done = 0;
    if (done) return;
    done = 1;

    // --- find the main executable (never trust dyld image index 0) ------------
    uint32_t n = _dyld_image_count();
    int midx = -1;
    for (uint32_t i = 0; i < n; i++) {
        const struct mach_header *h = _dyld_get_image_header(i);
        if (h && h->filetype == MH_EXECUTE) { midx = (int)i; break; }
    }
    if (midx < 0) {
        // Fallback for an environment without a plain MH_EXECUTE image.
        for (uint32_t i = 0; i < n; i++) {
            const char *nm = _dyld_get_image_name(i);
            if (nm && strstr(nm, "keybagd")) { midx = (int)i; break; }
        }
    }
    if (midx < 0) return;

    uintptr_t slide = (uintptr_t)_dyld_get_image_vmaddr_slide((uint32_t)midx);
    unsigned char *target = (unsigned char *)(kCacheFnStatic + slide);

    // --- guard: expected prologue, or already patched (idempotent) ------------
    if (memcmp(target, kPatchedHead, 4) == 0) return;
    if (memcmp(target, kPrologue, 4) != 0) return;   // unknown build: leave it be

    // --- patch, then immediately restore r-x (W^X) ----------------------------
    long ps = getpagesize();
    uintptr_t page = (uintptr_t)target & ~((uintptr_t)ps - 1);

    unsigned char orig[8];
    memcpy(orig, target, sizeof(orig));

    // VM_PROT_COPY hands us a private COW copy of the signed __TEXT page; the
    // original file mapping is not writable.
    kern_return_t kr = vm_protect(mach_task_self(), (vm_address_t)page, (vm_size_t)ps, FALSE,
                                  VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) return;

    memcpy(target, kPatch, sizeof(kPatch));

    // Drop WRITE before anything on this page is fetched.
    if (vm_protect(mach_task_self(), (vm_address_t)page, (vm_size_t)ps, FALSE,
                   VM_PROT_READ | VM_PROT_EXECUTE) != KERN_SUCCESS) {
        // Could not restore r-x -> roll back rather than leave an RWX page.
        vm_protect(mach_task_self(), (vm_address_t)page, (vm_size_t)ps, FALSE,
                   VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
        memcpy(target, orig, sizeof(orig));
        sys_icache_invalidate(target, sizeof(orig));
        vm_protect(mach_task_self(), (vm_address_t)page, (vm_size_t)ps, FALSE,
                   VM_PROT_READ | VM_PROT_EXECUTE);
        return;
    }

    sys_icache_invalidate(target, sizeof(kPatch));

    // Light read-back check: if the write did not stick we restore the prologue
    // and leave the daemon exactly as we found it.
    if (memcmp(target, kPatchedHead, 4) != 0) {
        vm_protect(mach_task_self(), (vm_address_t)page, (vm_size_t)ps, FALSE,
                   VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
        memcpy(target, orig, sizeof(orig));
        sys_icache_invalidate(target, sizeof(orig));
        vm_protect(mach_task_self(), (vm_address_t)page, (vm_size_t)ps, FALSE,
                   VM_PROT_READ | VM_PROT_EXECUTE);
    }
}

%ctor { kcs_apply(); }
