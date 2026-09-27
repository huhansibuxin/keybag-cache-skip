// KeybagCacheSkip
// ---------------------------------------------------------------------------
// Problem: on iOS 16 keybagd, on every launch, runs a routine @0x1000167cc which
// opens /private/var/keybags/backup/backup_keys_cache.sql3, runs `db_check_once`,
// then walks all data-volume keys and REPLACEs them into the cache (~1.27M rows /
// 306 MB). That pins CPU (~99%) for ~20-25 s per launch, and keybagd relaunches
// constantly (`RunAtLoad` + machservice on demand + `-t 15` idle exit), so the
// spike repeats. Visible in keybagd.log.0 as a recurring
// `db_check_once: ... is ok` line ~22-25 s after each launch, and the sql3 file's
// mtime updates on every launch.
//
// Fix: hook @0x1000167cc, return NULL immediately. Its caller does `cbz w0`, so
// NULL makes keybagd skip storing a cache handle (the natural "no cache" state).
// No db open, no db_check_once, no 1.27M-row loop. Backup is disabled and keybagd
// derives keys on demand, so this is feature-wise a no-op.
//
// Reverse-engineered from the device binary (sha1 0aad8913… == /rootfs/usr/libexec/keybagd):
//   * function entry  @0x1000167cc  (pacibsp; bytes 7F 23 03 D5)
//   * db_check_once   emit          @0x100016854 / 0x100016878  (inside 0x1000167cc)
//   * insert helper   @0x10000e7c0  (REPLACE INTO WrappedKeys VALUES(?,?,?,0))
//   * rebuild loop    @0x1000169d0  (x20 += 0x7c stride, x26 = row counter)
//
// v5 diagnostics: previous builds wrote to /tmp, /var/logs and
// /var/mobile/Library/Logs and produced NOTHING, so we could not tell "dylib not
// loaded" from "loaded but constructor skipped". This build logs into locations
// keybagd itself provably writes every launch (its sql3 folder / its own log),
// which also tells us whether the jailbreak's path masking hides the jailbreak
// from keybagd. See kcs_marker.txt in /private/var/keybags/backup/.
// ---------------------------------------------------------------------------

#import <substrate.h>
#import <mach-o/dyld.h>
#import <stdint.h>
#import <string.h>
#import <stdio.h>
#import <unistd.h>
#import <stdarg.h>
#import <dlfcn.h>
#import <os/log.h>

// ---- diagnostic (temporary) -------------------------------------------------
// Channel choice matters: keybagd is a system daemon, and the jailbreak may mask
// part of the filesystem from it (we verified /var/logs and /rootfs/var/logs are
// DIFFERENT directories). So we write to paths keybagd itself writes every launch:
//   /private/var/keybags/backup/  <- where its sql3 cache lives
// and we also append to its own log file, plus the usual fallbacks.
static void kcs_log(const char *fmt, ...) {
    char buf[768];
    va_list ap; va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    // unified log (shows up if the collector filters by process and not subsystem)
    os_log_with_type(OS_LOG_DEFAULT, OS_LOG_TYPE_ERROR, "KCS %{public}s", buf);

    static const char *paths[] = {
        "/private/var/keybags/backup/kcs_marker.txt",  // keybagd writes here every launch
        "/var/keybags/backup/kcs_marker.txt",
        "/private/var/keybags/kcs_marker.txt",
        "/var/keybags/kcs_marker.txt",
        "/var/logs/keybagd.log.0",                     // keybagd's own log file
        "/tmp/kcs_marker.txt",
        "/var/mobile/Library/Logs/kcs_marker.txt",
    };
    for (unsigned i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        FILE *f = fopen(paths[i], "a");
        if (f) { fprintf(f, "%s\n", buf); fclose(f); }
    }
}

// Preferred (static) load address of the cache function in keybagd.
static const uintptr_t kCacheFnStatic = 0x1000167cc;

// This keybagd build's arm64e prologue decodes to `pacibsp`:
// instruction word 0xD503237F -> little-endian bytes 7F 23 03 D5.
static const unsigned char kCacheFnPrologue[4] = { 0x7f, 0x23, 0x03, 0xd5 };

static void *(*orig_cache_fn)(void) = NULL;

// Replacement: never open/check/rebuild the backup-keys cache.
static void *replacement_cache_fn(void) {
    kcs_log("KCS-CALLED pid=%d -> return NULL (skip cache open/check/rebuild)",
            getpid());
    return NULL;
}

static void kcs_bootstrap(void) {
    static int done = 0;
    if (done) return;
    done = 1;

    // Which image are we in, and can this process even see the jailbreak's tweak
    // folder? If TweakInject is NOT visible here, the jailbreak is masked from
    // this process and injection cannot work by design.
    char img0[256] = "?";
    const char *n0 = _dyld_get_image_name(0);
    if (n0) { strncpy(img0, n0, sizeof(img0) - 1); img0[sizeof(img0) - 1] = 0; }
    int tj = (access("/usr/lib/TweakInject/KeybagCacheSkip.dylib", F_OK) == 0);
    Dl_info dli; memset(&dli, 0, sizeof(dli));
    const char *self = (dladdr((void *)kcs_bootstrap, &dli) && dli.dli_fname) ? dli.dli_fname : "?";

    uintptr_t slide = (uintptr_t)_dyld_get_image_vmaddr_slide(0);
    void *target = (void *)(kCacheFnStatic + slide);

    unsigned char head[8];
    memcpy(head, target, sizeof(head));
    int match = (memcmp(head, kCacheFnPrologue, 4) == 0);

    kcs_log("KCS-BOOT v5 pid=%d img0=%s slide=%#lx hdr=%p tweakinject_visible=%d self=%s",
            getpid(), img0, (unsigned long)slide, (void *)_dyld_get_image_header(0), tj, self);
    kcs_log("KCS-TARGET target=%p bytes=%02x%02x%02x%02x%02x%02x%02x%02x prologue_match=%d",
            target, head[0], head[1], head[2], head[3], head[4], head[5], head[6], head[7], match);

    if (!match) {
        kcs_log("KCS-BAILED prologue mismatch -> not hooking (keybagd differs from RE build)");
        return;
    }

    MSHookFunction(target, (void *)replacement_cache_fn, (void **)&orig_cache_fn);
    kcs_log("KCS-HOOKED ok orig=%p", (void *)orig_cache_fn);
}

// Two independent init channels: Logos %ctor, and an ObjC +load (runs when the
// image's ObjC metadata is mapped, i.e. even if dyld init-offsets are skipped).
@interface KCSBoot : NSObject @end
@implementation KCSBoot
+ (void)load { kcs_bootstrap(); }
@end

%ctor { kcs_bootstrap(); }
