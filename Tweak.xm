// KeybagCacheSkip
// ---------------------------------------------------------------------------
// Problem: on iOS 16 keybagd, on every launch, runs function @0x1000167cc which
// opens /var/keybags/backup/backup_keys_cache.sql3, runs `db_check_once`, then
// loops over ALL data-volume keys inserting them (REPLACE INTO WrappedKeys) into
// the cache. On a data-filled device that is ~1.27M rows / ~306 MB, pinning CPU
// (~99%) for ~20-25s per launch. Combined with `-t 15` idle-exit + relaunch this
// repeats constantly (visible in keybagd.log.0 as a recurring
// `db_check_once: ... is ok` line ~25s after each launch).
//
// Fix: hook @0x1000167cc and return NULL immediately. Its caller does `cbz w0`
// -> NULL makes keybagd skip storing any cache handle (the natural "no cache"
// state). No db open, no db_check_once, no 1.27M-row insert loop, no VACUUM.
// Backup is disabled and keybagd derives keys on demand, so this is a no-op.
//
// Reverse-engineered from the device binary (sha1 0aad8913... == /rootfs/
// usr/libexec/keybagd):
//   * function entry  @0x1000167cc  (pacibsp; 7F 23 03 D5)
//   * db_check_once   log emit      @0x100016854 / 0x100016878
//   * key enumeration @0x100020448  (returns count + array)
//   * insert loop     @0x100016938  calling insert helper @0x10000e7c0
// ---------------------------------------------------------------------------

#import <substrate.h>
#import <mach-o/dyld.h>
#import <stdint.h>
#import <string.h>
#import <stdio.h>
#import <unistd.h>
#import <stdarg.h>
#import <os/log.h>

// ---- diagnostic (temporary) -------------------------------------------------
// keybagd emits its own log via os_log (see /var/logs/keybagd.log.0), so we log
// with os_log too -> our lines land in the SAME stream and are readable on the
// device. We also try a few files as a fallback in case the os_log subsystem
// differs. Remove once the hook is verified working.
static void kcs_log(const char *fmt, ...) {
    char buf[512];
    va_list ap; va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    os_log_with_type(OS_LOG_DEFAULT, OS_LOG_TYPE_ERROR, "KCS %{public}s", buf);

    const char *paths[3] = {
        "/var/logs/keybagcacheskip.log",
        "/tmp/keybagcacheskip.log",
        "/var/mobile/Library/Logs/keybagcacheskip.log"
    };
    for (int i = 0; i < 3; i++) {
        FILE *f = fopen(paths[i], "a");
        if (f) { fprintf(f, "%s\n", buf); fclose(f); }
    }
}

// Preferred (static) load address of the cache function in keybagd.
static const uintptr_t kCacheFnStatic = 0x1000167cc;

// This keybagd build's arm64e function prologue decodes to `pacibsp` with exact
// little-endian bytes 7F 23 03 D5. We pin those 4 bytes so we only hook if the
// target still is the real function entry (bail cleanly on an iOS update).
static const unsigned char kCacheFnPrologue[4] = { 0x7f, 0x23, 0x03, 0xd5 };

static void *(*orig_cache_fn)(void) = NULL;

// Replacement: never open/check/rebuild the backup-keys cache.
static void *replacement_cache_fn(void) {
    kcs_log("CALLED pid=%d -> return NULL (skip cache open/check/rebuild)", getpid());
    return NULL;
}

%ctor {
    char path[1024]; uint32_t psz = sizeof(path);
    const char *exe = (_NSGetExecutablePath(path, &psz) == 0) ? path : "?";
    kcs_log("ctor pid=%d exe=%s", getpid(), exe);

    uintptr_t slide = (uintptr_t)_dyld_get_image_vmaddr_slide(0);
    void *target = (void *)(kCacheFnStatic + slide);

    unsigned char head[4];
    memcpy(head, target, sizeof(head));
    if (memcmp(head, kCacheFnPrologue, 4) != 0) {
        kcs_log("BAILED prologue mismatch target=%p slide=%#lx bytes=%02x%02x%02x%02x",
                target, (unsigned long)slide, head[0], head[1], head[2], head[3]);
        return;
    }

    MSHookFunction(target, (void *)replacement_cache_fn,
                   (void **)&orig_cache_fn);
    kcs_log("HOOKED ok target=%p slide=%#lx orig=%p", target, (unsigned long)slide,
            (void *)orig_cache_fn);
}
