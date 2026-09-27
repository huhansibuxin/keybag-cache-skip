// KeybagCacheSkip
// ---------------------------------------------------------------------------
// Problem: on iOS 16 (rootless) keybagd rebuilds /var/keybags/backup/
// backup_keys_cache.sql3 from scratch on every cold boot. That cache holds the
// data-volume encryption keys (WrappedKeys) for BACKUP. On a data-filled device
// it is ~306 MB / ~1.27M rows, and the rebuild pins CPU for ~20s + heats the
// phone. Combined with `-t 15` idle-exit + EnablePressuredExit the daemon gets
// killed mid-rebuild -> db corruption -> relaunch -> rebuild again (vicious
// cycle). Backup is disabled, and keybagd tolerates a missing cache (derives
// keys on demand), so the cache is dead weight.
//
// Fix: hook the rebuild routine `drain_backup_keys` in /usr/libexec/keybagd and
// make it return NULL immediately. The caller (xref at 0x100016f48) does
// `cbz w0` -> if NULL it simply skips storing any cache handle, i.e. the
// natural "no cache" state. No db is opened, no rows inserted, no VACUUM.
//
// This mirrors the "local禁止扫描" approach: hook a static C function by its
// (preferred-load) address + ASLR slide and short-circuit it.
//
// Reverse-engineered from the device binary pulled to local keybagd.bin:
//   * REPLACE INTO WrappedKeys ...  -> referenced by adr @0x100027eb1
//   * single-row insert helper 0x10000e7c0 (binds 3 params, sqlite3_step once)
//   * its only loop caller 0x1000169d0 (x20+=0x7c stride, x26 = row counter)
//   * enclosing rebuild fn entry 0x1000167cc (pacibsp; opens cache db, enumerates
//     all keys, loops 1.27M inserts, commits, closes)
//   * VACUUM path lives in keybagd_startstopBackup_block_invoke (0x1000171b0) and
//     only fires on backup start/stop -> irrelevant since backup is off.
// ---------------------------------------------------------------------------

#import <substrate.h>
#import <mach-o/dyld.h>
#import <stdint.h>
#import <string.h>
#import <stdio.h>
#import <unistd.h>
#import <stdarg.h>

// ---- diagnostic log (temporary, for on-device verification) -----------------
// keybagd launches on demand and idle-exits, so this only appends a few lines
// per day. It lets us confirm: (a) the dylib was loaded into keybagd, and
// (b) whether the hook armed or the prologue guard bailed. Remove once verified.
static void kcs_log(const char *fmt, ...) {
    FILE *f = fopen("/tmp/keybagcacheskip.log", "a");
    if (!f) return;
    va_list ap; va_start(ap, fmt); vfprintf(f, fmt, ap); va_end(ap);
    fprintf(f, "\n");
    fclose(f);
}

// Preferred (static) load address of drain_backup_keys in keybagd.
static const uintptr_t kDrainBackupKeysStatic = 0x1000167cc;

// This keybagd build's arm64e function prologue decodes (capstone) to `pacibsp`
// with the exact little-endian bytes 7F 23 03 D5. We pin these 4 bytes as an
// integrity check so we only hook if the target at kDrainBackupKeysStatic is
// STILL the real function entry. (0xD503237F == pacibsp in this binary; the
// "classic" bf/7f low-byte variant depends on the exact build, so we match the
// bytes observed at reverse-engineering time, not a hardcoded PAC constant.)
static const unsigned char kDrainPrologue[4] = { 0x7f, 0x23, 0x03, 0xd5 };

static void *(*orig_drain_backup_keys)(void) = NULL;

// Replacement: never rebuild / never create the backup-keys cache.
// Returning NULL makes the caller skip storing any cache handle; keybagd then
// derives keys on demand. Backup is disabled, so this is a no-op feature-wise.
static void *replacement_drain_backup_keys(void) {
    return NULL;
}

%ctor {
    char path[1024]; uint32_t psz = sizeof(path);
    const char *exe = (_NSGetExecutablePath(path, &psz) == 0) ? path : "?";
    kcs_log("ctor pid=%d exe=%s", getpid(), exe);

    uintptr_t slide = (uintptr_t)_dyld_get_image_vmaddr_slide(0);
    void *target = (void *)(kDrainBackupKeysStatic + slide);

    // Sanity check: only hook if the first instruction at the target is really
    // this function's prologue (7F 23 03 D5 == pacibsp in this keybagd build).
    // If keybagd ever differs (iOS update), bail instead of hooking garbage and
    // crashing the security daemon.
    unsigned char head[4];
    memcpy(head, target, sizeof(head));
    if (memcmp(head, kDrainPrologue, 4) != 0) {
        // Mismatch -> do not hook. Leave keybagd untouched.
        kcs_log("BAILED prologue mismatch target=%p bytes=%02x%02x%02x%02x",
                target, head[0], head[1], head[2], head[3]);
        return;
    }

    MSHookFunction(target, (void *)replacement_drain_backup_keys,
                   (void **)&orig_drain_backup_keys);
    kcs_log("HOOKED ok target=%p", target);
}
