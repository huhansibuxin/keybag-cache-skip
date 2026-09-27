# KeybagCacheSkip

Stop `/usr/libexec/keybagd` from rebuilding its backup-keys cache on every
launch — iOS 16, rootless **and** roothide.

> **v1.2.0 is the silent release.** It performs **zero file I/O**. The diagnostic
> marker files that v1.1.x appended on every launch (written while we were hunting
> the four failure modes documented below) are gone. If you ever need that
> instrumented build, it lives in the `v1.1.2` tag.

## The problem

On a data-filled iOS 16 device, `keybagd` rebuilds
`/private/var/keybags/backup/backup_keys_cache.sql3` **on every launch**. That
file is the backup-specific cache of the data volume's file-encryption keys
(`WrappedKeys`). On a real device it reaches **~306 MB / ~1.27 M rows**, and the
rebuild pins a CPU core near **100 % for ~20 s** and heats the phone.

`keybagd` is an on-demand daemon launched with `-t 15` (idle-exit) and
`EnablePressuredExit`, so it comes and goes — and every launch repeats the spike.

## Why it is safe to skip

- **Backup is off** on the target devices, so the backup-keys cache is dead
  weight; `keybagd` tolerates a missing cache and derives keys on demand.
- Reverse-engineering the binary shows the rebuild routine returns a sqlite
  handle and **its only caller does `cbz w0`**. Returning **NULL** therefore
  means "no cache handle" — the routine's own natural "no cache" state. No db
  opened, no rows inserted, no `VACUUM`, no corruption.

## How it works

`Tweak.xm` patches the rebuild routine's entry in place — no substrate, no
trampoline:

```
0x1000167cc   pacibsp …          ->   mov x0, #0     (0xD2800000)
                                      ret            (0xD65F03C0)
```

Reverse-engineered addresses (device `keybagd`, iOS 16.6.1 / 20G81, sha1
`0aad8913…`):

| Role | Address |
|---|---|
| `REPLACE INTO WrappedKeys ...` string | `0x100027eb1` |
| single-row insert helper | `0x10000e7c0` (binds 3 params, one `sqlite3_step`) |
| 1.27 M-row loop body | `0x1000169d0` (`x20 += 0x7c`, `x26` = row counter) |
| **rebuild routine entry** | **`0x1000167cc`** (`pacibsp`) |
| its only caller | `0x100016f48` → `cbz w0` (NULL-safe) |

`mov x0,#0` zeroes the full register, so the caller's `cbz w0` always takes the
NULL branch. Because the routine's own `pacibsp` is overwritten the return
address stays unsigned, so a bare `ret` is the correct pair (not `retab`).

### Four constraints, each learned the hard way

1. **Zero substrate symbols.** keybagd cannot `dlopen` `libellekit` /
   `libsubstrate`, so a tweak that links it fails to load *silently* — no logs,
   no effect. This build references no substrate symbol (no `MSHookFunction`, no
   `%hook`) and relies on `-Wl,-dead_strip_dylibs` plus a CI assertion to keep it
   that way.
2. **The slide must come from the main executable.** In this rootless/roothide
   jailbreak the injected `systemhook-<UUID>.dylib` owns dyld image index 0, so
   index 0 is *not* keybagd. We scan for `filetype == MH_EXECUTE`.
3. **iOS enforces W^X.** The patched page is restored to `r-x` *before* anything
   on it is fetched. The target shares its 16 KB page with `main()`, so an RWX
   page there kills the daemon on `main()`'s first instruction (SIGBUS /
   `KERN_PROTECTION_FAILURE`) in a 10-second crash loop.
4. **Guard on the prologue.** The patch is applied only when the bytes still
   decode to the expected `pacibsp` (or already to our own patch, for
   idempotency). On an unknown build the tweak **bails and leaves keybagd
   untouched** — it never pokes garbage into a security daemon.

## Verified on device

Controlled test (`launchctl kickstart -k` on keybagd, waiting past the old
~22 s rebuild window):

| Signal | Before restart | After restart |
|---|---|---|
| `backup_keys_cache.sql3` size / mtime | 306667520 / 00:53 | **306667520 / 00:53 (unchanged)** |
| `keybagd` crash reports | 25 | **25** (no new) |
| daemon state | running | **running, `killall -0` rc=0** |
| `db_check_once` in keybagd.log | 0 | **0** |

The ~20 s / 100 % CPU spike is gone and the daemon starts clean every time.

## Build

Dual-variant (rootless + roothide) via GitHub Actions:

```bash
git clone https://github.com/huhansibuxin/keybag-cache-skip
cd keybag-cache-skip
make package                                  # rootless
THEOS_PACKAGE_SCHEME=roothide make package    # roothide
```

CI artifacts: `KeybagCacheSkip-rootless` / `KeybagCacheSkip-roothide`. The
workflow fails the build if the dylib re-gains a substrate dependency **or** any
diagnostic string.

## Install

Install the matching `.deb` with your package manager / TrollFools. `keybagd` is
killed afterwards so `launchd` relaunches it already patched.

> **roothide users:** install the `*-roothide.deb`. The Filter targets the daemon
> by `Executables = ( "keybagd" )`, which roothide/ElleKit honours (note:
> `ExecutableNames` is a different, non-working key).

## Caveats

- **Backups.** This deliberately prevents the backup-keys cache from being
  built. If you later turn on iCloud / local backup, **uninstall this tweak
  first** (keys are still derived on demand, but backup setup may behave
  differently).
- **iOS version.** The patch address is specific to iOS 16.6.1 (20G81). On any
  other build the prologue will not match and the tweak will simply do nothing —
  by design.
