# KeybagCacheSkip

Skip `/usr/libexec/keybagd`'s backup-keys cache rebuild on iOS 16 (rootless / roothide).

## The problem

On a data-filled iOS 16 device, `keybagd` rebuilds
`/var/keybags/backup/backup_keys_cache.sql3` **from scratch on every cold boot**.
That file is the **backup-specific** cache of the data volume's file-encryption
keys (`WrappedKeys`). On a real device it grows to ~306 MB / ~1.27M rows. The
rebuild pins a CPU core for ~20 s and heats the phone.

Worse, `keybagd` is launched with `-t 15` (idle-exit after 15 s) and
`EnablePressuredExit=true`, so it keeps getting killed mid-rebuild → the sqlite
db gets corrupted → relaunch → rebuild again. A self-reinforcing storm.

## Why it's safe to skip

- **Backup is disabled** on the target devices, so the backup-keys cache is dead
  weight. `keybagd` tolerates a missing cache and derives keys on demand.
- Reverse-engineering the `keybagd` binary showed the rebuild routine
  (`drain_backup_keys`) returns a sqlite handle, and its only caller does
  `cbz w0` — if it returns **NULL**, the caller simply skips storing any cache
  handle, i.e. the natural "no cache" state. No db opened, no rows inserted, no
  `VACUUM`, no corruption.

## How it works

`Tweak.xm` hooks the rebuild routine by its (preferred-load) address +
ASLR slide, using `MSHookFunction`, and makes it `return NULL` immediately.

Reverse-engineered addresses (from the device `keybagd` binary, iOS 16):

| Role | Address |
|---|---|
| `REPLACE INTO WrappedKeys ...` string | `0x100027eb1` |
| single-row insert helper (`0x10000e7c0`) | binds 3 params, `sqlite3_step` once |
| 1.27M-row loop body (`0x1000169d0`) | `x20 += 0x7c`, `x26` = row counter |
| **rebuild fn entry `drain_backup_keys` (`0x1000167cc`)** | `pacibsp`; opens cache db, enumerates all keys, loops, commits, closes |
| caller (`0x100016f48`) | `bl #0x1000167cc` → `cbz w0` (NULL-safe) |
| `VACUUM` path | only fires on backup start/stop — irrelevant when backup is off |

### Safety guard

The hook only installs if the first 4 bytes at the target address still match
this binary's `pacibsp` prologue (`7F 23 03 D5`). If `keybagd` ever changes
(iOS update), the tweak **bails and leaves keybagd untouched** instead of
hooking garbage and crashing the security daemon. No silent mis-hooks.

## Build

Dual-variant (rootless + roothide) via GitHub Actions:

```bash
git clone https://github.com/huhansibuxin/keybag-cache-skip
cd keybag-cache-skip
# local rootless build
make package
# or, for roothide:
THEOS_PACKAGE_SCHEME=roothide make package
```

CI artifacts: `KeybagCacheSkip-rootless` / `KeybagCacheSkip-roothide`.

## Install

Install the matching `.deb` with your package manager / TrollFools. After
install, `keybagd` is killed so `launchd` relaunches it **without** the rebuild
spike.

> **Note (roothide):** install the `*-roothide.deb`. The Filter targets the
> `keybagd` executable, so it only loads into that daemon.

## ⚠️ Caveat — do not use if you rely on backup

This tweak deliberately prevents the backup-keys cache from being built. If you
later turn on iCloud / local device backup, **disable (uninstall) this tweak
first**, otherwise backup key-caching is skipped (keys are still derived on
demand, but backup setup may be slower / behave differently).
