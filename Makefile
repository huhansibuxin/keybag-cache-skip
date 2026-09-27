# KeybagCacheSkip
# Rootless + Roothide dual-variant build. THEOS_PACKAGE_SCHEME is overridden
# by CI per-job (rootless vs roothide); the ?= below is only the local default.
export TARGET = iphone:clang:latest:16.0
# arm64e: matches the substrate-free LocalStorageSkip build that is PROVEN to
# dlopen inside keybagd on the test device (its masquerade test loaded fine).
export ARCHS = arm64e

# scheme 由 CI/环境变量决定（rootless 默认，roothide job 传 roothide）。
# 必须用 ?= —— 普通赋值会覆盖 CI 注入的环境变量，roothide job 会被打回 rootless。
THEOS_PACKAGE_SCHEME ?= rootless
export THEOS_PACKAGE_SCHEME

export _THEOS_PLATFORM_DPKG_DEB_COMPRESSION = gzip

TWEAK_NAME = KeybagCacheSkip
KeybagCacheSkip_FILES = Tweak.xm

# ⚠️ 这是本插件能否在 keybagd 里加载的生死开关（2026-09-28 实机证明）：
# keybagd 进程里 libellekit.dylib(=libsubstrate) 加载不出来，所以任何 LC_LOAD_DYLIB
# 里带 substrate 的 dylib 都会被 dlopen **静默失败** —— 插件一行日志都不会有。
# `-dead_strip_dylibs` 让链接器丢掉「零符号引用」的库，从而丢掉 Theos 自动加的
# -lsubstrate（本源码已不使用 MSHookFunction/MSHookMessageEx/任何 substrate 符号）。
# CI 里有一条 otool 断言，一旦 substrate 回来会直接 fail 构建。
KeybagCacheSkip_LDFLAGS = -Wl,-dead_strip_dylibs
# 体积优先：源码只有几百行，不含 ObjC/stdio（无任何文件 I/O），-Os 让产物尽可能小。
KeybagCacheSkip_CFLAGS = -Os
# 关掉 -Werror，避免小警告挂掉 CI（与 LocalStorageSkip / NIP 同款安全网）
ERROR_ON_WARNINGS = 0

include $(THEOS)/makefiles/common.mk
include $(THEOS_MAKE_PATH)/tweak.mk

# After install: kill keybagd so launchd relaunches it with the patch armed.
INSTALL_TARGET_PROCESSES = keybagd
