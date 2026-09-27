# KeybagCacheSkip
# Rootless + Roothide dual-variant build. THEOS_PACKAGE_SCHEME is overridden
# by CI per-job (rootless vs roothide); the ?= below is only the local default.
export TARGET = iphone:clang:latest:16.0
export ARCHS = arm64

# scheme 由 CI/环境变量决定（rootless 默认，roothide job 传 roothide）。
# 必须用 ?= —— 普通赋值会覆盖 CI 注入的环境变量，roothide job 会被打回 rootless。
THEOS_PACKAGE_SCHEME ?= rootless
export THEOS_PACKAGE_SCHEME

export _THEOS_PLATFORM_DPKG_DEB_COMPRESSION = gzip

TWEAK_NAME = KeybagCacheSkip
KeybagCacheSkip_FILES = Tweak.xm
KeybagCacheSkip_CFLAGS = -fobjc-arc

include $(THEOS)/makefiles/common.mk
include $(THEOS_MAKE_PATH)/tweak.mk

# After install: kill keybagd so launchd relaunches it without the rebuild spike.
INSTALL_TARGET_PROCESSES = keybagd
