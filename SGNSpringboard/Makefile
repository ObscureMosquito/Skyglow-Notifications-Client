TARGET := iphone:clang:16.5:6.0
ARCHS = armv7 armv7s arm64 arm64e
ARCHS = armv7 armv7s
INSTALL_TARGET_PROCESSES = SpringBoard

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = SGNSpringboard

SGNSpringboard_FILES = Tweak.x
SGNSpringboard_CFLAGS = -fobjc-arc -Wno-deprecated-declarations

include $(THEOS_MAKE_PATH)/tweak.mk
