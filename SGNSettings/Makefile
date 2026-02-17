TARGET := iphone:clang:16.5:6.0
INSTALL_TARGET_PROCESSES = Preferences


include $(THEOS)/makefiles/common.mk

TWEAK_NAME = SGNSettings

SGNSettings_FILES = Tweak.x
SGNSettings_CFLAGS = -fobjc-arc

include $(THEOS_MAKE_PATH)/tweak.mk
