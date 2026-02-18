TARGET := iphone:clang:6.0:6.0
INSTALL_TARGET_PROCESSES = Preferences
ARCHS = armv7

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = SGNSettings

SGNSettings_FILES = Tweak.x
SGNSettings_CFLAGS = -fobjc-arc
SGNSettings_FRAMEWORKS = UIKit
SGNSettings_PRIVATE_FRAMEWORKS = Preferences
ADDITIONAL_CFLAGS += -D"API_AVAILABLE(...)= " -D"API_DEPRECATED(...)= " -D"API_UNAVAILABLE(...)= " -D"instancetype=id"

include $(THEOS_MAKE_PATH)/tweak.mk
