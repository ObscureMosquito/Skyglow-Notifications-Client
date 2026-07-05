TARGET := iphone:clang:7.0:7.0
INSTALL_TARGET_PROCESSES = Preferences
ARCHS = armv7 armv7s arm64

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = SGNSettings

SGNSettings_FILES = Tweak.x
SGNSettings_CFLAGS = -fobjc-arc
SGNSettings_FRAMEWORKS = UIKit
SGNSettings_PRIVATE_FRAMEWORKS = Preferences
ADDITIONAL_CFLAGS += -DAPI_AVAILABLE\(...\)= -DAPI_DEPRECATED\(...\)= -DAPI_UNAVAILABLE\(...\)= -Dinstancetype=id

include $(THEOS_MAKE_PATH)/tweak.mk
