TARGET := iphone:clang:latest:6.0
export TARGET=iphone:clang:7.0
ARCHS = armv7 armv7s
INSTALL_TARGET_PROCESSES = SpringBoard


include $(THEOS)/makefiles/common.mk

TWEAK_NAME = SkyglowNotificationsAPNSHook

SkyglowNotificationsAPNSHook_FILES = Tweak.x
SkyglowNotificationsAPNSHook_CFLAGS = -fobjc-arc
SkyglowNotificationsAPNSHook_FRAMEWORKS = UIKit 

include $(THEOS_MAKE_PATH)/tweak.mk
