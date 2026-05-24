TARGET := iphone:clang:7.0:7.0
ARCHS = armv7 armv7s arm64

INSTALL_TARGET_PROCESSES = SpringBoard

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = SGNSpringboard

SGNSpringboard_FILES = Tweak.x $(THEOS_PROJECT_DIR)/Skyglow-Notifications-Daemon/SGControlChannel.m $(THEOS_PROJECT_DIR)/Skyglow-Notifications-Daemon/SGLog.m
SGNSpringboard_CFLAGS = -fno-objc-arc -Wno-unused-function -Wno-deprecated-declarations -I..
SGNSpringboard_FRAMEWORKS = UIKit

include $(THEOS_MAKE_PATH)/tweak.mk
