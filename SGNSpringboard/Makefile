TARGET := iphone:clang:7.0:4.0
ARCHS = armv7 armv7s arm64

INSTALL_TARGET_PROCESSES = SpringBoard

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = SGNSpringboard

SGNSpringboard_FILES = Tweak.x $(THEOS_PROJECT_DIR)/Skyglow-Notifications-Daemon/SGControlChannel.m $(THEOS_PROJECT_DIR)/Skyglow-Notifications-Daemon/SGLog.m $(THEOS_PROJECT_DIR)/Skyglow-Notifications-Daemon/SGCompatibilityShim.m
SGNSpringboard_CFLAGS = -fno-objc-arc -Wno-unused-function -Wno-deprecated-declarations -I.. -I$(THEOS_PROJECT_DIR)/libraries/libstatusbar/src
SGNSpringboard_LDFLAGS += -L$(THEOS_PROJECT_DIR)/libraries/libstatusbar/lib -lstatusbar
SGNSpringboard_FRAMEWORKS = UIKit

include $(THEOS_MAKE_PATH)/tweak.mk
