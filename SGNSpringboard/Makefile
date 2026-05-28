TARGET := iphone:clang:7.0:4.0
ARCHS = armv7 armv7s arm64

INSTALL_TARGET_PROCESSES = SpringBoard

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = SGNSpringboard

SGNSpringboard_FILES = Tweak.x SGNStatusBarIndicator.mm $(THEOS_PROJECT_DIR)/Skyglow-Notifications-Daemon/SGControlChannel.m $(THEOS_PROJECT_DIR)/Skyglow-Notifications-Daemon/SGLog.m $(THEOS_PROJECT_DIR)/Skyglow-Notifications-Daemon/SGCompatibilityShim.m
SGNSpringboard_CFLAGS = -fno-objc-arc -Wno-unused-function -Wno-deprecated-declarations -I.. -I$(THEOS_PROJECT_DIR)/libraries/libstatusbar/src
# iOS 4.x predates libc++ (/usr/lib/libc++.1.dylib, iOS 5.0+); link the GNU
# libstdc++ that ships on the whole iOS 4->11 range so dyld can load the tweak.
# (_CCFLAGS is theos's C++/ObjC++ compile-flag var in this tree.)
SGNSpringboard_CCFLAGS += -stdlib=libstdc++
SGNSpringboard_LDFLAGS += -stdlib=libstdc++ -L$(THEOS_PROJECT_DIR)/libraries/libstatusbar/lib -lstatusbar
SGNSpringboard_FRAMEWORKS = UIKit CoreGraphics

include $(THEOS_MAKE_PATH)/tweak.mk
