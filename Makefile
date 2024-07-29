TARGET := iphone:clang:latest:6.0
export TARGET=iphone:clang:6.0
ARCHS = armv7 armv7s
include $(THEOS)/makefiles/common.mk

TOOL_NAME = SkyglowNotificationsDaemon

SkyglowNotificationsDaemon_FILES = main.m KeyManager.m CommonDefinitions.m
SkyglowNotificationsDaemon_CFLAGS = -Wno-deprecated-declarations -Wno-objc-method-access -Wno-module-import-in-extern-c -Wno-error
SkyglowNotificationsDaemon_LDFLAGS = -stdlib=libstdc++ -lstdc++
SkyglowNotificationsDaemon_CODESIGN_FLAGS = -Sentitlements.plist
SkyglowNotificationsDaemon_INSTALL_PATH = /usr/local/bin
SkyglowNotificationsDaemon_FRAMEWORKS = UIKit SystemConfiguration
SkyglowNotificationsDaemon_LIBRARIES = ssl crypto


include $(THEOS_MAKE_PATH)/tool.mk

SUBPROJECTS += skyglownotificationsdaemonsettings
include $(THEOS_MAKE_PATH)/aggregate.mk
