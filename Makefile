TARGET := iphone:clang:7.0:4.0
ARCHS = armv7 armv7s arm64

export ADDITIONAL_CFLAGS += -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 -fno-builtin -fno-stack-protector
export ADDITIONAL_OBJCFLAGS += -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 -fno-builtin -fno-stack-protector
export ADDITIONAL_CCFLAGS += -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 -fno-builtin -fno-stack-protector

include $(THEOS)/makefiles/common.mk
 
TOOL_NAME = SkyglowNotificationsDaemon
SkyglowNotificationsDaemon_FILES = \
    Skyglow-Notifications-Daemon/main.m \
    Skyglow-Notifications-Daemon/SGLog.m \
    Skyglow-Notifications-Daemon/SGProtocolHandler.m \
    Skyglow-Notifications-Daemon/SGServerLocator.m \
    Skyglow-Notifications-Daemon/SGDatabaseManager.m \
    Skyglow-Notifications-Daemon/SGCryptoEngine.m \
    Skyglow-Notifications-Daemon/SGTokenManager.m \
    Skyglow-Notifications-Daemon/SGStatusServer.c \
    Skyglow-Notifications-Daemon/SGPayloadParser.m \
    Skyglow-Notifications-Daemon/SGConfiguration.m \
    Skyglow-Notifications-Daemon/SGKeepAliveStrategy.c \
    Skyglow-Notifications-Daemon/SGReachabilityMonitor.m \
    Skyglow-Notifications-Daemon/SGDaemon.m \
    Skyglow-Notifications-Daemon/SGAvailability.m \
    Skyglow-Notifications-Daemon/SGControlChannel.m \
    Skyglow-Notifications-Daemon/SGCompatibilityShim.m
SkyglowNotificationsDaemon_CFLAGS = -fno-objc-arc -Wno-unused-result -I$(THEOS_PROJECT_DIR)/openssl/include
SkyglowNotificationsDaemon_LDFLAGS = \
  -Wl,-sectcreate,__RESTRICT,__restrict,/dev/null \
  $(THEOS_PROJECT_DIR)/libraries/openssl/lib/libssl.a \
  $(THEOS_PROJECT_DIR)/libraries/openssl/lib/libcrypto.a
SkyglowNotificationsDaemon_CODESIGN_FLAGS = -Sentitlements.plist
SkyglowNotificationsDaemon_INSTALL_PATH = /usr/local/bin
SkyglowNotificationsDaemon_FRAMEWORKS = UIKit SystemConfiguration CFNetwork Security IOKit
SkyglowNotificationsDaemon_LIBRARIES += sqlite3


include $(THEOS_MAKE_PATH)/tool.mk

SUBPROJECTS += SGNPreferenceBundle
SUBPROJECTS += SGNSpringboard
SUBPROJECTS += SGNSettings
include $(THEOS_MAKE_PATH)/aggregate.mk
