TARGET := iphone:clang:6.0:6.0
ARCHS = armv7

include $(THEOS)/makefiles/common.mk

THEOS_DEVICE_IP = iPod
 
TOOL_NAME = SkyglowNotificationsDaemon
SkyglowNotificationsDaemon_FILES = \
    Skyglow-Notifications-Daemon/main.m \
    Skyglow-Notifications-Daemon/SGProtocolHandler.m \
    Skyglow-Notifications-Daemon/SGServerLocator.m \
    Skyglow-Notifications-Daemon/SGDatabaseManager.m \
    Skyglow-Notifications-Daemon/SGCryptoEngine.m \
    Skyglow-Notifications-Daemon/SGMachServer.m \
    Skyglow-Notifications-Daemon/SGTokenManager.m \
    Skyglow-Notifications-Daemon/SGStatusServer.c \
    Skyglow-Notifications-Daemon/SGPayloadParser.m \
    Skyglow-Notifications-Daemon/SGConfiguration.m \
    Skyglow-Notifications-Daemon/SGKeepAliveStrategy.c \
    Skyglow-Notifications-Daemon/SGReachabilityMonitor.m \
    Skyglow-Notifications-Daemon/SGDaemon.m
SkyglowNotificationsDaemon_CFLAGS = -fno-objc-arc -Wno-unused-result -I$(THEOS_PROJECT_DIR)/openssl/include
SkyglowNotificationsDaemon_LDFLAGS = \
  $(THEOS_PROJECT_DIR)/openssl/lib/libssl.a \
  $(THEOS_PROJECT_DIR)/openssl/lib/libcrypto.a
SkyglowNotificationsDaemon_CODESIGN_FLAGS = -Sentitlements.plist
SkyglowNotificationsDaemon_INSTALL_PATH = /usr/local/bin
SkyglowNotificationsDaemon_FRAMEWORKS = UIKit SystemConfiguration CFNetwork Security IOKit PersistentConnection
SkyglowNotificationsDaemon_LIBRARIES += sqlite3


include $(THEOS_MAKE_PATH)/tool.mk

SUBPROJECTS += SGNPreferenceBundle
SUBPROJECTS += SGNSpringboard
SUBPROJECTS += SGNSettings
include $(THEOS_MAKE_PATH)/aggregate.mk