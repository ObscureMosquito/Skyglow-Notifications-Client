TARGET := iphone:clang:7.0:6.0
ARCHS = armv7
include $(THEOS)/makefiles/common.mk
THEOS_DEVICE_IP = iPod
 
TOOL_NAME = SkyglowNotificationsDaemon
SkyglowNotificationsDaemon_FILES = \
    Skyglow-Notifications-Daemon/main.m \
    Skyglow-Notifications-Daemon/CommonDefinitions.m \
    Skyglow-Notifications-Daemon/Protocol.m \
    Skyglow-Notifications-Daemon/ServerLocationFinder.m \
    Skyglow-Notifications-Daemon/DBManager.m \
    Skyglow-Notifications-Daemon/CryptoManager.m \
    Skyglow-Notifications-Daemon/AppMachMsgs.m \
    Skyglow-Notifications-Daemon/Tokens.m \
    Skyglow-Notifications-Daemon/StatusServer.c
SkyglowNotificationsDaemon_CFLAGS = -Wno-deprecated-declarations -I$(THEOS_PROJECT_DIR)/openssl/include
SkyglowNotificationsDaemon_LDFLAGS = \
  $(THEOS_PROJECT_DIR)/openssl/lib/libssl.a \
  $(THEOS_PROJECT_DIR)/openssl/lib/libcrypto.a
SkyglowNotificationsDaemon_CODESIGN_FLAGS = -Sentitlements.plist
SkyglowNotificationsDaemon_INSTALL_PATH = /usr/local/bin
SkyglowNotificationsDaemon_FRAMEWORKS = UIKit SystemConfiguration CFNetwork Security
SkyglowNotificationsDaemon_LIBRARIES += sqlite3


include $(THEOS_MAKE_PATH)/tool.mk

SUBPROJECTS += SGNPreferenceBundle
SUBPROJECTS += SGNSpringboard
SUBPROJECTS += SGNSettings
include $(THEOS_MAKE_PATH)/aggregate.mk
