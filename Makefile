TARGET := iphone:clang:7.0:6.0
ARCHS = armv7
include $(THEOS)/makefiles/common.mk
THEOS_DEVICE_IP = iPod
 
TOOL_NAME = SkyglowNotificationsDaemon
SkyglowNotificationsDaemon_FILES = \
    Skyglow-Notifications-Daemon/main.m \
    Skyglow-Notifications-Daemon/Protocol.m \
    Skyglow-Notifications-Daemon/ServerLocationFinder.m \
    Skyglow-Notifications-Daemon/DBManager.m \
    Skyglow-Notifications-Daemon/CryptoManager.m \
    Skyglow-Notifications-Daemon/LocalIPC.m \
    Skyglow-Notifications-Daemon/Tokens.m \
    Skyglow-Notifications-Daemon/StatusServer.c \
    Skyglow-Notifications-Daemon/PayloadParser.m \
    Skyglow-Notifications-Daemon/Globals.m \
    Skyglow-Notifications-Daemon/GrowthAlgorithm.c \
    Skyglow-Notifications-Daemon/NetworkMonitor.m \
    Skyglow-Notifications-Daemon/NotificationDaemon.m
SkyglowNotificationsDaemon_CFLAGS = -fno-objc-arc -Wno-deprecated-declarations -I$(THEOS_PROJECT_DIR)/openssl/include
SkyglowNotificationsDaemon_LDFLAGS = \
  $(THEOS_PROJECT_DIR)/openssl/lib/libssl.a \
  $(THEOS_PROJECT_DIR)/openssl/lib/libcrypto.a
SkyglowNotificationsDaemon_CODESIGN_FLAGS = -Sentitlements.plist
SkyglowNotificationsDaemon_INSTALL_PATH = /usr/local/bin
SkyglowNotificationsDaemon_FRAMEWORKS = UIKit SystemConfiguration CFNetwork Security IOKit
SkyglowNotificationsDaemon_LIBRARIES += sqlite3


include $(THEOS_MAKE_PATH)/tool.mk

SUBPROJECTS += SGNPreferenceBundle
SUBPROJECTS += SGNSpringboard
SUBPROJECTS += SGNSettings
include $(THEOS_MAKE_PATH)/aggregate.mk

TOOL_NAME = sgn_test_token

sgn_test_token_FILES = sgn_test_token.m
sgn_test_token_FRAMEWORKS = Foundation
sgn_test_token_INSTALL_PATH = /usr/local/bin
sgn_test_token_CODESIGN_FLAGS = -S

include $(THEOS_MAKE_PATH)/tool.mk