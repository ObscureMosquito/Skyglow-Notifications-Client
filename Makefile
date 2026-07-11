TARGET := iphone:clang:7.0:4.0
ARCHS = armv7 armv7s arm64

include $(THEOS)/makefiles/common.mk
 
TOOL_NAME = SkyglowNotificationsDaemon
SkyglowNotificationsDaemon_FILES = \
    Skyglow-Notifications-Daemon/core/main.m \
    Skyglow-Notifications-Daemon/core/SGNotificationProcessor.m \
    Skyglow-Notifications-Daemon/core/SGConnectionPolicy.c \
    Skyglow-Notifications-Daemon/shared/SGLog.m \
    Skyglow-Notifications-Daemon/net/SGProtocolHandler.m \
    Skyglow-Notifications-Daemon/net/SGServerLocator.m \
    Skyglow-Notifications-Daemon/state/SGDatabaseManager.m \
    Skyglow-Notifications-Daemon/crypto/SGCryptoEngine.m \
    Skyglow-Notifications-Daemon/crypto/SGTokenManager.m \
    Skyglow-Notifications-Daemon/shared/SGStatusServer.c \
    Skyglow-Notifications-Daemon/payload/SGPayloadParser.m \
    Skyglow-Notifications-Daemon/payload/SGJSONParser.m \
    Skyglow-Notifications-Daemon/payload/SGStructuredTLV.m \
    Skyglow-Notifications-Daemon/state/SGConfiguration.m \
    Skyglow-Notifications-Daemon/state/SGKeychainStore.m \
    Skyglow-Notifications-Daemon/net/SGKeepAliveStrategy.c \
    Skyglow-Notifications-Daemon/net/SGKeepAliveOffload.m \
    Skyglow-Notifications-Daemon/net/SGReachabilityMonitor.m \
    Skyglow-Notifications-Daemon/core/SGDaemon.m \
    Skyglow-Notifications-Daemon/platform/SGAvailability.m \
    Skyglow-Notifications-Daemon/platform/SGPlatformIOS.m \
    Skyglow-Notifications-Daemon/state/SGAtomicFile.m \
    Skyglow-Notifications-Daemon/state/SGDurableInbox.m \
    Skyglow-Notifications-Daemon/state/SGStateStore.m \
    Skyglow-Notifications-Daemon/state/SGMigration.m \
    Skyglow-Notifications-Daemon/net/control/SGControlAuthorization.m \
    Skyglow-Notifications-Daemon/net/control/SGControlChannel.m \
    Skyglow-Notifications-Daemon/net/control/SGControlCommandRouter.m \
    Skyglow-Notifications-Daemon/platform/SGCompatibilityShim.m \
    libraries/sqlite/sqlite3.c
SkyglowNotificationsDaemon_CFLAGS = -fno-objc-arc -Wno-unused-result \
  -fstack-protector-all -D_FORTIFY_SOURCE=2 \
  -I$(THEOS_PROJECT_DIR)/libraries/openssl/include \
  -I$(THEOS_PROJECT_DIR)/libraries/sqlite/include \
  -I$(THEOS_PROJECT_DIR)/Skyglow-Notifications-Daemon/core \
  -I$(THEOS_PROJECT_DIR)/Skyglow-Notifications-Daemon/state \
  -I$(THEOS_PROJECT_DIR)/Skyglow-Notifications-Daemon/net \
  -I$(THEOS_PROJECT_DIR)/Skyglow-Notifications-Daemon/net/control \
  -I$(THEOS_PROJECT_DIR)/Skyglow-Notifications-Daemon/crypto \
  -I$(THEOS_PROJECT_DIR)/Skyglow-Notifications-Daemon/payload \
  -I$(THEOS_PROJECT_DIR)/Skyglow-Notifications-Daemon/platform \
  -I$(THEOS_PROJECT_DIR)/Skyglow-Notifications-Daemon/shared \
  -DSQLITE_THREADSAFE=1 \
  -DSQLITE_OMIT_LOAD_EXTENSION \
  -DSQLITE_DEFAULT_MEMSTATUS=0 \
  -DSQLITE_ENABLE_LOCKING_STYLE=0 \
  -DHAVE_GETHOSTUUID=0 \
  -Wno-unused-but-set-variable
SkyglowNotificationsDaemon_LDFLAGS = \
  -Wl,-sectcreate,__RESTRICT,__restrict,/dev/null \
  $(THEOS_PROJECT_DIR)/libraries/openssl/lib/libssl.a \
  $(THEOS_PROJECT_DIR)/libraries/openssl/lib/libcrypto.a
SkyglowNotificationsDaemon_CODESIGN_FLAGS = -Sentitlements.plist
SkyglowNotificationsDaemon_INSTALL_PATH = /usr/local/bin
SkyglowNotificationsDaemon_FRAMEWORKS = SystemConfiguration CFNetwork Security IOKit
SkyglowNotificationsDaemon_LIBRARIES += z


include $(THEOS_MAKE_PATH)/tool.mk

SUBPROJECTS += SGNPreferenceBundle
SUBPROJECTS += SGNSpringboard
#SUBPROJECTS += SGNSettings
include $(THEOS_MAKE_PATH)/aggregate.mk
