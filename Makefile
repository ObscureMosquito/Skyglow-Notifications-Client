include BuildConfig.mk

SG_DAEMON_FILE_LOGGING ?= 1
SG_DAEMON_CONSOLE_LOGGING ?= 0
SG_DAEMON_TTY_LOGGING ?= 1

include $(THEOS)/makefiles/common.mk
 
TOOL_NAME = SkyglowNotificationsDaemon sgnctl
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
    Skyglow-Notifications-Daemon/platform/SGPlatformFactory.m \
    Skyglow-Notifications-Daemon/platform/SGIOSPlatform.m \
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
  -DSG_LOG_FILE_DEFAULT_ENABLED=$(SG_DAEMON_FILE_LOGGING) \
  -DSG_LOG_CONSOLE_DEFAULT_ENABLED=$(SG_DAEMON_CONSOLE_LOGGING) \
  -DSG_LOG_TTY_DEFAULT_ENABLED=$(SG_DAEMON_TTY_LOGGING) \
  -DSQLITE_THREADSAFE=1 \
  -DSQLITE_OMIT_LOAD_EXTENSION \
  -DSQLITE_DEFAULT_MEMSTATUS=0 \
  -DSQLITE_ENABLE_LOCKING_STYLE=0 \
  -DHAVE_GETHOSTUUID=0 \
  -Wno-unused-but-set-variable
SkyglowNotificationsDaemon_LDFLAGS = \
  $(THEOS_PROJECT_DIR)/libraries/openssl/lib/libssl.a \
  $(THEOS_PROJECT_DIR)/libraries/openssl/lib/libcrypto.a
# iOS 8 needs this casue whoever implemeted the jailbreak does not like me and dosent hanle mach ports properly
ifneq ($(SKYGLOW_LEGACY_BUILD),1)
SkyglowNotificationsDaemon_LDFLAGS += -Wl,-sectcreate,__RESTRICT,__restrict,/dev/null
endif
SkyglowNotificationsDaemon_CODESIGN_FLAGS = -Sentitlements.plist
SkyglowNotificationsDaemon_INSTALL_PATH = /usr/libexec/
SkyglowNotificationsDaemon_FRAMEWORKS = SystemConfiguration CFNetwork Security IOKit
SkyglowNotificationsDaemon_LIBRARIES += z

sgnctl_FILES = \
    tools/sgnctl.m \
    Skyglow-Notifications-Daemon/net/control/SGControlChannel.m \
    Skyglow-Notifications-Daemon/net/control/SGControlAuthorization.m \
    Skyglow-Notifications-Daemon/shared/SGLog.m
sgnctl_CFLAGS = -fno-objc-arc -Wno-deprecated-declarations \
    -I$(THEOS_PROJECT_DIR)/Skyglow-Notifications-Daemon/net \
    -I$(THEOS_PROJECT_DIR)/Skyglow-Notifications-Daemon/net/control \
    -I$(THEOS_PROJECT_DIR)/Skyglow-Notifications-Daemon/shared \
    -I$(THEOS_PROJECT_DIR)/Skyglow-Notifications-Daemon/platform \
    -I$(THEOS_PROJECT_DIR)/Skyglow-Notifications-Daemon/core \
    -I$(THEOS_PROJECT_DIR)/Skyglow-Notifications-Daemon/state
sgnctl_FRAMEWORKS = Foundation
sgnctl_INSTALL_PATH = /usr/local/bin


include $(THEOS_MAKE_PATH)/tool.mk

SUBPROJECTS += SGNPreferenceBundle
SUBPROJECTS += SGNSpringboard
include $(THEOS_MAKE_PATH)/aggregate.mk

after-stage::
	$(ECHO_NOTHING)mkdir -p $(THEOS_STAGING_DIR)/Library/LaunchDaemons$(ECHO_END)
	$(ECHO_NOTHING)sed 's|@DAEMON_PATH@|$(THEOS_PACKAGE_INSTALL_PREFIX)/usr/libexec/SkyglowNotificationsDaemon|g' packaging/com.skyglow.snd.plist.in > $(THEOS_STAGING_DIR)/Library/LaunchDaemons/com.skyglow.snd.plist$(ECHO_END)
	$(ECHO_NOTHING)chmod 644 $(THEOS_STAGING_DIR)/Library/LaunchDaemons/com.skyglow.snd.plist$(ECHO_END)
