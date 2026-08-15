include BuildConfig.mk

SG_DAEMON_FILE_LOGGING ?= 1
SG_DAEMON_CONSOLE_LOGGING ?= 0
SG_DAEMON_TTY_LOGGING ?= 1

include $(THEOS)/makefiles/common.mk
 
ifeq ($(SGN_MACOS),1)
SGN_OPENSSL      := $(THEOS_PROJECT_DIR)/libraries/openssl/macos
SGN_PLATFORM_SRC := Skyglow-Notifications-Daemon/platform/SGMacPlatform.m
SGN_DAEMON_PATH   = /usr/local/libexec/SkyglowNotificationsDaemon
else
SGN_OPENSSL      := $(THEOS_PROJECT_DIR)/libraries/openssl/ios
SGN_PLATFORM_SRC := Skyglow-Notifications-Daemon/platform/SGIOSPlatform.m
SGN_DAEMON_PATH   = $(THEOS_PACKAGE_INSTALL_PREFIX)/usr/libexec/SkyglowNotificationsDaemon
endif

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
    $(SGN_PLATFORM_SRC) \
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
  -I$(SGN_OPENSSL)/include \
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
ifeq ($(SGN_MACOS),1)
SkyglowNotificationsDaemon_CFLAGS += -Wno-deprecated-declarations -Wno-error
SkyglowNotificationsDaemon_USE_MODULES = 0
endif
SkyglowNotificationsDaemon_LDFLAGS = \
  $(SGN_OPENSSL)/lib/libssl.a \
  $(SGN_OPENSSL)/lib/libcrypto.a
# iOS 8 needs this casue whoever implemeted the jailbreak does not like me and dosent hanle mach ports properly
ifneq ($(SGN_MACOS),1)
ifneq ($(SGN_LEGACY_BUILD),1)
SkyglowNotificationsDaemon_LDFLAGS += -Wl,-sectcreate,__RESTRICT,__restrict,/dev/null
endif
endif
ifeq ($(SGN_MACOS),1)
SkyglowNotificationsDaemon_CODESIGN_FLAGS = -S
SkyglowNotificationsDaemon_INSTALL_PATH = /usr/local/libexec
else
SkyglowNotificationsDaemon_CODESIGN_FLAGS = -Sentitlements.plist
SkyglowNotificationsDaemon_INSTALL_PATH = /usr/libexec/
endif
SkyglowNotificationsDaemon_FRAMEWORKS = SystemConfiguration CFNetwork Security IOKit
ifeq ($(SGN_MACOS),1)
SkyglowNotificationsDaemon_FRAMEWORKS += Foundation CoreFoundation
endif
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
sgnctl_FRAMEWORKS = Foundation CoreFoundation
sgnctl_INSTALL_PATH = /usr/local/bin
ifeq ($(SGN_MACOS),1)
sgnctl_USE_MODULES = 0
endif


include $(THEOS_MAKE_PATH)/tool.mk

ifneq ($(SGN_MACOS),1)
SUBPROJECTS += SGNPreferenceBundle
SUBPROJECTS += SGNSpringboard
endif
include $(THEOS_MAKE_PATH)/aggregate.mk

after-stage::
	$(ECHO_NOTHING)mkdir -p $(THEOS_STAGING_DIR)/Library/LaunchDaemons$(ECHO_END)
	$(ECHO_NOTHING)sed 's|@DAEMON_PATH@|$(SGN_DAEMON_PATH)|g' packaging/com.skyglow.snd.plist.in > $(THEOS_STAGING_DIR)/Library/LaunchDaemons/com.skyglow.snd.plist$(ECHO_END)
	$(ECHO_NOTHING)chmod 644 $(THEOS_STAGING_DIR)/Library/LaunchDaemons/com.skyglow.snd.plist$(ECHO_END)

ifeq ($(SGN_MACOS),1)
after-stage::
	$(ECHO_NOTHING)codesign --force --sign - "$(THEOS_STAGING_DIR)/usr/local/libexec/SkyglowNotificationsDaemon"$(ECHO_END)
	$(ECHO_NOTHING)codesign --force --sign - "$(THEOS_STAGING_DIR)/usr/local/bin/sgnctl"$(ECHO_END)
endif

ifeq ($(SGN_MACOS),1)
SGN_PKG_ID  := $(shell grep -i '^Package:' control | cut -d' ' -f2-)
SGN_PKG_VER := $(shell grep -i '^Version:' control | cut -d' ' -f2-)

macpkg: stage
	rm -rf "$(THEOS_STAGING_DIR)/Library/Application Support"
	rm -rf $(THEOS_PROJECT_DIR)/packages/.scripts
	mkdir -p $(THEOS_PROJECT_DIR)/packages/.scripts
	cp layout/DEBIAN/postinst $(THEOS_PROJECT_DIR)/packages/.scripts/postinstall
	chmod 755 $(THEOS_PROJECT_DIR)/packages/.scripts/postinstall
	pkgbuild --root "$(THEOS_STAGING_DIR)" --scripts "$(THEOS_PROJECT_DIR)/packages/.scripts" --identifier "$(SGN_PKG_ID)" --version "$(SGN_PKG_VER)" --ownership recommended "$(THEOS_PROJECT_DIR)/packages/$(SGN_PKG_ID)-$(MACOS_ARCH)-$(SGN_PKG_VER).pkg"
	@echo "[Skyglow] pkg -> packages/$(SGN_PKG_ID)-$(MACOS_ARCH)-$(SGN_PKG_VER).pkg"
endif
