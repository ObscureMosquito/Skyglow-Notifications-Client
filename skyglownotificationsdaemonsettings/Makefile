TARGET := iphone:clang:6.0:6.0
ARCHS = armv7

include $(THEOS)/makefiles/common.mk

# --- 1. The Preference Bundle ---
BUNDLE_NAME = SkyglowNotificationsDaemonSettings

SkyglowNotificationsDaemonSettings_FILES = SNRootListController.m SNLogViewController.m SNRegisterAccount.m ../ServerLocationFinder.m SNAppToggleCell.m SNAppListController.m SNServerInfoViewController.m SNCustomViewCell.m
SkyglowNotificationsDaemonSettings_FRAMEWORKS = UIKit CoreGraphics CFNetwork
SkyglowNotificationsDaemonSettings_PRIVATE_FRAMEWORKS = Preferences
SkyglowNotificationsDaemonSettings_LDFLAGS = \
  $(THEOS_PROJECT_DIR)/openssl/lib/libssl.a \
  $(THEOS_PROJECT_DIR)/openssl/lib/libcrypto.a \
  -lsqlite3
SkyglowNotificationsDaemonSettings_INSTALL_PATH = /Library/PreferenceBundles
SkyglowNotificationsDaemonSettings_CFLAGS = -fobjc-arc -Wno-arc-performSelector-leaks -I$(THEOS_PROJECT_DIR)/openssl/include
ADDITIONAL_CFLAGS += -D"API_AVAILABLE(...)= " -D"API_DEPRECATED(...)= " -D"API_UNAVAILABLE(...)= " -D"instancetype=id"

include $(THEOS_MAKE_PATH)/bundle.mk

# The Restart Helper Tool
TOOL_NAME = sndrestart

sndrestart_FILES = sndrestart.c
sndrestart_INSTALL_PATH = /Library/PreferenceBundles/SkyglowNotificationsDaemonSettings.bundle
sndrestart_CODESIGN_FLAGS = -S

include $(THEOS_MAKE_PATH)/tool.mk

after-stage::
	# 1. Ensure the binary is executable
	$(ECHO_NOTHING)chmod 755 $(THEOS_STAGING_DIR)/Library/PreferenceBundles/SkyglowNotificationsDaemonSettings.bundle/sndrestart$(ECHO_END)
	
	# 2. Set the SUID bit (4755) so it runs as root
	# Note: This only sets the file mode in the package. 
	# The device's installer (dpkg) must respect this, which it usually does.
	$(ECHO_NOTHING)chmod 4755 $(THEOS_STAGING_DIR)/Library/PreferenceBundles/SkyglowNotificationsDaemonSettings.bundle/sndrestart$(ECHO_END)