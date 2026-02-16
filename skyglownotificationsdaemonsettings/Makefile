TARGET := iphone:clang:16.5:6.0
ARCHS = armv7

include $(THEOS)/makefiles/common.mk

# --- 1. The Preference Bundle ---
BUNDLE_NAME = SkyglowNotificationsDaemonSettings

SkyglowNotificationsDaemonSettings_FILES = SNRootListController.m SNGuideViewController.m SNLogViewController.m SNCustomViewCell.m SNRegisterAccount.m ../ServerLocationFinder.m SNAppToggleCell.m SNAppListController.m
SkyglowNotificationsDaemonSettings_FRAMEWORKS = UIKit
SkyglowNotificationsDaemonSettings_PRIVATE_FRAMEWORKS = Preferences CoreGraphics CFNetwork
SkyglowNotificationsDaemonSettings_LDFLAGS = \
  $(THEOS_PROJECT_DIR)/openssl/lib/libssl.a \
  $(THEOS_PROJECT_DIR)/openssl/lib/libcrypto.a
SkyglowNotificationsDaemonSettings_INSTALL_PATH = /Library/PreferenceBundles
SkyglowNotificationsDaemonSettings_CFLAGS = -fobjc-arc -Wno-arc-performSelector-leaks -I$(THEOS_PROJECT_DIR)/openssl/include

include $(THEOS_MAKE_PATH)/bundle.mk

# --- 2. The Restart Helper Tool ---
TOOL_NAME = sndrestart

sndrestart_FILES = sndrestart.c
# We install it INTO the bundle so it's self-contained
sndrestart_INSTALL_PATH = /Library/PreferenceBundles/SkyglowNotificationsDaemonSettings.bundle
# Sign it with entitlements if needed (usually pseudo-signing is enough for this)
sndrestart_CODESIGN_FLAGS = -S

include $(THEOS_MAKE_PATH)/tool.mk

# --- 3. Permissions Magic (The "Setuid" bit) ---
# This runs after the build is staged but before it's packaged into a .deb
after-stage::
	# 1. Ensure the binary is executable
	$(ECHO_NOTHING)chmod 755 $(THEOS_STAGING_DIR)/Library/PreferenceBundles/SkyglowNotificationsDaemonSettings.bundle/sndrestart$(ECHO_END)
	
	# 2. Set the SUID bit (4755) so it runs as root
	# Note: This only sets the file mode in the package. 
	# The device's installer (dpkg) must respect this, which it usually does.
	$(ECHO_NOTHING)chmod 4755 $(THEOS_STAGING_DIR)/Library/PreferenceBundles/SkyglowNotificationsDaemonSettings.bundle/sndrestart$(ECHO_END)