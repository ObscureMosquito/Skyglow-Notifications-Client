TARGET := iphone:clang:16.5:6.0
ARCHS = armv7 arm64 arm64e

include $(THEOS)/makefiles/common.mk

BUNDLE_NAME = SGNPreferenceBundle

SGNPreferenceBundle_FILES = \
    SNRootListController.m \
    SNLogViewController.m \
    SNAppToggleCell.m \
    SNAppListController.m \
    SNServerInfoViewController.m \
    SNCustomViewCell.m \
    SNDebugViewController.m \
    SNDataManager.m
SGNPreferenceBundle_FRAMEWORKS = UIKit CoreGraphics CFNetwork CoreFoundation QuartzCore
SGNPreferenceBundle_PRIVATE_FRAMEWORKS = Preferences
SGNPreferenceBundle_LDFLAGS = \
  $(THEOS_PROJECT_DIR)/openssl/lib/libssl.a \
  $(THEOS_PROJECT_DIR)/openssl/lib/libcrypto.a \
  -lsqlite3
SGNPreferenceBundle_INSTALL_PATH = /Library/PreferenceBundles
SGNPreferenceBundle_CFLAGS = -fobjc-arc -Wno-deprecated-declarations -I$(THEOS_PROJECT_DIR)/openssl/include
#ADDITIONAL_CFLAGS += -D"API_AVAILABLE(...)= " -D"API_DEPRECATED(...)= " -D"API_UNAVAILABLE(...)= " -D"instancetype=id"

include $(THEOS_MAKE_PATH)/bundle.mk

TOOL_NAME = sndrestart

sndrestart_FILES = sndrestart.c
sndrestart_INSTALL_PATH = /Library/PreferenceBundles/SGNPreferenceBundle.bundle
sndrestart_CODESIGN_FLAGS = -S../entitlements.plist

include $(THEOS_MAKE_PATH)/tool.mk

after-stage::
	$(ECHO_NOTHING)chmod 755 $(THEOS_STAGING_DIR)/Library/PreferenceBundles/SGNPreferenceBundle.bundle/sndrestart$(ECHO_END)
	$(ECHO_NOTHING)chmod 4755 $(THEOS_STAGING_DIR)/Library/PreferenceBundles/SGNPreferenceBundle.bundle/sndrestart$(ECHO_END)