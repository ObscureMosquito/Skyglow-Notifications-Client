TARGET := iphone:clang:7.0:7.0
ARCHS = armv7 armv7s
#status item, remove from apsd in app list 
include $(THEOS)/makefiles/common.mk

BUNDLE_NAME = SGNPreferenceBundle

SGNPreferenceBundle_FILES = \
    SNRootListController.m \
    SNLogViewController.m \
    SNLogTailViewController.m \
    SNAppToggleCell.m \
    SNAppListController.m \
    SNServerInfoViewController.m \
    SNProfileListController.m \
    SNCustomViewCell.m \
    SNDebugViewController.m \
    SNCustomizationViewController.m \
    SNDataManager.m \
    SNChannelGateway.m \
    $(THEOS_PROJECT_DIR)/Skyglow-Notifications-Daemon/SGControlChannel.m \
    $(THEOS_PROJECT_DIR)/Skyglow-Notifications-Daemon/SGLog.m
SGNPreferenceBundle_FRAMEWORKS = UIKit CoreGraphics CFNetwork CoreFoundation QuartzCore
SGNPreferenceBundle_PRIVATE_FRAMEWORKS = Preferences
SGNPreferenceBundle_LDFLAGS = \
  $(THEOS_PROJECT_DIR)/libraries/openssl/lib/libssl.a \
  $(THEOS_PROJECT_DIR)/libraries/openssl/lib/libcrypto.a \
  $(THEOS_PROJECT_DIR)/libraries/SFPFilePicker/lib/SFPFilePicker.a \
  -lsqlite3
SGNPreferenceBundle_INSTALL_PATH = /Library/PreferenceBundles
SGNPreferenceBundle_CFLAGS = -fobjc-arc -Wno-deprecated-declarations -I$(THEOS_PROJECT_DIR)/libraries/openssl/include -I..
ADDITIONAL_CFLAGS += -D"API_AVAILABLE(...)= " -D"API_DEPRECATED(...)= " -D"API_UNAVAILABLE(...)= " -D"instancetype=id"

include $(THEOS_MAKE_PATH)/bundle.mk

TOOL_NAME = sndrestart

sndrestart_FILES = sndrestart.c
sndrestart_INSTALL_PATH = /Library/PreferenceBundles/SGNPreferenceBundle.bundle
sndrestart_CODESIGN_FLAGS = -S../entitlements.plist

include $(THEOS_MAKE_PATH)/tool.mk

after-stage::
	$(ECHO_NOTHING)chmod 755 $(THEOS_STAGING_DIR)/Library/PreferenceBundles/SGNPreferenceBundle.bundle/sndrestart$(ECHO_END)
	$(ECHO_NOTHING)chmod 4755 $(THEOS_STAGING_DIR)/Library/PreferenceBundles/SGNPreferenceBundle.bundle/sndrestart$(ECHO_END)