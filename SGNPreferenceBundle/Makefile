include ../BuildConfig.mk

include $(THEOS)/makefiles/common.mk

BUNDLE_NAME = SGNPreferenceBundle

SGNPreferenceBundle_FILES = \
    SNAlert.m \
    SNRootListController.m \
    SNStatusBannerViewController.m \
    SNLogTailViewController.m \
    SNAppToggleCell.m \
    SNAppListController.m \
    SNProfileControllerBase.m \
    SNProfileWizardViewController.m \
    SNProfileDetailViewController.m \
    SNProfileListController.m \
    SNCustomViewCell.m \
    SNDebugViewController.m \
    SNDataManager.m \
    SNChannelGateway.m \
    SNDeferredActivity.m \
    SNPaneHeader.m \
    SNLogParser.m \
    $(THEOS_PROJECT_DIR)/Skyglow-Notifications-Daemon/net/control/SGControlAuthorization.m \
    $(THEOS_PROJECT_DIR)/Skyglow-Notifications-Daemon/net/control/SGControlChannel.m \
    $(THEOS_PROJECT_DIR)/Skyglow-Notifications-Daemon/shared/SGLog.m \
    $(THEOS_PROJECT_DIR)/Skyglow-Notifications-Daemon/platform/SGCompatibilityShim.m
SGNPreferenceBundle_FRAMEWORKS = UIKit CoreGraphics CFNetwork CoreFoundation QuartzCore
SGNPreferenceBundle_PRIVATE_FRAMEWORKS = Preferences
SGNPreferenceBundle_LDFLAGS = \
  $(THEOS_PROJECT_DIR)/libraries/openssl/ios/lib/libssl.a \
  $(THEOS_PROJECT_DIR)/libraries/openssl/ios/lib/libcrypto.a \
  $(THEOS_PROJECT_DIR)/libraries/SFPFilePicker/lib/SFPFilePicker.a \
  -lsqlite3
SGNPreferenceBundle_INSTALL_PATH = /Library/PreferenceBundles
SGNPreferenceBundle_CFLAGS = -fno-objc-arc -Wno-deprecated-declarations -I$(THEOS_PROJECT_DIR)/libraries/openssl/ios/include -I.. -I$(THEOS_PROJECT_DIR)/Skyglow-Notifications-Daemon/core -I$(THEOS_PROJECT_DIR)/Skyglow-Notifications-Daemon/state -I$(THEOS_PROJECT_DIR)/Skyglow-Notifications-Daemon/net -I$(THEOS_PROJECT_DIR)/Skyglow-Notifications-Daemon/net/control -I$(THEOS_PROJECT_DIR)/Skyglow-Notifications-Daemon/crypto -I$(THEOS_PROJECT_DIR)/Skyglow-Notifications-Daemon/payload -I$(THEOS_PROJECT_DIR)/Skyglow-Notifications-Daemon/platform -I$(THEOS_PROJECT_DIR)/Skyglow-Notifications-Daemon/shared
ifeq ($(SGN_LEGACY_BUILD),1)
ADDITIONAL_CFLAGS += -DAPI_AVAILABLE\(...\)= -DAPI_DEPRECATED\(...\)= -DAPI_UNAVAILABLE\(...\)= -Dinstancetype=id
endif

include $(THEOS_MAKE_PATH)/bundle.mk
