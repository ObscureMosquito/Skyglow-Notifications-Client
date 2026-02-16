TARGET := iphone:clang:16.5:6.0
ARCHS = armv7 armv7s arm64 arm64e

include $(THEOS)/makefiles/common.mk

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
