TARGET := iphone:clang:latest:6.0
export TARGET=iphone:clang:7.0
ARCHS = armv7 armv7s arm64

include $(THEOS)/makefiles/common.mk

BUNDLE_NAME = SkyglowNotificationsDaemonSettings

SkyglowNotificationsDaemonSettings_FILES = SNRootListController.m SNGuideViewController.m SNLogViewController.m SNCustomViewCell.m SNRegisterAccount.m
SkyglowNotificationsDaemonSettings_FRAMEWORKS = UIKit
SkyglowNotificationsDaemonSettings_PRIVATE_FRAMEWORKS = Preferences CoreGraphics CFNetwork
SkyglowNotificationsDaemonSettings_LDFLAGS = -stdlib=libstdc++ -lstdc++
SkyglowNotificationsDaemonSettings_LIBRARIES = applist ssl crypto
SkyglowNotificationsDaemonSettings_INSTALL_PATH = /Library/PreferenceBundles
SkyglowNotificationsDaemonSettings_CFLAGS = -fobjc-arc -Wno-arc-performSelector-leaks

include $(THEOS_MAKE_PATH)/bundle.mk
