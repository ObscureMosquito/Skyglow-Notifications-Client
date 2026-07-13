ifeq ($(THEOS_PACKAGE_SCHEME),rootless)
TARGET := iphone:clang:16.5:17.0
ARCHS := arm64 arm64e
SKYGLOW_LEGACY_BUILD := 0
ADDITIONAL_CFLAGS += -Wno-error=deprecated-declarations
ADDITIONAL_CFLAGS += -Wno-error=ambiguous-macro
else
TARGET := iphone:clang:7.0:4.0
ARCHS := armv7 armv7s arm64
SKYGLOW_LEGACY_BUILD := 1
endif
