ifeq ($(PLATFORM),OSX)
MACOS_ARCH ?= $(shell uname -m)
ifeq ($(MACOS_ARCH),arm64)
TARGET := macosx:clang:latest:11.0
else
TARGET := macosx:clang:latest:10.8
endif
ARCHS := $(MACOS_ARCH)
SGN_MACOS := 1
SGN_LEGACY_BUILD := 0
else ifeq ($(THEOS_PACKAGE_SCHEME),rootless)
TARGET := iphone:clang:16.5:15.0
ARCHS := arm64 arm64e
SGN_LEGACY_BUILD := 0
ADDITIONAL_CFLAGS += -Wno-error=deprecated-declarations
ADDITIONAL_CFLAGS += -Wno-error=ambiguous-macro
else
TARGET := iphone:clang:7.0:4.0
ARCHS := armv7 armv7s arm64
SGN_LEGACY_BUILD := 1
endif
