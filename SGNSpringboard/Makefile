TARGET := iphone:clang:6.0:6.0
ARCHS = armv7

INSTALL_TARGET_PROCESSES = SpringBoard

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = SGNSpringboard

SGNSpringboard_FILES = Tweak.x
SGNSpringboard_CFLAGS = -fno-objc-arc -Wno-unused-function -Wno-deprecated-declarations
SGNSpringboard_FRAMEWORKS = UIKit

include $(THEOS_MAKE_PATH)/tweak.mk
