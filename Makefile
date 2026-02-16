TARGET := iphone:clang:16.5:6.0
ARCHS = armv7
include $(THEOS)/makefiles/common.mk
THEOS_DEVICE_IP = iPod
 
TOOL_NAME = SkyglowNotificationsDaemon
SkyglowNotificationsDaemon_FILES = main.m CommonDefinitions.m Protocol.m ServerLocationFinder.m DBManager.m CryptoManager.m AppMachMsgs.m Tokens.m
SkyglowNotificationsDaemon_CFLAGS = -Wno-deprecated-declarations -Wno-objc-method-access -Wno-module-import-in-extern-c -I$(THEOS_PROJECT_DIR)/openssl/include
SkyglowNotificationsDaemon_LDFLAGS = \
  $(THEOS_PROJECT_DIR)/openssl/lib/libssl.a \
  $(THEOS_PROJECT_DIR)/openssl/lib/libcrypto.a
SkyglowNotificationsDaemon_CODESIGN_FLAGS = -Sentitlements.plist
SkyglowNotificationsDaemon_INSTALL_PATH = /usr/local/bin
SkyglowNotificationsDaemon_FRAMEWORKS = UIKit SystemConfiguration CFNetwork Security
SkyglowNotificationsDaemon_LIBRARIES += sqlite3


include $(THEOS_MAKE_PATH)/tool.mk

SUBPROJECTS += skyglownotificationsdaemonsettings
SUBPROJECTS += SGNSpringboard
include $(THEOS_MAKE_PATH)/aggregate.mk
