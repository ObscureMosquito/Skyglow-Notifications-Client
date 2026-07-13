include ../BuildConfig.mk

INSTALL_TARGET_PROCESSES = SpringBoard

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = SGNSpringboard

SGNSpringboard_FILES = Tweak.x SGNAppIntent.m SGNDaemonBridge.m SGNNativePush.m SGNNativePushBroker.m backends/SGIOS17NotificationBackend.m backends/SGIOSLegacyNotificationBackend.m backends/SGIOSClassicNotificationBackend.m $(THEOS_PROJECT_DIR)/Skyglow-Notifications-Daemon/net/control/SGControlAuthorization.m $(THEOS_PROJECT_DIR)/Skyglow-Notifications-Daemon/net/control/SGControlChannel.m $(THEOS_PROJECT_DIR)/Skyglow-Notifications-Daemon/shared/SGLog.m $(THEOS_PROJECT_DIR)/Skyglow-Notifications-Daemon/state/SGAtomicFile.m $(THEOS_PROJECT_DIR)/Skyglow-Notifications-Daemon/state/SGDurableInbox.m $(THEOS_PROJECT_DIR)/Skyglow-Notifications-Daemon/platform/SGCompatibilityShim.m #SGNStatusBarIndicator.mm
SGNSpringboard_CFLAGS = -fno-objc-arc -Wno-unused-function -Wno-deprecated-declarations -I.. -I$(THEOS_PROJECT_DIR)/SGNSpringboard -I$(THEOS_PROJECT_DIR)/SGNSpringboard/backends -I$(THEOS_PROJECT_DIR)/libraries/libstatusbar/src -I$(THEOS_PROJECT_DIR)/Skyglow-Notifications-Daemon/core -I$(THEOS_PROJECT_DIR)/Skyglow-Notifications-Daemon/state -I$(THEOS_PROJECT_DIR)/Skyglow-Notifications-Daemon/net -I$(THEOS_PROJECT_DIR)/Skyglow-Notifications-Daemon/net/control -I$(THEOS_PROJECT_DIR)/Skyglow-Notifications-Daemon/crypto -I$(THEOS_PROJECT_DIR)/Skyglow-Notifications-Daemon/payload -I$(THEOS_PROJECT_DIR)/Skyglow-Notifications-Daemon/platform -I$(THEOS_PROJECT_DIR)/Skyglow-Notifications-Daemon/shared
SGNSpringboard_CCFLAGS += -stdlib=libstdc++
#SGNSpringboard_LDFLAGS += -stdlib=libstdc++ -L$(THEOS_PROJECT_DIR)/libraries/libstatusbar/lib -lstatusbar
SGNSpringboard_FRAMEWORKS = UIKit CoreGraphics

include $(THEOS_MAKE_PATH)/tweak.mk
