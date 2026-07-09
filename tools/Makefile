# Build the sgnctl developer/control tool for the Skyglow daemon (macOS).
#   make -f tools/Makefile         # builds build/sgnctl
#   sudo build/sgnctl status       # (run as root — the daemon authorizes euid 0)
# Run from the repo root.

DAEMON_DIR := Skyglow-Notifications-Daemon
BUILD_DIR  := build
CC         := xcrun clang

INCLUDES := \
	-I$(DAEMON_DIR)/net \
	-I$(DAEMON_DIR)/shared \
	-I$(DAEMON_DIR)/platform \
	-I$(DAEMON_DIR)/core \
	-I$(DAEMON_DIR)/state

SRCS := \
	tools/sgnctl.m \
	$(DAEMON_DIR)/net/SGControlChannel.m \
	$(DAEMON_DIR)/net/SGControlAuthorization.m \
	$(DAEMON_DIR)/shared/SGLog.m

CFLAGS := -fno-objc-arc -O2 -g -Wno-deprecated-declarations $(INCLUDES)
LDFLAGS := -framework Foundation -framework CoreFoundation

.PHONY: all clean
all: $(BUILD_DIR)/sgnctl

$(BUILD_DIR)/sgnctl: $(SRCS)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) $(SRCS) $(LDFLAGS) -o $@
	@codesign -s - $@ 2>/dev/null || true
	@echo "built $@"

clean:
	rm -f $(BUILD_DIR)/sgnctl
