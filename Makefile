# Binary Ninja Plugin Makefile
# Gamayun - Binary Ninja plugin client for Dazhbog

BN_API_REPO := https://github.com/Vector35/binaryninja-api.git
BN_API_DIR := binaryninja-api

UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Darwin)
BN_API_COMMIT ?= dev/5.3.9223
BN_INSTALL_DIR ?= /Applications/Binary Ninja.app
BN_PLUGINS_DIR ?= $(HOME)/Library/Application Support/Binary Ninja/plugins
QT6_ROOT_PATH ?= /Users/int/Qt-6.6.1
PLUGIN_EXT := dylib
NPROC := $(shell sysctl -n hw.ncpu)
else
BN_API_COMMIT ?= 2a6ad0fe00f8835093fdd4a97082c37df7a2923a
BN_INSTALL_DIR ?= /media/null/px/Downloads/binaryninja_linux_dev_personal/binaryninja
BN_PLUGINS_DIR ?= $(HOME)/.binaryninja/plugins
QT6_ROOT_PATH ?= /media/null/ares/qt/6.10.1/qtbase
PLUGIN_EXT := so
NPROC := $(shell nproc)
endif

BUILD_DIR := build
PLUGIN_NAME := libgamayun.$(PLUGIN_EXT)
PLUGIN_PATH := $(BUILD_DIR)/out/bin/$(PLUGIN_NAME)

CMAKE_FLAGS := -DBN_ALLOW_STUBS=ON -DBN_INSTALL_DIR="$(BN_INSTALL_DIR)" -DQT6_ROOT_PATH="$(QT6_ROOT_PATH)"

.PHONY: all clean install uninstall api build configure distclean rebuild info install-force

all: build

# Clone and checkout the Binary Ninja API at the specified commit
api: $(BN_API_DIR)/.git/HEAD
	@echo "Checking out binaryninja-api at $(BN_API_COMMIT)..."
	@cd $(BN_API_DIR) && git fetch origin && git checkout $(BN_API_COMMIT) 2>/dev/null || true
	@cd $(BN_API_DIR) && git submodule update --init --recursive

$(BN_API_DIR)/.git/HEAD:
	@echo "Cloning binaryninja-api..."
	git clone $(BN_API_REPO) $(BN_API_DIR)
	cd $(BN_API_DIR) && git checkout $(BN_API_COMMIT)
	cd $(BN_API_DIR) && git submodule update --init --recursive

# Configure with CMake
configure: api $(BUILD_DIR)/Makefile

$(BUILD_DIR)/Makefile: CMakeLists.txt
	@mkdir -p $(BUILD_DIR)
	cmake -S . -B $(BUILD_DIR) $(CMAKE_FLAGS)

# Build the plugin
build: configure
	@echo "Building plugin..."
	cmake --build $(BUILD_DIR) --parallel $(NPROC)

# Install the plugin to Binary Ninja plugins directory
# WARNING: Native UI plugins cannot be hot-reloaded! BN will crash if running.
# This is because Qt widgets have vtables pointing into the .so - when it's
# replaced, those pointers become invalid and any widget interaction segfaults.
install: build
	@if pgrep -x "binaryninja" > /dev/null; then \
		echo "ERROR: Binary Ninja is running!"; \
		echo "Native UI plugins cannot be hot-reloaded safely."; \
		echo "Please close Binary Ninja before installing."; \
		exit 1; \
	fi
	@echo "Installing plugin to $(BN_PLUGINS_DIR)..."
	@mkdir -p "$(BN_PLUGINS_DIR)"
	@rm -f "$(BN_PLUGINS_DIR)/$(PLUGIN_NAME)"
	cp "$(PLUGIN_PATH)" "$(BN_PLUGINS_DIR)/"
	@echo "Installed $(PLUGIN_NAME) to $(BN_PLUGINS_DIR)"

# Force install even if BN is running (will likely crash BN)
install-force: build
	@echo "WARNING: Force installing while Binary Ninja may be running!"
	@echo "This will likely crash Binary Ninja if it's open."
	@mkdir -p "$(BN_PLUGINS_DIR)"
	@rm -f "$(BN_PLUGINS_DIR)/$(PLUGIN_NAME)"
	cp "$(PLUGIN_PATH)" "$(BN_PLUGINS_DIR)/"
	@echo "Installed $(PLUGIN_NAME) to $(BN_PLUGINS_DIR)"
	@echo "NOTE: Restart Binary Ninja to load the new plugin"

# Uninstall the plugin
uninstall:
	@echo "Removing plugin from $(BN_PLUGINS_DIR)..."
	rm -f "$(BN_PLUGINS_DIR)/$(PLUGIN_NAME)"
	@echo "Uninstalled $(PLUGIN_NAME)"

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)

# Deep clean - also remove the API checkout
distclean: clean
	rm -rf $(BN_API_DIR)

# Rebuild from scratch
rebuild: clean build

# Show current configuration
info:
	@echo "Binary Ninja API commit: $(BN_API_COMMIT)"
	@echo "Binary Ninja install dir: $(BN_INSTALL_DIR)"
	@echo "Plugin install dir: $(BN_PLUGINS_DIR)"
	@echo "Plugin: $(PLUGIN_NAME)"
