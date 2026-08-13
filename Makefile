SHELL := /bin/sh
.DEFAULT_GOAL := build

CXX ?= c++
PYTHON ?= python3
HOST_SYSTEM := $(shell uname -s | tr '[:upper:]' '[:lower:]')
HOST_MACHINE := $(shell uname -m)
HOST_ARCH := $(if $(filter arm64 aarch64,$(HOST_MACHINE)),arm64,$(if $(filter x86_64 amd64,$(HOST_MACHINE)),amd64,$(HOST_MACHINE)))
TARGET_SYSTEM ?= $(HOST_SYSTEM)
TARGET_ARCH ?= $(HOST_ARCH)
TARGET := $(TARGET_SYSTEM)-$(TARGET_ARCH)
VERSION ?= v0.0.0-dev
REVISION ?= $(shell git rev-parse --verify HEAD)
SOURCE_DATE_EPOCH ?= $(shell git show -s --format=%ct HEAD)
DIST_ROOT ?= dist
DIST_DIR := $(DIST_ROOT)/$(TARGET)
BINARY := $(DIST_DIR)/credbind-ssh-authorized-keys
CPPFLAGS := '-DCREDBIND_VERSION="$(VERSION)"' '-DCREDBIND_REVISION="$(REVISION)"' '-DCREDBIND_SOURCE_DATE_EPOCH="$(SOURCE_DATE_EPOCH)"' '-DCREDBIND_TARGET="$(TARGET)"'
CXXFLAGS := -std=c++17 -O2 -fPIE -fstack-protector-strong -D_FORTIFY_SOURCE=3 -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Wshadow -Wformat=2 -Werror -ffile-prefix-map=$(CURDIR)=. -fdebug-prefix-map=$(CURDIR)=. -fmacro-prefix-map=$(CURDIR)=.

ifeq ($(TARGET_SYSTEM),linux)
LDFLAGS := -pie -Wl,-z,relro,-z,now,-z,noexecstack -Wl,--as-needed
STRIP_FLAGS := --strip-all
else ifeq ($(TARGET_SYSTEM),darwin)
LDFLAGS := -Wl,-pie,-dead_strip
STRIP_FLAGS := -u -r
else
$(error unsupported TARGET_SYSTEM $(TARGET_SYSTEM))
endif

.PHONY: build credbind-ssh-authorized-keys fixtures test test-unit test-fixtures
.PHONY: test-conformance test-cli test-integration test-syslog test-deadline
.PHONY: test-openssh test-sanitize test-fuzz-smoke fuzz test-readme check
.PHONY: verify-binary clean _not-implemented FORCE

build: $(BINARY)

credbind-ssh-authorized-keys: $(BINARY)

$(BINARY): src/main.cpp Makefile FORCE
	@mkdir -p $(DIST_DIR)
	@temporary="$@.tmp"; rm -f "$$temporary"; \
		$(CXX) $(CPPFLAGS) $(CXXFLAGS) src/main.cpp $(LDFLAGS) -o "$$temporary"; \
		strip $(STRIP_FLAGS) "$$temporary"; \
		chmod 0755 "$$temporary"; \
		mv -f "$$temporary" "$@"

fixtures:
	$(PYTHON) scripts/fixtures.py fetch

test: test-unit test-cli

test-unit: build
	$(PYTHON) tests/unit/version_test.py "$(BINARY)" --version "$(VERSION)" --revision "$(REVISION)" --source-date-epoch "$(SOURCE_DATE_EPOCH)" --target "$(TARGET)"

test-cli: test-unit

test-readme: test-unit

check: test build verify-binary

verify-binary: build
	@test "$(TARGET)" = "$(HOST_SYSTEM)-$(HOST_ARCH)" || { echo "verify-binary requires the host target" >&2; exit 1; }
	$(PYTHON) scripts/verify_binary.py --binary "$(BINARY)" --target "$(TARGET)" --version "$(VERSION)" --revision "$(REVISION)" --source-date-epoch "$(SOURCE_DATE_EPOCH)"

test-fixtures test-conformance test-integration test-syslog test-deadline test-openssh test-sanitize test-fuzz-smoke fuzz:
	@$(MAKE) --no-print-directory _not-implemented TARGET_NAME=$@

_not-implemented:
	@echo "$(TARGET_NAME) is not implemented in the build baseline and cannot report success" >&2
	@exit 1

FORCE:

clean:
	rm -rf dist .cache
