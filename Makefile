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
TEST_BINARY := .cache/tests/parsers
THIRD_PARTY_HEADERS := third_party/nlohmann/json.hpp third_party/tl/expected.hpp
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
.PHONY: dependencies-check diagnostics verify-binary clean _not-implemented FORCE

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

test: test-unit test-fixtures test-cli test-integration test-syslog test-deadline

test-unit: dependencies-check build $(TEST_BINARY)
	$(TEST_BINARY)
	$(PYTHON) tests/unit/version_test.py "$(BINARY)" --version "$(VERSION)" --revision "$(REVISION)" --source-date-epoch "$(SOURCE_DATE_EPOCH)" --target "$(TARGET)"

$(TEST_BINARY): tests/unit/parsers_test.cpp src/base64url.cpp src/base64url.hpp src/strict_json.cpp src/strict_json.hpp src/parse_error.hpp $(THIRD_PARTY_HEADERS) Makefile
	@mkdir -p $(@D)
	$(CXX) -Isrc -Ithird_party $(CXXFLAGS) tests/unit/parsers_test.cpp src/base64url.cpp src/strict_json.cpp $(LDFLAGS) -o $@

test-cli:
	@$(MAKE) --no-print-directory _not-implemented TARGET_NAME=$@

test-readme:
	@$(MAKE) --no-print-directory _not-implemented TARGET_NAME=$@

dependencies-check:
	$(PYTHON) scripts/check_dependencies.py

diagnostics: dependencies-check
	@$(CXX) --version
	@$(PYTHON) -c 'import json; value=json.load(open("third_party/dependencies.json")); print(" ".join(item["name"]+"="+item["version"] for item in value["dependencies"]))'

check: dependencies-check test build verify-binary

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
