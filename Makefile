SHELL := /bin/sh
.DEFAULT_GOAL := build

CXX ?= c++
PYTHON ?= python3
PKG_CONFIG ?= pkg-config
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
ADAPTER_TEST_BINARY := .cache/tests/adapters
CORE_SOURCES := src/base64url.cpp src/crypto.cpp src/direct_verifier.cpp src/issuer_verifier.cpp src/jwks.cpp src/jws.cpp src/openssh_certificate.cpp src/strict_json.cpp
ADAPTER_SOURCES := src/command.cpp src/config.cpp src/syslog_logger.cpp $(CORE_SOURCES)
LIBCRYPTO_CFLAGS := $(shell $(PKG_CONFIG) --cflags libcrypto 2>/dev/null) -DOPENSSL_API_COMPAT=0x30000000L
LIBCRYPTO_LIBS := $(shell $(PKG_CONFIG) --libs libcrypto 2>/dev/null)
THIRD_PARTY_HEADERS := third_party/nlohmann/json.hpp third_party/tl/expected.hpp
CPPFLAGS := '-DCREDBIND_VERSION="$(VERSION)"' '-DCREDBIND_REVISION="$(REVISION)"' '-DCREDBIND_SOURCE_DATE_EPOCH="$(SOURCE_DATE_EPOCH)"' '-DCREDBIND_TARGET="$(TARGET)"'
CXXFLAGS := -std=c++17 -O2 -fPIE -fvisibility=hidden -fvisibility-inlines-hidden -fstack-protector-strong -D_FORTIFY_SOURCE=3 -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Wshadow -Wformat=2 -Werror -ffile-prefix-map=$(CURDIR)=. -fdebug-prefix-map=$(CURDIR)=. -fmacro-prefix-map=$(CURDIR)=.

ifeq ($(TARGET_SYSTEM),linux)
LDFLAGS := -pie -Wl,-z,relro,-z,now,-z,noexecstack -Wl,--as-needed
STRIP_FLAGS := --strip-all
else ifeq ($(TARGET_SYSTEM),darwin)
LDFLAGS := -Wl,-pie,-dead_strip
STRIP_FLAGS := -u -r
else
$(error unsupported TARGET_SYSTEM $(TARGET_SYSTEM))
endif

.PHONY: build credbind-ssh-authorized-keys fixtures test test-unit test-fixtures test-cli-adapters
.PHONY: test-integration-adapters test-syslog-adapters
.PHONY: test-conformance test-cli test-integration test-syslog test-deadline
.PHONY: test-openssh test-sanitize test-fuzz-smoke fuzz test-readme check
.PHONY: dependencies-check crypto-check diagnostics verify-binary clean _not-implemented FORCE

build: $(BINARY)

credbind-ssh-authorized-keys: $(BINARY)

$(BINARY): src/main.cpp src/command.hpp src/config.hpp src/syslog_logger.hpp $(ADAPTER_SOURCES) Makefile FORCE
	@mkdir -p $(DIST_DIR)
	@temporary="$@.tmp"; rm -f "$$temporary"; \
		$(CXX) -Isrc -Ithird_party $(LIBCRYPTO_CFLAGS) $(CPPFLAGS) $(CXXFLAGS) src/main.cpp $(ADAPTER_SOURCES) $(LDFLAGS) $(LIBCRYPTO_LIBS) -o "$$temporary"; \
		strip $(STRIP_FLAGS) "$$temporary"; \
		chmod 0755 "$$temporary"; \
		mv -f "$$temporary" "$@"

fixtures:
	$(PYTHON) scripts/fixtures.py fetch

test: test-unit test-fixtures test-cli test-integration test-syslog test-deadline

test-unit: dependencies-check crypto-check build $(TEST_BINARY) $(ADAPTER_TEST_BINARY)
	$(TEST_BINARY)
	$(ADAPTER_TEST_BINARY) "$(CURDIR)/tests/fixtures/issuer-jwks.json"
	$(PYTHON) scripts/verify_crypto_binary.py --binary "$(TEST_BINARY)"
	$(PYTHON) tests/unit/version_test.py "$(BINARY)" --version "$(VERSION)" --revision "$(REVISION)" --source-date-epoch "$(SOURCE_DATE_EPOCH)" --target "$(TARGET)"

test-fixtures: dependencies-check crypto-check $(TEST_BINARY)
	$(PYTHON) scripts/fixtures.py verify
	$(PYTHON) tests/fixtures/parser_vectors_test.py "$(TEST_BINARY)"

$(ADAPTER_TEST_BINARY): tests/unit/adapters_test.cpp src/command.hpp src/config.hpp src/syslog_logger.hpp $(ADAPTER_SOURCES) $(THIRD_PARTY_HEADERS) Makefile
	@mkdir -p $(@D)
	$(CXX) -Isrc -Ithird_party $(LIBCRYPTO_CFLAGS) $(CXXFLAGS) tests/unit/adapters_test.cpp $(ADAPTER_SOURCES) $(LDFLAGS) $(LIBCRYPTO_LIBS) -o $@

$(TEST_BINARY): tests/unit/parsers_test.cpp src/base64url.cpp src/base64url.hpp src/crypto.cpp src/crypto.hpp src/direct_verifier.cpp src/direct_verifier.hpp src/issuer_verifier.cpp src/issuer_verifier.hpp src/jwks.cpp src/jwks.hpp src/jws.cpp src/jws.hpp src/openssh_certificate.cpp src/openssh_certificate.hpp src/strict_json.cpp src/strict_json.hpp src/parse_error.hpp $(THIRD_PARTY_HEADERS) Makefile
	@mkdir -p $(@D)
	$(CXX) -Isrc -Ithird_party $(LIBCRYPTO_CFLAGS) $(CXXFLAGS) tests/unit/parsers_test.cpp src/base64url.cpp src/crypto.cpp src/direct_verifier.cpp src/issuer_verifier.cpp src/jwks.cpp src/jws.cpp src/openssh_certificate.cpp src/strict_json.cpp $(LDFLAGS) $(LIBCRYPTO_LIBS) -o $@

test-cli:
	@$(MAKE) --no-print-directory test-cli-adapters
	@echo "test-cli cannot report complete: shared config-init defaults and useful-policy flag grammar are unspecified" >&2
	@exit 1

test-cli-adapters: build
	$(PYTHON) tests/cli/adapters_test.py "$(BINARY)"

test-integration-adapters: test-cli-adapters test-syslog-adapters
	@echo "specified offline config/check/render/verify integration passed"

test-integration: test-integration-adapters

test-syslog-adapters: fixtures $(ADAPTER_TEST_BINARY)
	$(ADAPTER_TEST_BINARY) "$(CURDIR)/tests/fixtures/issuer-jwks.json" \
		"$(CURDIR)/.cache/conformance/v1.0.0-rc.1/corpus/credbind-ssh-v1-conformance-v1.0.0-rc.1/vectors/ssh-carrier-p256.json" \
		"$(CURDIR)/.cache/conformance/v1.0.0-rc.1/corpus/credbind-ssh-v1-conformance-v1.0.0-rc.1/keys/issuer-jwks.json"

test-syslog: test-syslog-adapters

test-deadline: fixtures $(ADAPTER_TEST_BINARY)
	$(ADAPTER_TEST_BINARY) "$(CURDIR)/tests/fixtures/issuer-jwks.json" \
		"$(CURDIR)/.cache/conformance/v1.0.0-rc.1/corpus/credbind-ssh-v1-conformance-v1.0.0-rc.1/vectors/ssh-carrier-p256.json" \
		"$(CURDIR)/.cache/conformance/v1.0.0-rc.1/corpus/credbind-ssh-v1-conformance-v1.0.0-rc.1/keys/issuer-jwks.json"

test-readme:
	@$(MAKE) --no-print-directory _not-implemented TARGET_NAME=$@

dependencies-check:
	$(PYTHON) scripts/check_dependencies.py

crypto-check:
	@$(PKG_CONFIG) --atleast-version=3.0 libcrypto || { echo "system OpenSSL libcrypto >= 3.0 is required" >&2; exit 1; }

diagnostics: dependencies-check crypto-check
	@$(CXX) --version
	@echo "libcrypto=$$($(PKG_CONFIG) --modversion libcrypto)"
	@$(PYTHON) -c 'import json; value=json.load(open("third_party/dependencies.json")); print(" ".join(item["name"]+"="+item["version"] for item in value["dependencies"]))'

check: dependencies-check test build verify-binary

verify-binary: build
	@test "$(TARGET)" = "$(HOST_SYSTEM)-$(HOST_ARCH)" || { echo "verify-binary requires the host target" >&2; exit 1; }
	$(PYTHON) scripts/verify_binary.py --binary "$(BINARY)" --target "$(TARGET)" --version "$(VERSION)" --revision "$(REVISION)" --source-date-epoch "$(SOURCE_DATE_EPOCH)"

test-conformance test-openssh test-sanitize test-fuzz-smoke fuzz:
	@$(MAKE) --no-print-directory _not-implemented TARGET_NAME=$@

_not-implemented:
	@echo "$(TARGET_NAME) is not implemented in the build baseline and cannot report success" >&2
	@exit 1

FORCE:

clean:
	rm -rf dist .cache
