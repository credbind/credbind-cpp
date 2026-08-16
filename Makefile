SHELL := /bin/sh
.DEFAULT_GOAL := build

CXX ?= c++
PYTHON ?= python3
PKG_CONFIG ?= pkg-config
CREDBIND_GO_ROOT ?= $(abspath ../credbind-go)
OPENSSH_TEST_BINARY ?= $(BINARY)
CREDBIND_LIVE_REQUEST ?=
CREDBIND_LIVE_CELL ?=
CREDBIND_LIVE_ACTION_SOURCE ?=
CREDBIND_LIVE_EVIDENCE_OUTPUT ?=
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
SANITIZE_TEST_BINARY := .cache/tests/parsers-sanitize
SANITIZE_ADAPTER_TEST_BINARY := .cache/tests/adapters-sanitize
FUZZ_DIR := .cache/fuzz
FUZZ_CXX ?= $(shell if test -x /opt/homebrew/opt/llvm/bin/clang++; then echo /opt/homebrew/opt/llvm/bin/clang++; else command -v clang++; fi)
LLVM_SYMBOLIZER ?= $(shell if test -x /opt/homebrew/opt/llvm/bin/llvm-symbolizer; then echo /opt/homebrew/opt/llvm/bin/llvm-symbolizer; elif test -n "$(FUZZ_CXX)" && test -x "$$(dirname "$(FUZZ_CXX)")/llvm-symbolizer"; then echo "$$(dirname "$(FUZZ_CXX)")/llvm-symbolizer"; fi)
SYMBOLIZER_ENV := $(if $(LLVM_SYMBOLIZER),ASAN_SYMBOLIZER_PATH=$(LLVM_SYMBOLIZER),)
ifeq ($(HOST_SYSTEM),darwin)
SANITIZER_ENV := ASAN_OPTIONS=detect_leaks=0 $(SYMBOLIZER_ENV)
else
SANITIZER_ENV := $(SYMBOLIZER_ENV)
endif
FUZZ_ENV := $(SYMBOLIZER_ENV)
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
.PHONY: test-openssh test-live test-sanitize test-fuzz-smoke fuzz _fuzz-smoke test-readme check
.PHONY: dependencies-check crypto-check fuzz-check diagnostics verify-binary clean _not-implemented FORCE

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

test: test-unit test-fixtures test-conformance test-cli test-integration test-syslog test-deadline

test-unit: dependencies-check crypto-check build $(TEST_BINARY) $(ADAPTER_TEST_BINARY)
	$(TEST_BINARY)
	$(ADAPTER_TEST_BINARY) "$(CURDIR)/tests/fixtures/issuer-jwks.json"
	$(PYTHON) scripts/verify_crypto_binary.py --binary "$(TEST_BINARY)"
	$(PYTHON) tests/unit/version_test.py "$(BINARY)" --version "$(VERSION)" --revision "$(REVISION)" --source-date-epoch "$(SOURCE_DATE_EPOCH)" --target "$(TARGET)"

test-fixtures: dependencies-check crypto-check $(TEST_BINARY)
	$(PYTHON) scripts/fixtures.py verify
	$(PYTHON) tests/fixtures/parser_vectors_test.py "$(TEST_BINARY)"

test-conformance: dependencies-check crypto-check $(TEST_BINARY) $(ADAPTER_TEST_BINARY)
	$(PYTHON) scripts/fixtures.py verify
	$(PYTHON) tests/conformance/shared_cases_test.py "$(TEST_BINARY)" "$(ADAPTER_TEST_BINARY)"

$(ADAPTER_TEST_BINARY): tests/unit/adapters_test.cpp src/command.hpp src/config.hpp src/syslog_logger.hpp $(ADAPTER_SOURCES) $(THIRD_PARTY_HEADERS) Makefile
	@mkdir -p $(@D)
	$(CXX) -Isrc -Ithird_party $(LIBCRYPTO_CFLAGS) $(CXXFLAGS) tests/unit/adapters_test.cpp $(ADAPTER_SOURCES) $(LDFLAGS) $(LIBCRYPTO_LIBS) -o $@

$(TEST_BINARY): tests/unit/parsers_test.cpp src/base64url.cpp src/base64url.hpp src/crypto.cpp src/crypto.hpp src/direct_verifier.cpp src/direct_verifier.hpp src/issuer_verifier.cpp src/issuer_verifier.hpp src/jwks.cpp src/jwks.hpp src/jws.cpp src/jws.hpp src/openssh_certificate.cpp src/openssh_certificate.hpp src/strict_json.cpp src/strict_json.hpp src/parse_error.hpp $(THIRD_PARTY_HEADERS) Makefile
	@mkdir -p $(@D)
	$(CXX) -Isrc -Ithird_party $(LIBCRYPTO_CFLAGS) $(CXXFLAGS) tests/unit/parsers_test.cpp src/base64url.cpp src/crypto.cpp src/direct_verifier.cpp src/issuer_verifier.cpp src/jwks.cpp src/jws.cpp src/openssh_certificate.cpp src/strict_json.cpp $(LDFLAGS) $(LIBCRYPTO_LIBS) -o $@

test-cli:
	@$(MAKE) --no-print-directory test-cli-adapters

test-cli-adapters: build
	$(PYTHON) tests/cli/adapters_test.py "$(BINARY)" "$(CURDIR)/tests/fixtures/issuer-jwks.json"

test-integration-adapters: test-cli-adapters test-syslog-adapters
	$(PYTHON) tests/integration/live_harness_config_test.py \
		"$(BINARY)" "$(CURDIR)/tests/fixtures/issuer-jwks.json"
	@echo "specified offline config/check/render/verify integration passed"

test-integration: test-integration-adapters

test-syslog-adapters: fixtures $(ADAPTER_TEST_BINARY)
	$(ADAPTER_TEST_BINARY) "$(CURDIR)/tests/fixtures/issuer-jwks.json" \
		"$(CURDIR)/.cache/conformance/v1.0.0-rc.2/corpus/credbind-ssh-v1-conformance-v1.0.0-rc.2/vectors/ssh-carrier-p256.json" \
		"$(CURDIR)/.cache/conformance/v1.0.0-rc.2/corpus/credbind-ssh-v1-conformance-v1.0.0-rc.2/keys/issuer-jwks.json"

test-syslog: test-syslog-adapters

test-deadline: fixtures $(ADAPTER_TEST_BINARY)
	$(ADAPTER_TEST_BINARY) "$(CURDIR)/tests/fixtures/issuer-jwks.json" \
		"$(CURDIR)/.cache/conformance/v1.0.0-rc.2/corpus/credbind-ssh-v1-conformance-v1.0.0-rc.2/vectors/ssh-carrier-p256.json" \
		"$(CURDIR)/.cache/conformance/v1.0.0-rc.2/corpus/credbind-ssh-v1-conformance-v1.0.0-rc.2/keys/issuer-jwks.json"

$(SANITIZE_TEST_BINARY): tests/unit/parsers_test.cpp src/base64url.cpp src/base64url.hpp src/crypto.cpp src/crypto.hpp src/direct_verifier.cpp src/direct_verifier.hpp src/issuer_verifier.cpp src/issuer_verifier.hpp src/jwks.cpp src/jwks.hpp src/jws.cpp src/jws.hpp src/openssh_certificate.cpp src/openssh_certificate.hpp src/strict_json.cpp src/strict_json.hpp src/parse_error.hpp $(THIRD_PARTY_HEADERS) Makefile
	@mkdir -p $(@D)
	$(CXX) -Isrc -Ithird_party $(LIBCRYPTO_CFLAGS) -std=c++17 -O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined -fPIE -fvisibility=hidden -fvisibility-inlines-hidden -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Wshadow -Wformat=2 -Werror tests/unit/parsers_test.cpp src/base64url.cpp src/crypto.cpp src/direct_verifier.cpp src/issuer_verifier.cpp src/jwks.cpp src/jws.cpp src/openssh_certificate.cpp src/strict_json.cpp $(LDFLAGS) -fsanitize=address,undefined $(LIBCRYPTO_LIBS) -o $@

$(SANITIZE_ADAPTER_TEST_BINARY): tests/unit/adapters_test.cpp src/command.hpp src/config.hpp src/syslog_logger.hpp $(ADAPTER_SOURCES) $(THIRD_PARTY_HEADERS) Makefile
	@mkdir -p $(@D)
	$(CXX) -Isrc -Ithird_party $(LIBCRYPTO_CFLAGS) -std=c++17 -O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined -fPIE -fvisibility=hidden -fvisibility-inlines-hidden -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Wshadow -Wformat=2 -Werror tests/unit/adapters_test.cpp $(ADAPTER_SOURCES) $(LDFLAGS) -fsanitize=address,undefined $(LIBCRYPTO_LIBS) -o $@

test-sanitize: dependencies-check crypto-check fixtures $(SANITIZE_TEST_BINARY) $(SANITIZE_ADAPTER_TEST_BINARY)
	$(SANITIZER_ENV) $(SANITIZE_TEST_BINARY)
	$(SANITIZER_ENV) $(SANITIZE_ADAPTER_TEST_BINARY) "$(CURDIR)/tests/fixtures/issuer-jwks.json" \
		"$(CURDIR)/.cache/conformance/v1.0.0-rc.2/corpus/credbind-ssh-v1-conformance-v1.0.0-rc.2/vectors/ssh-carrier-p256.json" \
		"$(CURDIR)/.cache/conformance/v1.0.0-rc.2/corpus/credbind-ssh-v1-conformance-v1.0.0-rc.2/keys/issuer-jwks.json"
	$(SANITIZER_ENV) $(PYTHON) tests/fixtures/parser_vectors_test.py "$(SANITIZE_TEST_BINARY)"
	$(SANITIZER_ENV) $(PYTHON) tests/conformance/shared_cases_test.py \
		"$(SANITIZE_TEST_BINARY)" "$(SANITIZE_ADAPTER_TEST_BINARY)"

$(FUZZ_DIR)/json: fuzz/json_fuzz.cpp src/strict_json.cpp src/strict_json.hpp src/parse_error.hpp $(THIRD_PARTY_HEADERS) Makefile
	@mkdir -p $(@D)
	$(FUZZ_CXX) -Isrc -Ithird_party -std=c++17 -O1 -g -fno-omit-frame-pointer -fsanitize=fuzzer,address,undefined -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Wshadow -Wformat=2 -Werror fuzz/json_fuzz.cpp src/strict_json.cpp -fsanitize=fuzzer,address,undefined -o $@

$(FUZZ_DIR)/certificate: fuzz/certificate_fuzz.cpp src/openssh_certificate.cpp src/openssh_certificate.hpp src/parse_error.hpp $(THIRD_PARTY_HEADERS) Makefile
	@mkdir -p $(@D)
	$(FUZZ_CXX) -Isrc -Ithird_party -std=c++17 -O1 -g -fno-omit-frame-pointer -fsanitize=fuzzer,address,undefined -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Wshadow -Wformat=2 -Werror fuzz/certificate_fuzz.cpp src/openssh_certificate.cpp -fsanitize=fuzzer,address,undefined -o $@

$(FUZZ_DIR)/token: fuzz/token_fuzz.cpp src/base64url.cpp src/base64url.hpp src/jws.cpp src/jws.hpp src/strict_json.cpp src/strict_json.hpp src/parse_error.hpp $(THIRD_PARTY_HEADERS) Makefile
	@mkdir -p $(@D)
	$(FUZZ_CXX) -Isrc -Ithird_party -std=c++17 -O1 -g -fno-omit-frame-pointer -fsanitize=fuzzer,address,undefined -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Wshadow -Wformat=2 -Werror fuzz/token_fuzz.cpp src/base64url.cpp src/jws.cpp src/strict_json.cpp -fsanitize=fuzzer,address,undefined -o $@

fuzz-check:
	@test -n "$(FUZZ_CXX)" && test -x "$(FUZZ_CXX)" || { \
		echo "Clang with libFuzzer is required" >&2; exit 1; }
	@runtime="$$($(FUZZ_CXX) -print-runtime-dir 2>/dev/null)"; \
		test -n "$$runtime" && test -n "$$(find "$$runtime" -maxdepth 1 -name 'libclang_rt.fuzzer*' -print -quit 2>/dev/null)" || { \
		echo "$(FUZZ_CXX) has no libFuzzer runtime; select a compatible Clang with FUZZ_CXX" >&2; exit 1; }

test-fuzz-smoke: fuzz-check
	@$(MAKE) --no-print-directory _fuzz-smoke TARGET_NAME=json
	@$(MAKE) --no-print-directory _fuzz-smoke TARGET_NAME=certificate
	@$(MAKE) --no-print-directory _fuzz-smoke TARGET_NAME=token

_fuzz-smoke: $(FUZZ_DIR)/$(TARGET_NAME)
	@work="$(FUZZ_DIR)/smoke-corpus/$(TARGET_NAME)"; artifacts="$(FUZZ_DIR)/artifacts/$(TARGET_NAME)"; \
		rm -rf "$$work" "$$artifacts"; mkdir -p "$$work" "$$artifacts"; \
		cp -R "fuzz/corpus/$(TARGET_NAME)/." "$$work/"; \
		$(FUZZ_ENV) $(FUZZ_DIR)/$(TARGET_NAME) -runs=256 -artifact_prefix="$$artifacts/" "$$work"

fuzz: fuzz-check
	@case "$(TARGET)" in json|certificate|token) ;; *) \
		echo "TARGET must be one of json, certificate or token" >&2; exit 1;; esac
	@case "$(DURATION)" in ''|*[!0-9]*|0) \
		echo "DURATION must be a positive integer number of seconds" >&2; exit 1;; esac
	@$(MAKE) --no-print-directory "$(FUZZ_DIR)/$(TARGET)"
	@work="$(FUZZ_DIR)/development-corpus/$(TARGET)"; artifacts="$(FUZZ_DIR)/artifacts/$(TARGET)"; \
		mkdir -p "$$work" "$$artifacts"; cp -R "fuzz/corpus/$(TARGET)/." "$$work/"; \
		$(FUZZ_ENV) $(FUZZ_DIR)/$(TARGET) -max_total_time=$(DURATION) -artifact_prefix="$$artifacts/" "$$work"

test-readme:
	$(PYTHON) scripts/readme_commands_test.py README.md

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

test-openssh: build
	$(PYTHON) tests/integration/openssh_authorized_keys_test.py \
		"$(OPENSSH_TEST_BINARY)" "$(CREDBIND_GO_ROOT)"

test-live: build
	@test -n "$(CREDBIND_LIVE_REQUEST)" || { echo "CREDBIND_LIVE_REQUEST is required" >&2; exit 1; }
	@test -n "$(CREDBIND_LIVE_CELL)" || { echo "CREDBIND_LIVE_CELL is required" >&2; exit 1; }
	@test -n "$(CREDBIND_LIVE_EVIDENCE_OUTPUT)" || { echo "CREDBIND_LIVE_EVIDENCE_OUTPUT is required" >&2; exit 1; }
	CREDBIND_LIVE_REQUEST="$(CREDBIND_LIVE_REQUEST)" \
	CREDBIND_LIVE_CELL="$(CREDBIND_LIVE_CELL)" \
	CREDBIND_LIVE_ACTION_SOURCE="$(CREDBIND_LIVE_ACTION_SOURCE)" \
	CREDBIND_LIVE_EVIDENCE_OUTPUT="$(CREDBIND_LIVE_EVIDENCE_OUTPUT)" \
	$(PYTHON) tests/integration/openssh_authorized_keys_test.py \
		"$(OPENSSH_TEST_BINARY)" "$(CREDBIND_GO_ROOT)"

_not-implemented:
	@echo "$(TARGET_NAME) is not implemented in the build baseline and cannot report success" >&2
	@exit 1

FORCE:

clean:
	rm -rf dist .cache
