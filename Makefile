export GO111MODULE=auto
include macadmins.mk
current_dir = $(shell pwd)

SHELL = /bin/sh

# Computed once, with a safe empty default if `uname` is unavailable (some
# Windows shells / CI images). Used to gate the darwin-only binary builds.
UNAME_S := $(shell uname -s 2>/dev/null)

BAZEL_OUTPUT_PATH := $(shell bazel info output_path)

APP_NAME = macadmins_extension
PKGDIR_TMP = ${TMPDIR}golang

all: build

.PHONY: clean .pre-build deps init gazelle update-repos test coverage build osqueryi zip install-go-test-coverage

GOBIN ?= $$(go env GOPATH)/bin

install-go-test-coverage:
	go install github.com/vladopajic/go-test-coverage/v2@latest

coverage: install-go-test-coverage
	go test ./... -coverprofile=./cover.out -covermode=atomic -coverpkg=./...
	${GOBIN}/go-test-coverage --config=./.testcoverage.yml

.pre-build: clean
	mkdir -p build/darwin
	mkdir -p build/windows
	mkdir -p build/linux

deps:
	go get -u golang.org/x/lint/golint
	go mod download
	go mod verify
	go mod vendor


init:
	go mod init github.com/macadmins/osquery-extension

clean:
	@sudo /bin/rm -rf build/
	@sudo /bin/rm -rf macadmins_extension
	@sudo /bin/rm -rf ${PKGDIR_TMP}*
	@sudo /bin/rm -f macadmins_extension.zip

gazelle:
	bazel run //:gazelle

update-repos:
	bazel run //:gazelle-update-repos -- -from_file=go.mod

test:
	# Query only test targets (any *_test kind) rather than `bazel test //...`,
	# which would also analyze the darwin go_binary targets (pure="off",
	# cgo=True in root BUILD.bazel) and fail on Linux CI where no darwin
	# C++ toolchain exists.
	# Matching all *_test kinds (not just go_test) keeps non-Go tests
	# (sh_test, py_test, etc.) in scope if any are added later. The target
	# list is passed via --target_pattern_file rather than expanded onto the
	# command line, so a growing test set can't hit argv length limits.
	@set -e; \
	targets="$$(mktemp "$${TMPDIR:-/tmp}/dot1x-test-targets.XXXXXX")"; \
	trap 'rm -f "$$targets"' EXIT; \
	bazel query 'kind(".*_test", //...)' > "$$targets"; \
	bazel test --test_output=errors --target_pattern_file="$$targets"

build: .pre-build
ifeq ($(UNAME_S),Darwin)
	bazel build --verbose_failures //:osquery-extension-mac-amd
	bazel build --verbose_failures //:osquery-extension-mac-arm
endif
	bazel build --verbose_failures //:osquery-extension-linux-amd
	bazel build --verbose_failures //:osquery-extension-linux-arm
	bazel build --verbose_failures //:osquery-extension-win-amd
	bazel build --verbose_failures //:osquery-extension-win-arm
	tools/bazel_to_builddir.sh

osqueryi: build
	sleep 2
	sudo osqueryi --extension=build/darwin/macadmins_extension.arm64.ext --allow_unsafe

zip: build
	/usr/bin/lipo -create -output build/darwin/${APP_NAME}.ext build/darwin/${APP_NAME}.amd64.ext build/darwin/${APP_NAME}.arm64.ext
	/bin/rm build/darwin/${APP_NAME}.amd64.ext
	/bin/rm build/darwin/${APP_NAME}.arm64.ext
	@sudo codesign --timestamp --force --deep -s "${DEV_APP_CERT}" build/darwin/${APP_NAME}.ext
	@sudo chown root:wheel build/darwin/${APP_NAME}.ext
	@sudo chmod 755 build/darwin/${APP_NAME}.ext
	mv build macadmins_extension
	zip -r macadmins_extension.zip macadmins_extension
