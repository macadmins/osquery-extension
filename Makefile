export GO111MODULE=auto
include macadmins.mk
current_dir = $(shell pwd)

SHELL = /bin/sh

BAZEL_OUTPUT_PATH := $(shell bazel info output_path)

APP_NAME = macadmins_extension
PKGDIR_TMP = ${TMPDIR}golang

all: build

.PHONY: clean .pre-build deps init gazelle update-repos test coverage build osqueryi zip

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
	bazel test --test_output=errors //...

coverage:
	rm -rf coverage
	mkdir -p coverage
	bazel coverage --combined_report=lcov //...
	mv $(BAZEL_OUTPUT_PATH)/_coverage/_coverage_report.dat coverage/lcov.info

build: .pre-build
	bazel build --verbose_failures //:osquery-extension-mac-amd
	bazel build --verbose_failures //:osquery-extension-mac-arm
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
