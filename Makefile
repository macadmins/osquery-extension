export GO111MODULE=auto
include macadmins.mk
current_dir = $(shell pwd)

SHELL = /bin/sh

BAZEL_OUTPUT_PATH := $(shell bazel info output_path)

APP_NAME = macadmins_extension

# PKGDIR_TMP is the directory `clean` removes with a privileged glob, so its two failure
# modes are both worth closing explicitly.
#
# TMPDIR is set by the shell on macOS but is not guaranteed: a cron job, a CI runner, or a
# `sudo` invocation that resets the environment can leave it empty. `${TMPDIR}golang` then
# expands to the bare string `golang`, and `sudo /bin/rm -rf golang*` runs relative to the
# working directory -- which is the repository root.
#
# And TMPDIR may or may not carry a trailing slash. macOS sets one; `/tmp` without it is the
# ordinary form on Linux and in CI, and simple concatenation then produces `/tmpgolang` --
# absolute, so an absolute-path check passes it, but a sibling of /tmp rather than a child,
# so the glob is `sudo /bin/rm -rf /tmpgolang*` at the filesystem root. Normalising the
# separator is what makes the path the intended one rather than merely an absolute one.
#
# $(if $(strip ...)) rather than `?=` because make treats a variable exported as empty as
# defined, so `?=` would not substitute in the case that matters.
PKGDIR_BASE = $(patsubst %/,%,$(if $(strip ${TMPDIR}),${TMPDIR},/tmp))
PKGDIR_TMP = ${PKGDIR_BASE}/golang

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

# The glob is guarded rather than interpolated straight into the command, and the guard
# checks the shape of the path rather than only that it is absolute.
#
# An absolute-path test alone is not enough: `/tmpgolang` is absolute and is not the intended
# directory. So the parent must be an existing directory and the basename must be exactly
# `golang`, which is the whole of what this target is entitled to remove. Refuses loudly
# instead of deleting, so an unusual environment is reported rather than acted on.
clean:
	@sudo /bin/rm -rf build/
	@sudo /bin/rm -rf macadmins_extension
	@case "${PKGDIR_TMP}" in \
		/*/golang) \
			if [ -d "${PKGDIR_BASE}" ]; then \
				sudo /bin/rm -rf "${PKGDIR_TMP}"*; \
			else \
				echo "clean: refusing, ${PKGDIR_BASE} is not a directory" >&2; exit 1; \
			fi ;; \
		*) echo "clean: refusing to remove unexpected PKGDIR_TMP=\"${PKGDIR_TMP}\"" >&2; exit 1 ;; \
	esac
	@sudo /bin/rm -f macadmins_extension.zip

gazelle:
	bazel run //:gazelle

update-repos:
	bazel run //:gazelle-update-repos -- -from_file=go.mod

test:
	bazel test --test_output=errors //...

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
