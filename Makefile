export GO111MODULE=auto
include config.mk
current_dir = $(shell pwd)

SHELL = /bin/sh

APP_NAME = macadmins_extension
PKGDIR_TMP = ${TMPDIR}golang
OSQUERYI = sudo osqueryi --extension=build/Darwin/macadmins_extension.ext --allow_unsafe --extensions_autoload=/ --config-path=/ --extensions_timeout=60

all: build

.pre-build: clean
	mkdir -p build/Darwin
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
	/bin/rm -rf build/
	/bin/rm -rf macadmins_extension
	/bin/rm -rf ${PKGDIR_TMP}*
	/bin/rm -f macadmins_extension.zip

build: .pre-build
	GOOS=darwin GOARCH=amd64 go build -o build/darwin/${APP_NAME}.amd64.ext
	GOOS=darwin GOARCH=arm64 go build -o build/darwin/${APP_NAME}.arm64.ext
	/usr/bin/lipo -create -output build/darwin/${APP_NAME}.ext build/darwin/${APP_NAME}.amd64.ext build/darwin/${APP_NAME}.arm64.ext
	@sudo codesign --timestamp --force --deep -s "${DEV_APP_CERT}" build/darwin/${APP_NAME}.ext
	GOOS=linux GOARCH=amd64  go build -o build/linux/${APP_NAME}.amd64.ext
	GOOS=linux GOARCH=arm64  go build -o build/linux/${APP_NAME}.arm64.ext
	GOOS=windows GOARCH=amd64  go build -o build/windows/${APP_NAME}.amd64.ext.exe
	GOOS=windows GOARCH=arm64  go build -o build/windows/${APP_NAME}.arm64.ext
	/bin/rm build/darwin/${APP_NAME}.amd64.ext
	/bin/rm build/darwin/${APP_NAME}.arm64.ext

osqueryi: build
	sleep 2
	OSQUERYI

zip: build
	mv build macadmins_extension
	zip -r macadmins_extension.zip macadmins_extension
