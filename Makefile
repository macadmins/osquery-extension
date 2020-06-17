export GO111MODULE=auto
current_dir = $(shell pwd)

SHELL = /bin/sh

APP_NAME = macadmins_extension
PKGDIR_TMP = ${TMPDIR}golang
OSQUERYI = sudo osqueryi --extension build/linux/macadmins_extension.ext --allow_unsafe --extensions_autoload=/ --config-path=/ --extensions_timeout=60

ifneq ($(OS), Windows_NT)
	CURRENT_PLATFORM = linux
	ifeq ($(shell uname), Darwin)
		SHELL := /bin/sh
		CURRENT_PLATFORM = darwin
		OSQUERYI = sudo osqueryi --extension build/darwin/macadmins_extension.ext --allow_unsafe --extensions_autoload=/ --config-path=/ --extensions_timeout=60
	endif
else
	CURRENT_PLATFORM = windows
endif

all: build

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
	/bin/rm -rf build/
	/bin/rm -rf macadmins_extension
	/bin/rm -rf ${PKGDIR_TMP}_darwin
	/bin/rm -f macadmins_extension.zip

build: .pre-build
	GOOS=darwin go build -i -o build/darwin/${APP_NAME}.ext -pkgdir ${PKGDIR_TMP}
	GOOS=linux go build -i -o build/linux/${APP_NAME}.ext -pkgdir ${PKGDIR_TMP}
	GOOS=windows go build -i -o build/windows/${APP_NAME}.ext.exe -pkgdir ${PKGDIR_TMP}


osqueryi: build
	OSQUERYI

zip: build
	mv build macadmins_extension
	zip -r macadmins_extension.zip macadmins_extension