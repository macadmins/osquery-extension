#!/usr/bin/env bash

mkdir -p build/darwin
mkdir -p build/linux
mkdir -p build/windows

APP_NAME="macadmins_extension"

cp $(bazel cquery --output=files //:osquery-extension-mac-amd 2>/dev/null) build/darwin/${APP_NAME}.amd64.ext

cp $(bazel cquery --output=files //:osquery-extension-mac-arm 2>/dev/null) build/darwin/${APP_NAME}.arm64.ext

cp $(bazel cquery --output=files //:osquery-extension-linux-amd 2>/dev/null) build/linux/${APP_NAME}.amd64.ext

cp $(bazel cquery --output=files //:osquery-extension-linux-arm 2>/dev/null) build/linux/${APP_NAME}.arm64.ext

cp $(bazel cquery --output=files //:osquery-extension-win-amd 2>/dev/null) build/windows/${APP_NAME}.amd64.ext.exe

# mv $(bazel cquery --output=files //:osquery-extension-win-arm 2>/dev/null) build/windows/${APP_NAME}.arm64.ext.exe
