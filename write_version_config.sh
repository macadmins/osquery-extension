#!/bin/sh

# read the contents of the VERSION file and store in a variable
VERSION=$(cat VERSION)

cat > $1 <<EOF
package main

func init() {
  Version = "${VERSION:-}"
}
EOF