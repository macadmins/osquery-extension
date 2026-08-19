#!/usr/bin/env bash
set -euo pipefail

mkdir -p build/darwin
mkdir -p build/linux
mkdir -p build/windows

APP_NAME="macadmins_extension"

# Captured once with stderr suppressed and failure tolerated (some Windows
# shells / CI images lack uname), so `set -e` can't abort the Linux/Windows
# copies below when uname is unavailable. Empty value => not Darwin.
host_os="$(uname -s 2>/dev/null || true)"

# copy_bazel_output TARGET DEST copies the single output file of a bazel
# target to DEST. It captures the cquery result, validates that exactly one
# non-empty path was returned, and quotes the path so files with whitespace
# (or an unexpected multi-file output) are handled safely rather than being
# silently word-split.
copy_bazel_output() {
	if [ "$#" -ne 2 ]; then
		echo "usage: copy_bazel_output TARGET DEST" >&2
		return 2
	fi
	# Run the body in a subshell with an EXIT trap, so the temp file is removed
	# on every exit path (normal, error under set -e, or signal) and the trap
	# is scoped to this invocation — it never alters the parent shell's global
	# traps (unlike a RETURN trap, which would persist after the function).
	(
		set -euo pipefail
		# Template form works on both GNU and BSD/macOS mktemp (a bare `mktemp`
		# with no template is not portable to BSD).
		err="$(mktemp "${TMPDIR:-/tmp}/bazel_to_builddir.XXXXXX")"
		trap 'rm -f "$err"' EXIT

		# Capture stderr and the exit code so an actual bazel/cquery failure
		# (missing bazel, bad workspace, query error) is reported distinctly
		# from a successful-but-empty result. The `&& rc=0 || rc=$?` idiom
		# records the exit code without tripping `set -e`.
		file="$(bazel cquery --output=files "$1" 2>"$err")" && rc=0 || rc=$?
		if [ "$rc" -ne 0 ]; then
			echo "error: 'bazel cquery' failed for $1 (exit ${rc}):" >&2
			cat "$err" >&2
			exit 1
		fi
		if [ -z "$file" ]; then
			echo "error: no output file for $1 (target produced no outputs)" >&2
			exit 1
		fi
		# Reject multi-path output (one path per line). wc -l is used instead
		# of `grep -c`, which exits non-zero on zero matches and trips set -e.
		lines="$(printf '%s\n' "$file" | wc -l | tr -d '[:space:]')"
		if [ "$lines" -ne 1 ]; then
			echo "error: expected exactly one output file for $1, got ${lines}:" >&2
			printf '%s\n' "$file" >&2
			exit 1
		fi
		# Guard against an output path that begins with `-` being parsed as a
		# cp option by prefixing `./`. Portable across GNU and BSD/macOS cp,
		# whereas `--` end-of-options is not universally honored on BSD. dest
		# is always a build/ path, so only the source needs guarding.
		case "$file" in
		-*) file="./$file" ;;
		esac
		cp "$file" "$2"
	)
}

# Mac binaries only build on macOS hosts (require Apple C++ toolchain + cgo).
if [ "$host_os" = "Darwin" ]; then
	copy_bazel_output //:osquery-extension-mac-amd "build/darwin/${APP_NAME}.amd64.ext"
	copy_bazel_output //:osquery-extension-mac-arm "build/darwin/${APP_NAME}.arm64.ext"
fi

copy_bazel_output //:osquery-extension-linux-amd "build/linux/${APP_NAME}.amd64.ext"
copy_bazel_output //:osquery-extension-linux-arm "build/linux/${APP_NAME}.arm64.ext"
copy_bazel_output //:osquery-extension-win-amd "build/windows/${APP_NAME}.amd64.ext.exe"

# copy_bazel_output //:osquery-extension-win-arm "build/windows/${APP_NAME}.arm64.ext.exe"
