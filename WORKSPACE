load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

# --- Apple C/C++ toolchain for cgo on macOS -------------------------------
# The dot1x table calls EAP8021X.framework (CoreFoundation) via cgo,
# so the macOS go_binary targets are built with cgo enabled (see
# root BUILD.bazel go_binary targets: cgo = True, pure = "off"). That requires an Apple CC toolchain,
# which apple_support provides. This block must precede rules_go so its CC
# toolchain is registered for the Apple cc actions cgo uses.
#
# NOTE: In WORKSPACE mode (no bzlmod), these http_archive + load calls are
# unconditional — they are fetched on every platform even though only darwin
# builds consume them. The alternative (platform-gating with a load/condition)
# adds complexity without meaningful savings, since Bazel lazy-fetches archives
# and the WORKSPACE is already ~200 lines of unconditional deps. On bzlmod the
# toolchain is registered via MODULE.bazel, not this file.
#
# Pinned to 1.24.5: the last apple_support release that supports WORKSPACE mode
# (2.0.0 dropped it), and >= 1.19.0 so wrapped_clang is built WITHOUT the
# -Wl,-no_uuid workaround that recent macOS / dyld versions reject with
# "missing LC_UUID load command" (apple_support PR #373; bazelbuild/bazel#27026).
http_archive(
    name = "build_bazel_apple_support",
    sha256 = "1ae6fcf983cff3edab717636f91ad0efff2e5ba75607fdddddfd6ad0dbdfaf10",
    url = "https://github.com/bazelbuild/apple_support/releases/download/1.24.5/apple_support.1.24.5.tar.gz",
)

load(
    "@build_bazel_apple_support//lib:repositories.bzl",
    "apple_support_dependencies",
)

apple_support_dependencies()

# bazel_features (pulled in by apple_support_dependencies) deps.
load("@bazel_features//:deps.bzl", "bazel_features_deps")

bazel_features_deps()

# rules_cc (pulled in by apple_support_dependencies) deps + toolchains, plus the
# WORKSPACE-mode compatibility proxy repo (cc_compatibility_proxy) that the
# rules_cc 0.2.x APIs resolve through. In bzlmod this repo is created by a module
# extension; in WORKSPACE mode it must be created explicitly here.
load("@rules_cc//cc:repositories.bzl", "rules_cc_dependencies", "rules_cc_toolchains")

rules_cc_dependencies()

rules_cc_toolchains()

load("@rules_cc//cc:extensions.bzl", "compatibility_proxy_repo")

compatibility_proxy_repo()

# --------------------------------------------------------------------------

http_archive(
    name = "io_bazel_rules_go",
    sha256 = "68af54cb97fbdee5e5e8fe8d210d15a518f9d62abfd71620c3eaff3b26a5ff86",
    urls = [
        "https://mirror.bazel.build/github.com/bazel-contrib/rules_go/releases/download/v0.59.0/rules_go-v0.59.0.zip",
        "https://github.com/bazel-contrib/rules_go/releases/download/v0.59.0/rules_go-v0.59.0.zip",
    ],
)

http_archive(
    name = "bazel_gazelle",
    integrity = "sha256-MpOL2hbmcABjA1R5Bj2dJMYO2o15/Uc5Vj9Q0zHLMgk=",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/bazel-gazelle/releases/download/v0.35.0/bazel-gazelle-v0.35.0.tar.gz",
        "https://github.com/bazelbuild/bazel-gazelle/releases/download/v0.35.0/bazel-gazelle-v0.35.0.tar.gz",
    ],
)

load(
    "@io_bazel_rules_go//go:deps.bzl",
    "go_register_toolchains",
    "go_rules_dependencies",
)
load("@bazel_gazelle//:deps.bzl", "gazelle_dependencies", "go_repository")

############################################################
# Define your own dependencies here using go_repository.
# Else, dependencies declared by rules_go/gazelle will be used.
# The first declaration of an external repository "wins".
############################################################

load("//:deps.bzl", "go_dependencies")

# gazelle:repository_macro deps.bzl%go_dependencies
go_dependencies()

go_rules_dependencies()

go_register_toolchains(version = "1.25.4")

load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")
load("@platforms//host:extension.bzl", "host_platform_repo")

maybe(
    host_platform_repo,
    name = "host_platform",
)

gazelle_dependencies()
