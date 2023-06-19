load("@io_bazel_rules_go//go:def.bzl", "go_binary", "go_library")
load("@bazel_gazelle//:def.bzl", "gazelle")
# load(":rules.bzl", "foo_binary")

# gazelle:prefix github.com/macadmins/osquery-extension
gazelle(name = "gazelle")

gazelle(
    name = "gazelle-update-repos",
    args = [
        "-from_file=go.mod",
        "-to_macro=deps.bzl%go_dependencies",
        "-prune",
    ],
    command = "update-repos",
)

go_library(
    name = "osquery-extension_lib",
    srcs = ["main.go"],
    importpath = "github.com/macadmins/osquery-extension",
    visibility = ["//visibility:private"],
    deps = [
        "//tables/chromeuserprofiles",
        "//tables/fileline",
        "//tables/filevaultusers",
        "//tables/macos_profiles",
        "//tables/macosrsr",
        "//tables/mdm",
        "//tables/munki",
        "//tables/networkquality",
        "//tables/pendingappleupdates",
        "//tables/puppet",
        "//tables/unifiedlog",
        "@com_github_osquery_osquery_go//:osquery-go",
        "@com_github_osquery_osquery_go//plugin/table",
    ],
)

go_binary(
    name = "osquery-extension-arm",
    embed = [":osquery-extension_lib"],
    visibility = ["//visibility:public"],
    goarch = "arm64",
    goos = "darwin",
)

go_binary(
    name = "osquery-extension-win",
    embed = [":osquery-extension_lib"],
    visibility = ["//visibility:public"],
    goarch = "amd64",
    goos = "windows",
)

go_binary(
    name = "osquery-extension-amd",
    embed = [":osquery-extension_lib"],
    visibility = ["//visibility:public"],
    goarch = "amd64",
    goos = "darwin",
)

# pkg_zip(
#     name = "foo_zip",
#     srcs = [
#         "README.txt",
#         ":manpages",
#         ":share_doc",
#         "//resources/l10n:all",
#         "//src/client:arch",
#         "//src/server:arch",
#     ],
# )