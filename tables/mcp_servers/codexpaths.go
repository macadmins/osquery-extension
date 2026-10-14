package mcp_servers

import (
	"path/filepath"
	"strings"
)

// isCodexTOMLPath narrows a directory listing to Codex's own TOML configs.
//
// Needed because ~/.codex/<profile>.config.toml is reached by listing ~/.codex, so the names
// come from the filesystem rather than from a fixed path and have to be filtered. Every other
// source this table reads is named exactly, which is why this is the only path predicate left.

// isCodexTOMLPath reports whether a path is a Codex TOML config: config.toml or a
// <profile>.config.toml, in either case directly inside a .codex directory.
//
// The .codex parent is required rather than matching config.toml anywhere, because that
// basename is one of the most common on a developer machine -- Rust, Hugo and many others
// use it -- so matching it on basename alone inside a listing would be meaningless.
func isCodexTOMLPath(absPath string) bool {
	if filepath.Base(filepath.Dir(absPath)) != ".codex" {
		return false
	}
	base := filepath.Base(absPath)
	return base == "config.toml" || strings.HasSuffix(base, ".config.toml")
}
