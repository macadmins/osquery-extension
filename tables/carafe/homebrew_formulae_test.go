package carafe

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/osquery/osquery-go/plugin/table"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testHomebrewFormulaeInventory = `{
  "schema_version": "1",
  "generated_at": "2026-06-01T12:30:00Z",
  "brew_path": "/opt/homebrew/bin/brew",
  "arch": "arm64",
  "formulae": [
    {
      "name": "git",
      "full_name": "git",
      "tap": "homebrew/core",
      "installed_version": "2.50.0",
      "installed_on_request": true,
      "source_url": "https://www.kernel.org/pub/software/scm/git/git-2.50.1.tar.xz",
      "homepage": "https://git-scm.com",
      "license": "GPL-2.0-only",
      "checksum": "abc123",
      "outdated": true
    }
  ]
}`

func TestHomebrewFormulaeGenerate(t *testing.T) {
	homebrewFormulaePath = filepath.Join(t.TempDir(), "homebrew_formulae.json")
	require.NoError(t, os.WriteFile(homebrewFormulaePath, []byte(testHomebrewFormulaeInventory), 0600))

	rows, err := HomebrewFormulaeGenerate(context.Background(), table.QueryContext{})

	require.NoError(t, err)
	expectedRows := []map[string]string{
		{
			"name":                 "git",
			"full_name":            "git",
			"tap":                  "homebrew/core",
			"installed_version":    "2.50.0",
			"installed_on_request": "true",
			"source_url":           "https://www.kernel.org/pub/software/scm/git/git-2.50.1.tar.xz",
			"homepage":             "https://git-scm.com",
			"license":              "GPL-2.0-only",
			"checksum":             "abc123",
			"outdated":             "true",
			"generated_at":         "2026-06-01T12:30:00Z",
			"brew_path":            "/opt/homebrew/bin/brew",
			"arch":                 "arm64",
			"schema_version":       "1",
		},
	}
	assert.Equal(t, expectedRows, rows)
}

func TestHomebrewFormulaeGenerateMissingFile(t *testing.T) {
	homebrewFormulaePath = filepath.Join(t.TempDir(), "missing.json")

	rows, err := HomebrewFormulaeGenerate(context.Background(), table.QueryContext{})

	require.NoError(t, err)
	assert.Nil(t, rows)
}

func TestHomebrewFormulaeGenerateInvalidJSON(t *testing.T) {
	homebrewFormulaePath = filepath.Join(t.TempDir(), "homebrew_formulae.json")
	require.NoError(t, os.WriteFile(homebrewFormulaePath, []byte("{"), 0600))

	rows, err := HomebrewFormulaeGenerate(context.Background(), table.QueryContext{})

	assert.Nil(t, rows)
	assert.Error(t, err)
}

func TestHomebrewFormulaeColumns(t *testing.T) {
	columns := HomebrewFormulaeColumns()

	names := make([]string, 0, len(columns))
	for _, column := range columns {
		names = append(names, column.Name)
	}
	assert.Contains(t, names, "name")
	assert.Contains(t, names, "installed_version")
	assert.Contains(t, names, "generated_at")
}
