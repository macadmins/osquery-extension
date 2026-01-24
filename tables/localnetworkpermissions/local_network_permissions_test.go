package localnetworkpermissions

import (
	"context"
	_ "embed"
	"os"
	"testing"

	"github.com/osquery/osquery-go/plugin/table"
	"github.com/stretchr/testify/assert"
)

//go:embed test_networkextension.plist
var testPlistData []byte

func TestLocalNetworkPermissionsColumns(t *testing.T) {
	t.Parallel()
	columns := LocalNetworkPermissionsColumns()
	expectedColumns := []table.ColumnDefinition{
		table.TextColumn("bundle_id"),
		table.TextColumn("executable_path"),
		table.TextColumn("display_name"),
		table.TextColumn("type"),
		table.IntegerColumn("state"),
		table.TextColumn("provider_added"),
	}

	assert.Equal(t, expectedColumns, columns)
}

func TestLocalNetworkPermissionsGenerate(t *testing.T) {
	t.Parallel()

	// Create a temp file with test plist data
	tmpFile, err := os.CreateTemp(t.TempDir(), "networkextension-*.plist")
	assert.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.Write(testPlistData)
	assert.NoError(t, err)
	tmpFile.Close()

	// Override the plist path for this test
	originalPath := networkExtensionPlistPath
	networkExtensionPlistPath = tmpFile.Name()
	defer func() { networkExtensionPlistPath = originalPath }()

	ctx := context.Background()
	queryContext := table.QueryContext{}

	results, err := LocalNetworkPermissionsGenerate(ctx, queryContext)
	assert.NoError(t, err)
	assert.NotNil(t, results)

	// Verify we got the expected results from our test plist
	assert.Len(t, results, 2)

	// Check first result
	assert.Equal(t, "com.example.testapp", results[0]["bundle_id"])
	assert.Equal(t, "/Applications/TestApp.app/Contents/MacOS/TestApp", results[0]["executable_path"])
	assert.Equal(t, "Test App", results[0]["display_name"])
	assert.Equal(t, "applications", results[0]["type"])
	assert.Equal(t, "1", results[0]["state"])

	// Check second result
	assert.Equal(t, "com.example.anotherapp", results[1]["bundle_id"])
	assert.Equal(t, "/Applications/AnotherApp.app/Contents/MacOS/AnotherApp", results[1]["executable_path"])
	assert.Equal(t, "Another App", results[1]["display_name"])
	assert.Equal(t, "applications", results[1]["type"])
	assert.Equal(t, "0", results[1]["state"])
}

func TestLocalNetworkPermissionsGenerateFileNotFound(t *testing.T) {
	t.Parallel()

	// Override the plist path to a non-existent file
	originalPath := networkExtensionPlistPath
	networkExtensionPlistPath = "/nonexistent/path/to/plist"
	defer func() { networkExtensionPlistPath = originalPath }()

	ctx := context.Background()
	queryContext := table.QueryContext{}

	results, err := LocalNetworkPermissionsGenerate(ctx, queryContext)
	assert.NoError(t, err) // Should not error, just return empty results
	assert.Empty(t, results)
}

func TestExtractPermissionsFromObjects(t *testing.T) {
	t.Parallel()

	// Test with empty objects
	permissions := extractPermissionsFromObjects([]interface{}{})
	assert.Empty(t, permissions)

	// Test with nil
	permissions = extractPermissionsFromObjects(nil)
	assert.Empty(t, permissions)
}

func TestToInt(t *testing.T) {
	t.Parallel()

	assert.Equal(t, 42, toInt(42))
	assert.Equal(t, 42, toInt(int64(42)))
	assert.Equal(t, 42, toInt(uint64(42)))
	assert.Equal(t, 42, toInt(float64(42.0)))
	assert.Equal(t, 0, toInt("not a number"))
	assert.Equal(t, 0, toInt(nil))
}
