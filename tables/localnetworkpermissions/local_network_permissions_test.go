package localnetworkpermissions

import (
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

	_, err = tmpFile.Write(testPlistData)
	assert.NoError(t, err)
	assert.NoError(t, tmpFile.Close())

	// Test readLocalNetworkPermissions directly with the path parameter
	permissions, err := readLocalNetworkPermissions(tmpFile.Name())
	assert.NoError(t, err)
	assert.NotNil(t, permissions)

	// Verify we got the expected results from our test plist
	assert.Len(t, permissions, 2)

	// Check first result
	assert.Equal(t, "com.example.testapp", permissions[0].BundleID)
	assert.Equal(t, "/Applications/TestApp.app/Contents/MacOS/TestApp", permissions[0].ExecutablePath)
	assert.Equal(t, "Test App", permissions[0].DisplayName)
	assert.Equal(t, "applications", permissions[0].Type)
	assert.Equal(t, 1, permissions[0].State)

	// Check second result
	assert.Equal(t, "com.example.anotherapp", permissions[1].BundleID)
	assert.Equal(t, "/Applications/AnotherApp.app/Contents/MacOS/AnotherApp", permissions[1].ExecutablePath)
	assert.Equal(t, "Another App", permissions[1].DisplayName)
	assert.Equal(t, "applications", permissions[1].Type)
	assert.Equal(t, 0, permissions[1].State)
}

func TestLocalNetworkPermissionsGenerateFileNotFound(t *testing.T) {
	t.Parallel()

	// Test readLocalNetworkPermissions with a non-existent file path
	permissions, err := readLocalNetworkPermissions("/nonexistent/path/to/plist")
	assert.Error(t, err) // Should return an error for file not found
	assert.True(t, os.IsNotExist(err))
	assert.Nil(t, permissions)
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
