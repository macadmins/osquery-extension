package localnetworkpermissions

import (
	"context"
	_ "embed"
	"os"
	"path/filepath"
	"testing"

	"github.com/micromdm/plist"
	"github.com/osquery/osquery-go/plugin/table"
	"github.com/stretchr/testify/assert"
)

//go:embed test_networkextension.plist
var testPlistData []byte

func withNetworkExtensionPlistPath(t *testing.T, path string) {
	t.Helper()
	original := networkExtensionPlistPath
	networkExtensionPlistPath = path
	t.Cleanup(func() {
		networkExtensionPlistPath = original
	})
}

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
	// Test readLocalNetworkPermissions with a non-existent file path
	permissions, err := readLocalNetworkPermissions("/nonexistent/path/to/plist")
	assert.Error(t, err) // Should return an error for file not found
	assert.True(t, os.IsNotExist(err))
	assert.Nil(t, permissions)
}

func TestLocalNetworkPermissionsGenerateRows(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "networkextension.plist")
	err := os.WriteFile(tmpFile, testPlistData, 0600)
	assert.NoError(t, err)
	withNetworkExtensionPlistPath(t, tmpFile)

	results, err := LocalNetworkPermissionsGenerate(context.Background(), table.QueryContext{})
	assert.NoError(t, err)
	assert.Equal(t, []map[string]string{
		{
			"bundle_id":       "com.example.testapp",
			"executable_path": "/Applications/TestApp.app/Contents/MacOS/TestApp",
			"display_name":    "Test App",
			"type":            "applications",
			"state":           "1",
			"provider_added":  "true",
		},
		{
			"bundle_id":       "com.example.anotherapp",
			"executable_path": "/Applications/AnotherApp.app/Contents/MacOS/AnotherApp",
			"display_name":    "Another App",
			"type":            "applications",
			"state":           "0",
			"provider_added":  "false",
		},
	}, results)
}

func TestLocalNetworkPermissionsGenerateMissingFile(t *testing.T) {
	withNetworkExtensionPlistPath(t, filepath.Join(t.TempDir(), "missing.plist"))

	results, err := LocalNetworkPermissionsGenerate(context.Background(), table.QueryContext{})
	assert.NoError(t, err)
	assert.Empty(t, results)
}

func TestLocalNetworkPermissionsGenerateInvalidPlist(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "networkextension.plist")
	err := os.WriteFile(tmpFile, []byte("not plist"), 0600)
	assert.NoError(t, err)
	withNetworkExtensionPlistPath(t, tmpFile)

	results, err := LocalNetworkPermissionsGenerate(context.Background(), table.QueryContext{})
	assert.Error(t, err)
	assert.Nil(t, results)
	assert.ErrorContains(t, err, "read local network permissions")
}

func TestReadLocalNetworkPermissionsWithoutObjects(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "networkextension.plist")
	err := os.WriteFile(tmpFile, []byte(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>not_objects</key><array/></dict></plist>`), 0600)
	assert.NoError(t, err)

	permissions, err := readLocalNetworkPermissions(tmpFile)
	assert.NoError(t, err)
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

func TestExtractPermissionFromDictPartialAndMismatchedObjects(t *testing.T) {
	objects := []interface{}{
		"bundleid",
		"path",
		"com.example.testapp",
		map[string]interface{}{
			"NS.keys":    []interface{}{uint64(0), uint64(1), "displayname"},
			"NS.objects": []interface{}{uint64(2), "file:///Applications/Test.app"},
		},
	}

	permissions := extractPermissionsFromObjects(objects)
	assert.Equal(t, []LocalNetworkPermission{
		{
			BundleID:       "com.example.testapp",
			ExecutablePath: "/Applications/Test.app",
		},
	}, permissions)
}

func TestIsAppPermissionDictRejectsNonPermissionDictionaries(t *testing.T) {
	assert.False(t, isAppPermissionDict(map[string]interface{}{}, nil))
	assert.False(t, isAppPermissionDict(map[string]interface{}{
		"NS.keys":    []interface{}{"unrelated"},
		"NS.objects": []interface{}{"value"},
	}, nil))
}

func TestResolveUID(t *testing.T) {
	objects := []interface{}{"zero", "one"}
	assert.Equal(t, "one", resolveUID(uint64(1), objects))
	assert.Equal(t, "one", resolveUID(plist.UID(1), objects))
	assert.Equal(t, uint64(3), resolveUID(uint64(3), objects))
	assert.Equal(t, "literal", resolveUID("literal", objects))
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
