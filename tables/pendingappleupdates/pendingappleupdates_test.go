package pendingappleupdates

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/macadmins/osquery-extension/pkg/utils"
	"github.com/micromdm/plist"
	"github.com/osquery/osquery-go/plugin/table"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func withSoftwareUpdatePlistPath(t *testing.T, path string) {
	t.Helper()
	original := softwareUpdatePlistPath
	softwareUpdatePlistPath = path
	t.Cleanup(func() {
		softwareUpdatePlistPath = original
	})
}

func writeSoftwareUpdatePlist(t *testing.T, path string, updatePlist softwareUpdatePlist) {
	t.Helper()
	data, err := plist.Marshal(updatePlist)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0600))
}

func TestPendingAppleUpdatesColumns(t *testing.T) {
	assert.Equal(t, []table.ColumnDefinition{
		table.TextColumn("display_name"),
		table.TextColumn("display_version"),
		table.TextColumn("identifier"),
		table.TextColumn("product_key"),
	}, PendingAppleUpdatesColumns())
}

func TestPendingAppleUpdatesGenerate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "com.apple.SoftwareUpdate.plist")
	writeSoftwareUpdatePlist(t, path, softwareUpdatePlist{
		RecommendedUpdates: []recommendedUpdate{
			{
				DisplayName:    "macOS Example Update",
				DisplayVersion: "14.1",
				Identifier:     "MSU_UPDATE_1",
				ProductKey:     "012-34567",
			},
		},
	})
	withSoftwareUpdatePlistPath(t, path)

	results, err := PendingAppleUpdatesGenerate(context.Background(), table.QueryContext{})
	require.NoError(t, err)
	assert.Equal(t, []map[string]string{{
		"display_name":    "macOS Example Update",
		"display_version": "14.1",
		"identifier":      "MSU_UPDATE_1",
		"product_key":     "012-34567",
	}}, results)
}

func TestPendingAppleUpdatesGenerateMissingPlist(t *testing.T) {
	withSoftwareUpdatePlistPath(t, filepath.Join(t.TempDir(), "missing.plist"))

	results, err := PendingAppleUpdatesGenerate(context.Background(), table.QueryContext{})
	require.NoError(t, err)
	assert.Nil(t, results)
}

func TestPendingAppleUpdatesGenerateInvalidPlist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "com.apple.SoftwareUpdate.plist")
	require.NoError(t, os.WriteFile(path, []byte("not plist"), 0600))
	withSoftwareUpdatePlistPath(t, path)

	results, err := PendingAppleUpdatesGenerate(context.Background(), table.QueryContext{})
	assert.Error(t, err)
	assert.Nil(t, results)
}

func TestReadSoftwareUpdatePlistStatErrorIsTreatedAsMissing(t *testing.T) {
	withSoftwareUpdatePlistPath(t, filepath.Join(t.TempDir(), "missing.plist"))

	updates, err := readSoftwareUpdatePlist(utils.MockFileSystem{Err: errors.New("stat failed")})
	require.NoError(t, err)
	assert.Nil(t, updates)
}
