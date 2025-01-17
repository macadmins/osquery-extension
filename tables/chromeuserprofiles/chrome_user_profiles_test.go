package chromeuserprofiles

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBtoi(t *testing.T) {
	assert.Equal(t, 1, btoi(true))
	assert.Equal(t, 0, btoi(false))
}

func TestGoogleChromeProfilesColumns(t *testing.T) {
	columns := GoogleChromeProfilesColumns()
	assert.Len(t, columns, 5)

	expectedColumnNames := []string{"username", "email", "name", "ephemeral", "path"}
	for i, column := range columns {
		assert.Equal(t, expectedColumnNames[i], column.Name)
	}
}

func TestFindFileInUserDirs(t *testing.T) {
	// Create a temporary directory for testing
	tempDir := t.TempDir()

	// Create a user directory inside the temporary directory
	userDir := filepath.Join(tempDir, "testuser")
	err := os.Mkdir(userDir, os.ModePerm)
	assert.NoError(t, err)

	// Create a test file inside the user directory
	testFile := filepath.Join(userDir, "testfile.txt")
	err = os.WriteFile(testFile, []byte("test data"), os.ModePerm)
	assert.NoError(t, err)

	// Set the home directory location for the current platform
	homeDirLocations[runtime.GOOS] = []string{tempDir}

	// Test with a username
	foundFiles, err := findFileInUserDirs("testfile.txt", WithUsername("testuser"))
	assert.NoError(t, err)
	assert.Len(t, foundFiles, 1)
	assert.Equal(t, "testuser", foundFiles[0].user)
	assert.Equal(t, testFile, foundFiles[0].path)

	// Test without a username
	foundFiles, err = findFileInUserDirs("testfile.txt")
	assert.NoError(t, err)
	assert.Len(t, foundFiles, 1)
	assert.Equal(t, "testuser", foundFiles[0].user)
	assert.Equal(t, testFile, foundFiles[0].path)
}

func TestGenerateForPath(t *testing.T) {
	// Create a temporary directory for testing
	tempDir := t.TempDir()

	// Create a placeholder directory for one of the profiles - the name is the
	// info_cache map key, not the 'name' value
	profile1Path := filepath.Join(tempDir, "profile1")
	err := os.Mkdir(profile1Path, os.ModePerm)
	assert.NoError(t, err)

	// Create a test Chrome local state file
	localStateFile := filepath.Join(tempDir, "Local State")
	localStateData := `{
		"profile": {
			"info_cache": {
				"profile1": {
					"name": "Profile 1",
					"is_ephemeral": false,
					"user_name": "profile1@example.com"
				},
				"profile2": {
					"name": "Profile 2",
					"is_ephemeral": true,
					"user_name": "profile2@example.com"
				}
			}
		}
	}`

	err = os.WriteFile(localStateFile, []byte(localStateData), os.ModePerm)
	assert.NoError(t, err)

	// Test generateForPath
	fileInfo := userFileInfo{
		user: "testuser",
		path: localStateFile,
	}

	results, err := generateForPath(context.Background(), fileInfo)
	assert.NoError(t, err)
	assert.Len(t, results, 2)

	expectedProfiles := []map[string]string{
		{
			"username":  "testuser",
			"email":     "profile1@example.com",
			"name":      "Profile 1",
			"ephemeral": "0",
			"path":      profile1Path,
		},
		{
			"username":  "testuser",
			"email":     "profile2@example.com",
			"name":      "Profile 2",
			"ephemeral": "1",
			// this profile directory doesn't exist, so the path should be blank
			"path": "",
		},
	}

	assert.ElementsMatch(t, expectedProfiles, results)
}

func TestProfilePathStat(t *testing.T) {
	t.Run("profile directory exists", func(t *testing.T) {
		tempDir := t.TempDir()

		localStatePath := filepath.Join(tempDir, "Local State")

		profilePath := filepath.Join(tempDir, "profile1")
		err := os.Mkdir(profilePath, os.ModePerm)
		assert.NoError(t, err)

		actual, err := profilePathStat(localStatePath, "profile1")
		assert.NoError(t, err)
		assert.Equal(t, profilePath, actual)
	})

	t.Run("profile directory does not exist", func(t *testing.T) {
		tempDir := t.TempDir()

		localStatePath := filepath.Join(tempDir, "Local State")

		_, err := profilePathStat(localStatePath, "profile-does-not-exist")
		assert.ErrorIs(t, err, os.ErrNotExist)
	})
}
