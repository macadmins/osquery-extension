package fileline

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/macadmins/osquery-extension/pkg/utils"
	"github.com/stretchr/testify/assert"
)

func TestProcessFile(t *testing.T) {
	t.Run("processFile with wildcard", func(t *testing.T) {
		// Create temporary files for testing
		tmpFile1, err := os.CreateTemp("", "testfile1-*.txt")
		assert.NoError(t, err)
		defer os.Remove(tmpFile1.Name())

		tmpFile2, err := os.CreateTemp("", "testfile2-*.txt")
		assert.NoError(t, err)
		defer os.Remove(tmpFile2.Name())

		_, err = tmpFile1.WriteString("line1\nline2\n")
		assert.NoError(t, err)
		_, err = tmpFile2.WriteString("line3\nline4\n")
		assert.NoError(t, err)

		tmpFile1.Close()
		tmpFile2.Close()

		path := filepath.Join(filepath.Dir(tmpFile1.Name()), "testfile%-*.txt")
		fs := utils.MockFileSystem{FileExists: true, Err: nil}
		lines, err := processFile(path, true, fs)
		assert.NoError(t, err)
		assert.Len(t, lines, 4)
	})

	t.Run("processFile without wildcard", func(t *testing.T) {
		// Create a temporary file for testing
		tmpFile, err := os.CreateTemp("", "testfile-*.txt")
		assert.NoError(t, err)
		defer os.Remove(tmpFile.Name())

		_, err = tmpFile.WriteString("line1\nline2\n")
		assert.NoError(t, err)
		tmpFile.Close()

		fs := utils.MockFileSystem{FileExists: true, Err: nil}

		lines, err := processFile(tmpFile.Name(), false, fs)
		assert.NoError(t, err)
		assert.Len(t, lines, 2)
	})
}

func TestReadLines(t *testing.T) {
	t.Run("readLines file exists", func(t *testing.T) {
		// Create a temporary file for testing
		tmpFile, err := os.CreateTemp("", "testfile-*.txt")
		assert.NoError(t, err)
		defer os.Remove(tmpFile.Name())

		_, err = tmpFile.WriteString("line1\nline2\n")
		assert.NoError(t, err)
		tmpFile.Close()
		fs := utils.MockFileSystem{FileExists: true, Err: nil}
		lines, err := readLines(tmpFile.Name(), fs)
		assert.NoError(t, err)
		assert.Len(t, lines, 2)
	})

	t.Run("readLines file does not exist", func(t *testing.T) {
		fs := utils.MockFileSystem{FileExists: false, Err: nil}
		lines, err := readLines("nonexistentfile.txt", fs)
		assert.Error(t, err)
		assert.Nil(t, lines)
		assert.Equal(t, "file does not exist", err.Error())
	})
}
