package fileline

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/macadmins/osquery-extension/pkg/utils"
	"github.com/osquery/osquery-go/plugin/table"
	"github.com/stretchr/testify/assert"
)

func TestFileLineColumns(t *testing.T) {
	assert.Equal(t, []table.ColumnDefinition{
		table.TextColumn("line"),
		table.TextColumn("path"),
	}, FileLineColumns())
}

func TestProcessFile(t *testing.T) {
	t.Run("processFile with wildcard", func(t *testing.T) {
		// Create temporary files for testing
		tmpFile1, err := os.CreateTemp("", "testfile1-*.txt")
		assert.NoError(t, err)
		defer func() {
			assert.NoError(t, os.Remove(tmpFile1.Name()))
		}()

		tmpFile2, err := os.CreateTemp("", "testfile2-*.txt")
		assert.NoError(t, err)
		defer func() {
			assert.NoError(t, os.Remove(tmpFile2.Name()))
		}()

		_, err = tmpFile1.WriteString("line1\nline2\n")
		assert.NoError(t, err)
		_, err = tmpFile2.WriteString("line3\nline4\n")
		assert.NoError(t, err)

		assert.NoError(t, tmpFile1.Close())
		assert.NoError(t, tmpFile2.Close())

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
		defer func() {
			assert.NoError(t, os.Remove(tmpFile.Name()))
		}()

		_, err = tmpFile.WriteString("line1\nline2\n")
		assert.NoError(t, err)
		assert.NoError(t, tmpFile.Close())

		fs := utils.MockFileSystem{FileExists: true, Err: nil}

		lines, err := processFile(tmpFile.Name(), false, fs)
		assert.NoError(t, err)
		assert.Len(t, lines, 2)
	})

	t.Run("invalid wildcard pattern", func(t *testing.T) {
		lines, err := processFile("[", true, utils.MockFileSystem{FileExists: true})
		assert.Error(t, err)
		assert.Nil(t, lines)
	})

	t.Run("read error is returned without wildcard", func(t *testing.T) {
		lines, err := processFile(filepath.Join(t.TempDir(), "missing.txt"), false, utils.MockFileSystem{FileExists: true})
		assert.Error(t, err)
		assert.Nil(t, lines)
	})

	t.Run("read error is returned with wildcard", func(t *testing.T) {
		tmpFile := filepath.Join(t.TempDir(), "testfile-one.txt")
		err := os.Mkdir(tmpFile, os.ModePerm)
		assert.NoError(t, err)

		path := filepath.Join(filepath.Dir(tmpFile), "testfile%.txt")
		lines, err := processFile(path, true, utils.MockFileSystem{FileExists: false})
		assert.Error(t, err)
		assert.Nil(t, lines)
	})
}

func TestReadLines(t *testing.T) {
	t.Run("readLines file exists", func(t *testing.T) {
		// Create a temporary file for testing
		tmpFile, err := os.CreateTemp("", "testfile-*.txt")
		assert.NoError(t, err)
		defer func() {
			assert.NoError(t, os.Remove(tmpFile.Name()))
		}()

		_, err = tmpFile.WriteString("line1\nline2\n")
		assert.NoError(t, err)
		assert.NoError(t, tmpFile.Close())
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

	t.Run("readLines open error", func(t *testing.T) {
		fs := utils.MockFileSystem{FileExists: true, Err: nil}
		lines, err := readLines(filepath.Join(t.TempDir(), "missing.txt"), fs)
		assert.Error(t, err)
		assert.Nil(t, lines)
	})
}

func TestFileLineGenerate(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "testfile-*.txt")
	assert.NoError(t, err)
	defer func() {
		assert.NoError(t, os.Remove(tmpFile.Name()))
	}()

	_, err = tmpFile.WriteString("line1\nline2\n")
	assert.NoError(t, err)
	assert.NoError(t, tmpFile.Close())

	results, err := FileLineGenerate(context.Background(), table.QueryContext{
		Constraints: map[string]table.ConstraintList{
			"path": {Constraints: []table.Constraint{{
				Operator:   table.OperatorEquals,
				Expression: tmpFile.Name(),
			}}},
		},
	})
	assert.NoError(t, err)
	assert.Equal(t, []map[string]string{
		{"line": "line1", "path": tmpFile.Name()},
		{"line": "line2", "path": tmpFile.Name()},
	}, results)
}

func TestFileLineGenerateReturnsPathErrors(t *testing.T) {
	results, err := FileLineGenerate(context.Background(), table.QueryContext{
		Constraints: map[string]table.ConstraintList{
			"path": {Constraints: []table.Constraint{{
				Operator:   table.OperatorEquals,
				Expression: filepath.Join(t.TempDir(), "missing.txt"),
			}}},
		},
	})
	assert.Error(t, err)
	assert.Empty(t, results)
}
