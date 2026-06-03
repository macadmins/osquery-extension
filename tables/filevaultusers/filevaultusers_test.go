package filevaultusers

import (
	"context"
	"errors"
	"testing"

	"github.com/osquery/osquery-go/plugin/table"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func withRunFDESetupList(t *testing.T, fn func() ([]byte, error)) {
	t.Helper()
	original := runFDESetupList
	runFDESetupList = fn
	t.Cleanup(func() {
		runFDESetupList = original
	})
}

func TestFileVaultUsersColumns(t *testing.T) {
	assert.Equal(t, []table.ColumnDefinition{
		table.TextColumn("username"),
		table.TextColumn("uuid"),
	}, FileVaultUsersColumns())
}

func TestProcessFDESetupToUsers(t *testing.T) {
	t.Parallel()
	inputBytes := []byte("graham,163DDC62-5D23-40A2-8EC9-0190B267251B")
	expectedOutputItem := FileVaultUser{Username: "graham", UUID: "163DDC62-5D23-40A2-8EC9-0190B267251B"}
	var expectedOutput []FileVaultUser
	expectedOutput = append(expectedOutput, expectedOutputItem)

	output, err := processFDESetupToUsers(inputBytes)
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, len(output), 1, "Output must only have one element")

	assert.Equal(t, expectedOutput, output, "Expected output does not match real output")
}

func TestProcessFDESetupToUsersWithIncorrectInput(t *testing.T) {
	t.Parallel()
	inputBytes := []byte("graham,163DDC62-5D23-40A2-8EC9-0190B267251B,bad_extra_item")
	_, err := processFDESetupToUsers(inputBytes)
	if err == nil {
		t.Error("processFDESetupToUsers did not error when passed a malformed input")
	}

}

func TestProcessFDESetupToUsersWithMultilineInput(t *testing.T) {
	t.Parallel()
	inputBytes := []byte("graham,163DDC62-5D23-40A2-8EC9-0190B267251B\ndave,A643042D-6F7C-4A87-9EDB-2CA267035B01")
	var expectedOutput []FileVaultUser
	expectedOutput = append(expectedOutput, FileVaultUser{Username: "graham", UUID: "163DDC62-5D23-40A2-8EC9-0190B267251B"})
	expectedOutput = append(expectedOutput, FileVaultUser{Username: "dave", UUID: "A643042D-6F7C-4A87-9EDB-2CA267035B01"})

	output, err := processFDESetupToUsers(inputBytes)
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, expectedOutput, output, "Expected output does not match real output")

}

func TestProcessFDESetupToUsersIgnoresBlankLines(t *testing.T) {
	t.Parallel()
	inputBytes := []byte("\ngraham,163DDC62-5D23-40A2-8EC9-0190B267251B\n\n")
	output, err := processFDESetupToUsers(inputBytes)
	require.NoError(t, err)
	assert.Equal(t, []FileVaultUser{
		{Username: "graham", UUID: "163DDC62-5D23-40A2-8EC9-0190B267251B"},
	}, output)
}

func TestProcessFDESetupToUsersEmptyInput(t *testing.T) {
	t.Parallel()
	output, err := processFDESetupToUsers(nil)
	require.NoError(t, err)
	assert.Empty(t, output)
}

func TestGetFileVaultUsers(t *testing.T) {
	withRunFDESetupList(t, func() ([]byte, error) {
		return []byte("graham,163DDC62-5D23-40A2-8EC9-0190B267251B"), nil
	})

	output, err := getFileVaultUsers()
	require.NoError(t, err)
	assert.Equal(t, []FileVaultUser{
		{Username: "graham", UUID: "163DDC62-5D23-40A2-8EC9-0190B267251B"},
	}, output)
}

func TestGetFileVaultUsersCommandError(t *testing.T) {
	withRunFDESetupList(t, func() ([]byte, error) {
		return nil, errors.New("fdesetup failed")
	})

	output, err := getFileVaultUsers()
	assert.Error(t, err)
	assert.Empty(t, output)
	assert.ErrorContains(t, err, "runFDESetupList")
	assert.ErrorContains(t, err, "fdesetup failed")
}

func TestGetFileVaultUsersParseError(t *testing.T) {
	withRunFDESetupList(t, func() ([]byte, error) {
		return []byte("graham,uuid,extra"), nil
	})

	output, err := getFileVaultUsers()
	assert.Error(t, err)
	assert.Empty(t, output)
	assert.ErrorContains(t, err, "processFDESetupToUsers")
}

func TestFileVaultUsersGenerate(t *testing.T) {
	withRunFDESetupList(t, func() ([]byte, error) {
		return []byte("graham,163DDC62-5D23-40A2-8EC9-0190B267251B\ndave,A643042D-6F7C-4A87-9EDB-2CA267035B01"), nil
	})

	results, err := FileVaultUsersGenerate(context.Background(), table.QueryContext{})
	require.NoError(t, err)
	assert.Equal(t, []map[string]string{
		{"username": "graham", "uuid": "163DDC62-5D23-40A2-8EC9-0190B267251B"},
		{"username": "dave", "uuid": "A643042D-6F7C-4A87-9EDB-2CA267035B01"},
	}, results)
}

func TestFileVaultUsersGenerateError(t *testing.T) {
	withRunFDESetupList(t, func() ([]byte, error) {
		return nil, errors.New("fdesetup failed")
	})

	results, err := FileVaultUsersGenerate(context.Background(), table.QueryContext{})
	assert.Error(t, err)
	assert.Empty(t, results)
}
