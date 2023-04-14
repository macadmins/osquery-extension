package filevaultusers

import (
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
)

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

	if len(output) != 1 {
		t.Error("Output must only have one element")
	}
	if !reflect.DeepEqual(expectedOutput, output) {
		t.Error(cmp.Diff(expectedOutput, output))
	}
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

	if !reflect.DeepEqual(expectedOutput, output) {
		t.Error(cmp.Diff(expectedOutput, output))
	}
}
