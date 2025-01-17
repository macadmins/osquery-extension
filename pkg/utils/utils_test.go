package utils

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFileExists(t *testing.T) {
	// Create a temporary file for testing
	fs := MockFileSystem{
		FileExists: true,
		Err:        nil,
	}
	tempFile, err := os.CreateTemp("", "test")
	assert.NoError(t, err, "Failed to create temp file")

	defer os.Remove(tempFile.Name())
	tempFile.Close()

	// Test that FileExists returns true for an existing file
	assert.True(t, FileExists(fs, tempFile.Name()), "Expected file to exist")

	// Delete the temporary file
	os.Remove(tempFile.Name())

	// Test that FileExists returns false for a non-existing file
	assert.False(t, FileExists(fs, tempFile.Name()), "Expected file to not exist")
}

func TestBoolToString(t *testing.T) {
	// Test that BoolToString returns "true" for true
	assert.Equal(t, "true", BoolToString(true), "Expected true as string")

	// Test that BoolToString returns "false" for false
	assert.Equal(t, "false", BoolToString(false), "Expected false as string")
}
