package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVersionIsValid(t *testing.T) {
	assert.NotEmpty(t, Version)
	assert.NotEqual(t, "0", Version)
}
