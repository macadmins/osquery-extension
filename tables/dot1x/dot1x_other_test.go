//go:build !darwin && !windows

package dot1x

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// On platforms without an 802.1X backend (Linux, etc.), newBackend returns a
// noopBackend whose GetStatus reports the systemic ErrBackendUnavailable.
func TestOtherBackendUnavailable(t *testing.T) {
	t.Parallel()

	b := newBackend()
	_, ok := b.(noopBackend)
	require.True(t, ok, "non-darwin/windows newBackend should return noopBackend")

	s, err := b.GetStatus("eth0")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrBackendUnavailable)
	assert.Equal(t, "eth0", s.Interface)
}

func TestOtherDefaultInterfaces(t *testing.T) {
	t.Parallel()

	ifaces := defaultInterfaces()
	require.Len(t, ifaces, 10)
	assert.Equal(t, "en0", ifaces[0])
	assert.Equal(t, "en9", ifaces[9])
}
