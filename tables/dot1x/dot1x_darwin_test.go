//go:build darwin

package dot1x

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCgoFrameworkLoading(t *testing.T) {
	// Not parallel: dlopen has global state via the static copy_state_fn.
	backend := newBackend()

	// Verify the framework loads and the symbol resolves.
	// load_dot1x() is called in newBackend via sync.Once, so the
	// framework is loaded before the first GetStatus call.
	_, err := backend.GetStatus("en0")
	// EAP8021X.framework should be loadable on any macOS system.
	// The call should NOT fail with ErrBackendUnavailable.
	assert.NotErrorIs(t, err, ErrBackendUnavailable,
		"EAP8021X.framework should be loadable on darwin")

	// If there's no active EAP session on en0, that's fine — we get a
	// non-nil error but NOT ErrBackendUnavailable.
}

func TestCgoBogusInterface(t *testing.T) {
	backend := newBackend()

	_, err := backend.GetStatus("bogus999999")
	require.Error(t, err)
	// Bogus interface should not trigger framework-unavailable error.
	assert.NotErrorIs(t, err, ErrBackendUnavailable)
	assert.Contains(t, err.Error(), "bogus999999")
}

// Docks/USB adapters commonly get en10+; all en* names must be probed.
func TestEnInterfaceNames(t *testing.T) {
	t.Parallel()

	got := enInterfaceNames([]string{"lo0", "en0", "anpi0", "en12", "bridge0", "utun3", "en5", "awdl0", "enc0"})
	assert.Equal(t, []string{"en0", "en12", "en5"}, got)
	assert.Empty(t, enInterfaceNames(nil))
}
