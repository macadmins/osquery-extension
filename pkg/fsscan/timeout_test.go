package fsscan

import (
	"testing"
	"time"
)

// The budget is read from the environment on every call, so the fallback matters as much as
// the override: a value that is absent, unparseable or non-positive must not be honoured,
// because honouring it removes the only wall-clock bound a query has and nothing says so
// until osquery's watchdog kills the extension.
func TestWalkTimeoutHonoursEnvOverride(t *testing.T) {
	// Cleared first: the assertion below is about the default, and a developer who exports
	// this variable in their shell would otherwise see a spurious failure.
	t.Setenv(WalkTimeoutEnv, "")
	if got := WalkTimeout(); got != DefaultWalkTimeout {
		t.Errorf("default = %v, want %v", got, DefaultWalkTimeout)
	}
	t.Setenv(WalkTimeoutEnv, "5s")
	if got := WalkTimeout(); got != 5*time.Second {
		t.Errorf("override = %v, want 5s", got)
	}
	// A malformed or non-positive value falls back rather than disabling the budget, which
	// would silently remove the protection.
	for _, bad := range []string{"", "nonsense", "0s", "-10s"} {
		t.Setenv(WalkTimeoutEnv, bad)
		if got := WalkTimeout(); got != DefaultWalkTimeout {
			t.Errorf("%q = %v, want the default", bad, got)
		}
	}
}
