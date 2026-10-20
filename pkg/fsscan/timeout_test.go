package fsscan

import (
	"context"
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

// TestBudgetRemains: a scan stops when its query is cancelled or its deadline has passed.
func TestBudgetRemains(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	future, past := time.Now().Add(time.Hour), time.Now().Add(-time.Second)
	for _, tc := range []struct {
		name     string
		ctx      context.Context
		deadline time.Time
		want     bool
	}{
		{"wanted, in time", context.Background(), future, true},
		{"cancelled", cancelled, future, false},
		{"past the deadline", context.Background(), past, false},
	} {
		if got := BudgetRemains(tc.ctx, tc.deadline); got != tc.want {
			t.Errorf("%s: BudgetRemains = %v, want %v", tc.name, got, tc.want)
		}
	}
}
