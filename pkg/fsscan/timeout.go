package fsscan

import (
	"os"
	"strings"
	"time"
)

// WalkTimeoutEnv overrides DefaultWalkTimeout with a Go duration string.
//
// The name is inherited rather than chosen: this was the budget for a filesystem traversal
// that no longer exists, and it survives as the budget for a whole query's discovery. The
// variable is kept spelled as it is because it is operator-facing -- renaming it would
// silently stop honouring the override on every host where one has already been set, which
// is the single property an escape hatch has to keep.
const WalkTimeoutEnv = "MACADMINS_EXTENSION_WALK_TIMEOUT"

// DefaultWalkTimeout bounds one query's discovery in wall-clock time.
//
// The per-file size cap bounds bytes and the list of probed paths bounds how many files are
// opened, which is enough on a local disk. A home directory on a slow network mount can sit
// inside every one of those limits and still take minutes per open. osquery-go sets no
// deadline on the context it hands a table's Generate, so without this the only bound on a
// cold run is osquery's watchdog killing the extension, which drops every other table's rows
// along with the offending one.
//
// Sixty seconds was chosen against a measured cold cost of roughly five seconds for the
// heaviest discovery pass here, and sits well below where the watchdog acts.
//
// One budget per query, not per home: a caller that granted it per home would turn the cost
// into homes x budget, which is the shape that gets the extension killed on a shared Mac.
const DefaultWalkTimeout = 60 * time.Second

// WalkTimeout returns the configured budget.
//
// An absent, unparseable or non-positive value falls back to the default rather than being
// honoured. Those are precisely the values that would remove the bound without anyone
// intending to, and a removed bound is invisible until the watchdog fires.
func WalkTimeout() time.Duration {
	if value := strings.TrimSpace(os.Getenv(WalkTimeoutEnv)); value != "" {
		if parsed, err := time.ParseDuration(value); err == nil && parsed > 0 {
			return parsed
		}
	}
	return DefaultWalkTimeout
}
