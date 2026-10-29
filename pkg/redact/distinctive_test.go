package redact

import (
	"strings"
	"testing"
)

// TestContainsDistinctiveToken: the narrow check matches the distinctive credential formats and
// not the ordinary names the broad sk- and gitlab- patterns catch, and everything it matches,
// String also redacts, so the two patterns cannot drift apart in the unsafe direction.
func TestContainsDistinctiveToken(t *testing.T) {
	credentials := []string{
		"example.com/ghp_" + strings.Repeat("a", 36),
		"github_pat_" + strings.Repeat("b", 30),
		"glpat-" + strings.Repeat("c", 20),
		"xoxb-" + strings.Repeat("1", 12),
		"sk-proj-" + strings.Repeat("d", 24),
		"sk-ant-" + strings.Repeat("e", 24),
		"example.com/acme/sk-proj-" + strings.Repeat("h", 24),
		"AKIA" + strings.Repeat("F", 16),
		"AIza" + strings.Repeat("g", 35),
	}
	for _, value := range credentials {
		if !ContainsDistinctiveToken(value) {
			t.Errorf("ContainsDistinctiveToken(%q) = false, want true", value)
		}
		if String(value) == value {
			t.Errorf("String(%q) left a distinctive format unredacted", value)
		}
	}
	for _, value := range []string{
		"github.com/acme/sk-payments-service-client",
		"github.com/acme/gitlab-ci-pipeline-exporter-tools",
		"github.com/acme/task-management-service-client",
		"github.com/acme/task-proj-" + strings.Repeat("i", 24),
		"github.com/acme/disk-ant-" + strings.Repeat("j", 24),
		"golang.org/x/sys",
	} {
		if ContainsDistinctiveToken(value) {
			t.Errorf("ContainsDistinctiveToken(%q) = true for an ordinary name", value)
		}
	}
}
