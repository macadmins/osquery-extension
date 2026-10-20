package utils

import (
	"context"
	"strings"
	"testing"

	"github.com/osquery/osquery-go/plugin/table"
)

// TestRecoverPanicsReturnsFixedText: a panic is recovered into an error, and the panic value,
// which can quote a file the table was reading, does not reach osquery.
func TestRecoverPanicsReturnsFixedText(t *testing.T) {
	panicking := func(context.Context, table.QueryContext) ([]map[string]string, error) {
		panic("unexpected token in TOKEN=opaqueSecret")
	}
	rows, err := RecoverPanics("some_table", panicking)(context.Background(), table.QueryContext{})
	if err == nil || rows != nil {
		t.Fatalf("rows = %v, err = %v; want no rows and an error", rows, err)
	}
	if !strings.HasPrefix(err.Error(), "some_table: ") {
		t.Errorf("the error does not name the table: %q", err)
	}
	if strings.Contains(err.Error(), "opaqueSecret") || strings.Contains(err.Error(), "goroutine") {
		t.Errorf("the error carries the panic value or the stack: %q", err)
	}
}

// TestRecoverPanicsPassesResultsThrough: without a panic the wrapper changes nothing.
func TestRecoverPanicsPassesResultsThrough(t *testing.T) {
	want := []map[string]string{{"column": "value"}}
	healthy := func(context.Context, table.QueryContext) ([]map[string]string, error) {
		return want, nil
	}
	rows, err := RecoverPanics("some_table", healthy)(context.Background(), table.QueryContext{})
	if err != nil || len(rows) != 1 || rows[0]["column"] != "value" {
		t.Errorf("rows = %v, err = %v; want the generator's rows unchanged", rows, err)
	}
}
