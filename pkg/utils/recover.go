package utils

import (
	"context"
	"errors"
	"log"
	"runtime/debug"

	"github.com/osquery/osquery-go/plugin/table"
)

// RecoverPanics wraps a table's generate function where the table is registered, so a panic
// becomes an error for that query instead of ending the extension process, and with it every
// other table's rows. The panic value can quote input the table was reading, so it is neither
// logged nor returned; the stack, which names functions and offsets only, goes to the
// extension's log.
func RecoverPanics(name string, generate table.GenerateFunc) table.GenerateFunc {
	return func(ctx context.Context, queryContext table.QueryContext) (rows []map[string]string, err error) {
		defer func() {
			if recovered := recover(); recovered != nil {
				log.Printf("%s: recovered from a panic\n%s", name, debug.Stack())
				rows = nil
				err = errors.New(name + ": internal error; the extension log has the stack")
			}
		}()
		return generate(ctx, queryContext)
	}
}
