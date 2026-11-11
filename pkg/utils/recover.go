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
				rows = nil
				err = logRecovered(name)
			}
		}()
		return generate(ctx, queryContext)
	}
}

// RecoverWorker wraps work a table runs on a goroutine of its own, such as an errgroup
// callback. recover stops a panic only on the goroutine that defers it, so RecoverPanics at
// registration does not reach these; with this, the panic becomes the worker's error, reported
// as RecoverPanics reports one.
func RecoverWorker(name string, work func() error) func() error {
	return func() (err error) {
		defer func() {
			if recovered := recover(); recovered != nil {
				err = logRecovered(name)
			}
		}()
		return work()
	}
}

// logRecovered logs the stack of the panic being recovered and returns the fixed error text.
func logRecovered(name string) error {
	log.Printf("%s: recovered from a panic\n%s", name, debug.Stack())
	return errors.New(name + ": internal error; the extension log has the stack")
}
