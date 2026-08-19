//go:build darwin || windows

package dot1x

import "github.com/osquery/osquery-go/plugin/table"

// constraintFor builds a QueryContext with a single exact-match `interface`
// constraint. Shared by the darwin and windows backend tests (it is unused on
// other platforms, hence the build tag rather than an untagged helper file).
func constraintFor(ifname string) table.QueryContext {
	return table.QueryContext{
		Constraints: map[string]table.ConstraintList{
			"interface": {
				Constraints: []table.Constraint{
					{Operator: table.OperatorEquals, Expression: ifname},
				},
			},
		},
	}
}
