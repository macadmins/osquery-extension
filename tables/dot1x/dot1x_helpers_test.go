package dot1x

import "github.com/osquery/osquery-go/plugin/table"

// constraintFor requests exact matches for the named interfaces.
func constraintFor(names ...string) table.QueryContext {
	constraints := make([]table.Constraint, 0, len(names))
	for _, name := range names {
		constraints = append(constraints, table.Constraint{Operator: table.OperatorEquals, Expression: name})
	}
	return table.QueryContext{Constraints: map[string]table.ConstraintList{
		"interface": {Constraints: constraints},
	}}
}
