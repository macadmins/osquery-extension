package utils

import "github.com/osquery/osquery-go/plugin/table"

// EqualityConstraints returns the values a query compares column against with `=`, or nil to
// generate every row.
//
// Equality only, and all of it or none. QueryContext does not carry enough of the original
// boolean structure to prove an equality subset is sufficient, so a list that mixes operators
// -- `user = 'alice' OR user LIKE 'b%'` -- returns nil rather than alice alone. Generating more
// rows than asked costs time; returning fewer rows than the query matches is a wrong answer.
//
// An equality against the empty string is kept, not treated as no constraint: a query for
// rows whose user is empty must not widen into every account.
func EqualityConstraints(qc table.QueryContext, column string) map[string]struct{} {
	constraintList, ok := qc.Constraints[column]
	if !ok {
		return nil
	}
	values := make(map[string]struct{})
	for _, constraint := range constraintList.Constraints {
		if constraint.Operator != table.OperatorEquals {
			return nil
		}
		values[constraint.Expression] = struct{}{}
	}
	if len(values) == 0 {
		return nil
	}
	return values
}
