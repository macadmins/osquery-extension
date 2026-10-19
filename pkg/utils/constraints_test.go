package utils

import (
	"reflect"
	"testing"

	"github.com/osquery/osquery-go/plugin/table"
)

func queryOn(column string, constraints ...table.Constraint) table.QueryContext {
	return table.QueryContext{Constraints: map[string]table.ConstraintList{
		column: {Constraints: constraints},
	}}
}

func TestEqualityConstraints(t *testing.T) {
	equals := func(value string) table.Constraint {
		return table.Constraint{Operator: table.OperatorEquals, Expression: value}
	}
	if got := EqualityConstraints(table.QueryContext{}, "user"); got != nil {
		t.Errorf("no constraint: got %v, want nil", got)
	}
	got := EqualityConstraints(queryOn("user", equals("alice"), equals("bob")), "user")
	if !reflect.DeepEqual(got, map[string]struct{}{"alice": {}, "bob": {}}) {
		t.Errorf("two equalities: got %v", got)
	}
	mixed := queryOn("user", equals("alice"),
		table.Constraint{Operator: table.OperatorLike, Expression: "b%"})
	if got := EqualityConstraints(mixed, "user"); got != nil {
		t.Errorf("a mixed operator list widens to every row, got %v", got)
	}
	if got := EqualityConstraints(queryOn("user", equals("")), "user"); len(got) != 1 {
		t.Errorf("an empty-string equality is a constraint, got %v", got)
	}
	if got := EqualityConstraints(queryOn("user", equals("alice")), "uid"); got != nil {
		t.Errorf("a constraint on another column says nothing about this one, got %v", got)
	}
}
