package authdb

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/groob/plist"
	"github.com/macadmins/osquery-extension/pkg/utils"
	"github.com/osquery/osquery-go/plugin/table"
)

type AuthDBRight struct {
	Name               string   `json:"name" plist:"name"`
	AllowRoot          bool     `json:"allow-root" plist:"allow-root"`
	AuthenticateUser   bool     `json:"authenticate-user" plist:"authenticate-user"`
	Class              string   `json:"class" plist:"class"`
	Comment            string   `json:"comment" plist:"comment"`
	Created            float64  `json:"created" plist:"created"`
	Group              string   `json:"group" plist:"group"`
	Mechanisms         []string `json:"mechanisms,omitempty" plist:"mechanisms,omitempty"`
	Modified           float64  `json:"modified" plist:"modified"`
	RequireAppleSigned bool     `json:"require-apple-signed,omitempty" plist:"require-apple-signed,omitempty"`
	Rule               []string `json:"rule,omitempty" plist:"rule,omitempty"`
	SessionOwner       bool     `json:"session-owner" plist:"session-owner"`
	Shared             bool     `json:"shared" plist:"shared"`
	Timeout            int      `json:"timeout" plist:"timeout"`
	Tries              int      `json:"tries" plist:"tries"`
	Version            int      `json:"version" plist:"version"`
}

func AuthDBColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("name"),
		table.TextColumn("allow_root"),
		table.TextColumn("authenticate_user"),
		table.TextColumn("class"),
		table.TextColumn("comment"),
		table.TextColumn("created"),
		table.TextColumn("group"),
		table.TextColumn("mechanisms"),
		table.TextColumn("modified"),
		table.TextColumn("require_apple_signed"),
		table.TextColumn("rule"),
		table.TextColumn("session_owner"),
		table.TextColumn("shared"),
		table.TextColumn("timeout"),
		table.TextColumn("tries"),
		table.TextColumn("version"),
	}
}

func AuthDBGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	r := utils.NewRunner()

	var err error

	ruleNames := processContextConstraints(queryContext)

	if len(ruleNames) == 0 {
		ruleNames, err = getRuleNames(r)
		if err != nil {
			return nil, err
		}
	}

	rights, err := getRules(r, ruleNames)
	if err != nil {
		return nil, err
	}

	return buildOutput(rights), nil
}

func processContextConstraints(queryContext table.QueryContext) []string {
	var ruleNames []string

	// name is in the where clause
	if constraintList, present := queryContext.Constraints["name"]; present {
		for _, constraint := range constraintList.Constraints {
			// =
			if constraint.Operator == table.OperatorEquals {
				ruleNames = append(ruleNames, constraint.Expression)
			}
		}
	}

	return ruleNames
}

func getRules(r utils.Runner, ruleNames []string) ([]AuthDBRight, error) {
	var rights []AuthDBRight

	for _, ruleName := range ruleNames {
		rule, err := getRule(r, ruleName)
		if err != nil {
			return nil, err
		}
		rights = append(rights, rule)
	}

	return rights, nil
}

func buildOutput(rights []AuthDBRight) []map[string]string {
	var results []map[string]string

	for _, right := range rights {
		results = append(results, map[string]string{
			"name":                 right.Name,
			"allow_root":           utils.BoolToString(right.AllowRoot),
			"authenticate_user":    utils.BoolToString(right.AuthenticateUser),
			"class":                right.Class,
			"comment":              right.Comment,
			"created":              fmt.Sprintf("%f", right.Created),
			"group":                right.Group,
			"mechanisms":           strings.Join(right.Mechanisms, ","),
			"modified":             fmt.Sprintf("%f", right.Modified),
			"require_apple_signed": utils.BoolToString(right.RequireAppleSigned),
			"rule":                 strings.Join(right.Rule, ","),
			"session_owner":        utils.BoolToString(right.SessionOwner),
			"shared":               utils.BoolToString(right.Shared),
			"timeout":              strconv.Itoa(right.Timeout),
			"tries":                strconv.Itoa(right.Tries),
			"version":              strconv.Itoa(right.Version),
		})
	}

	return results
}

func getRuleNames(r utils.Runner) ([]string, error) {
	output, err := r.Runner.RunCmd("/usr/bin/sqlite3", "/var/db/auth.db", ".mode json", "select name from rules;", ".exit")
	if err != nil {
		return nil, err
	}

	type AuthDBRule struct {
		Name string `json:"name"`
	}

	var rules []AuthDBRule
	if err := json.Unmarshal(output, &rules); err != nil {
		return nil, err
	}

	var ruleNames []string
	for _, rule := range rules {
		ruleNames = append(ruleNames, rule.Name)
	}

	return ruleNames, nil
}

func getRule(r utils.Runner, ruleName string) (AuthDBRight, error) {
	output, err := r.Runner.RunCmd("/usr/bin/security", "authorizationdb", "read", ruleName)
	if err != nil {
		return AuthDBRight{}, err
	}

	var rule AuthDBRight
	if err := plist.Unmarshal(output, &rule); err != nil {
		return AuthDBRight{}, err
	}

	rule.Name = ruleName

	return rule, nil
}
