package authdb

import (
	"testing"

	"github.com/macadmins/osquery-extension/pkg/utils"
	"github.com/osquery/osquery-go/plugin/table"
	"github.com/stretchr/testify/assert"
)

func TestGetRuleNames(t *testing.T) {

	runner := utils.MockCmdRunner{
		Output: `[{"name":""},
		{"name":"_mbsetupuser-nonshared"},
		{"name":"admin"},
		{"name":"allow"},
		{"name":"app-specific-admin"},
		{"name":"appserver-admin"},
		{"name":"appserver-user"},
		{"name":"authenticate"},
		{"name":"authenticate-admin"},
		{"name":"authenticate-admin-30"},
		{"name":"authenticate-admin-extract"}]`,
		Err: nil,
	}

	expected := []string{
		"",
		"_mbsetupuser-nonshared",
		"admin",
		"allow",
		"app-specific-admin",
		"appserver-admin",
		"appserver-user",
		"authenticate",
		"authenticate-admin",
		"authenticate-admin-30",
		"authenticate-admin-extract",
	}

	r := utils.Runner{}
	r.Runner = runner
	out, err := getRuleNames(r)
	assert.NoError(t, err)
	assert.Equal(t, expected, out)

}

func TestGetRule(t *testing.T) {
	runner := utils.MockCmdRunner{
		Output: `<?xml version="1.0" encoding="UTF-8"?>
		<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
		<plist version="1.0">
		<dict>
				<key>allow-root</key>
				<false/>
				<key>authenticate-user</key>
				<false/>
				<key>class</key>
				<string>user</string>
				<key>comment</key>
				<string>Succeeds if user is from _mbsetupuser group.</string>
				<key>created</key>
				<real>730353220.36463201</real>
				<key>group</key>
				<string>_mbsetupuser</string>
				<key>modified</key>
				<real>730353220.36463201</real>
				<key>session-owner</key>
				<false/>
				<key>shared</key>
				<false/>
				<key>timeout</key>
				<integer>30</integer>
				<key>tries</key>
				<integer>10000</integer>
				<key>version</key>
				<integer>0</integer>
		</dict>
		</plist>`,
		Err: nil,
	}

	expected := AuthDBRight{
		Name:             "_mbsetupuser-nonshared",
		AllowRoot:        false,
		AuthenticateUser: false,
		Class:            "user",
		Comment:          "Succeeds if user is from _mbsetupuser group.",
		Created:          730353220.36463201,
		Group:            "_mbsetupuser",
		Modified:         730353220.36463201,
		SessionOwner:     false,
		Shared:           false,
		Timeout:          30,
		Tries:            10000,
		Version:          0,
	}

	r := utils.Runner{}
	r.Runner = runner
	out, err := getRule(r, "_mbsetupuser-nonshared")
	assert.NoError(t, err)
	assert.Equal(t, expected, out)
}

func TestAuthDBColumns(t *testing.T) {
	expectedColumns := []table.ColumnDefinition{
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
		table.TextColumn("session_owner"),
		table.TextColumn("shared"),
		table.TextColumn("timeout"),
		table.TextColumn("tries"),
		table.TextColumn("version"),
	}

	actualColumns := AuthDBColumns()

	assert.Equal(t, expectedColumns, actualColumns, "Expected columns to match")
}

func TestProcessContextConstraints(t *testing.T) {
	queryContext := table.QueryContext{
		Constraints: map[string]table.ConstraintList{
			"name": {
				Constraints: []table.Constraint{
					{
						Operator:   table.OperatorEquals,
						Expression: "testRule",
					},
				},
			},
		},
	}

	expectedRuleNames := []string{"testRule"}
	actualRuleNames := processContextConstraints(queryContext)

	assert.Equal(t, expectedRuleNames, actualRuleNames, "Expected rule names to match")

	// Test with no constraints
	queryContext = table.QueryContext{
		Constraints: map[string]table.ConstraintList{},
	}
	expectedRuleNames = []string(nil)
	actualRuleNames = processContextConstraints(queryContext)
	assert.Equal(t, expectedRuleNames, actualRuleNames, "Expected no rule names")
}

func TestGetRules(t *testing.T) {
	runner := utils.MockCmdRunner{
		Output: `<?xml version="1.0" encoding="UTF-8"?>
		<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
		<plist version="1.0">
		<dict>
			<key>class</key>
			<string>evaluate-mechanisms</string>
			<key>comment</key>
			<string>Login mechanism based rule.  Not for general use, yet.</string>
			<key>created</key>
			<real>730353220.36463201</real>
			<key>mechanisms</key>
			<array>
				<string>builtin:prelogin</string>
				<string>builtin:policy-banner</string>
				<string>loginwindow:login</string>
				<string>builtin:login-begin</string>
				<string>builtin:reset-password,privileged</string>
				<string>loginwindow:FDESupport,privileged</string>
				<string>builtin:forward-login,privileged</string>
				<string>builtin:auto-login,privileged</string>
				<string>builtin:authenticate,privileged</string>
				<string>PKINITMechanism:auth,privileged</string>
				<string>builtin:login-success</string>
				<string>loginwindow:success</string>
				<string>HomeDirMechanism:login,privileged</string>
				<string>HomeDirMechanism:status</string>
				<string>MCXMechanism:login</string>
				<string>CryptoTokenKit:login</string>
				<string>Crypt:Check,privileged</string>
				<string>Crypt:CryptGUI</string>
				<string>Crypt:Enablement,privileged</string>
				<string>loginwindow:done</string>
			</array>
			<key>modified</key>
			<real>738007875.40967596</real>
			<key>shared</key>
			<true/>
			<key>tries</key>
			<integer>10000</integer>
			<key>version</key>
			<integer>11</integer>
		</dict>
		</plist>`,
		Err: nil,
	}

	expected := []AuthDBRight{
		{
			Name:    "system.login.console",
			Class:   "evaluate-mechanisms",
			Comment: "Login mechanism based rule.  Not for general use, yet.",
			Created: 730353220.36463201,
			Mechanisms: []string{
				"builtin:prelogin",
				"builtin:policy-banner",
				"loginwindow:login",
				"builtin:login-begin",
				"builtin:reset-password,privileged",
				"loginwindow:FDESupport,privileged",
				"builtin:forward-login,privileged",
				"builtin:auto-login,privileged",
				"builtin:authenticate,privileged",
				"PKINITMechanism:auth,privileged",
				"builtin:login-success",
				"loginwindow:success",
				"HomeDirMechanism:login,privileged",
				"HomeDirMechanism:status",
				"MCXMechanism:login",
				"CryptoTokenKit:login",
				"Crypt:Check,privileged",
				"Crypt:CryptGUI",
				"Crypt:Enablement,privileged",
				"loginwindow:done",
			},
			Modified: 738007875.40967596,
			Shared:   true,
			Tries:    10000,
			Version:  11,
		},
	}

	r := utils.Runner{}
	r.Runner = runner
	out, err := getRules(r, []string{"system.login.console"})
	assert.NoError(t, err)
	assert.Equal(t, expected, out)
}

func TestBuildOutput(t *testing.T) {
	rights := []AuthDBRight{
		{
			Name:               "testRule",
			AllowRoot:          true,
			AuthenticateUser:   false,
			Class:              "class",
			Comment:            "comment",
			Created:            1.0,
			Group:              "group",
			Mechanisms:         []string{"mechanism1", "mechanism2"},
			Modified:           2.0,
			RequireAppleSigned: true,
			SessionOwner:       false,
			Shared:             true,
			Timeout:            10,
			Tries:              5,
			Version:            1,
		},
	}

	expectedOutput := []map[string]string{
		{
			"name":                 "testRule",
			"allow_root":           "true",
			"authenticate_user":    "false",
			"class":                "class",
			"comment":              "comment",
			"created":              "1.000000",
			"group":                "group",
			"mechanisms":           "mechanism1,mechanism2",
			"modified":             "2.000000",
			"require_apple_signed": "true",
			"session_owner":        "false",
			"shared":               "true",
			"timeout":              "10",
			"tries":                "5",
			"version":              "1",
		},
	}

	actualOutput := buildOutput(rights)

	assert.Equal(t, expectedOutput, actualOutput, "Expected output to match")
}
