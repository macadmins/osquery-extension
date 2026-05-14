package puppet

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/osquery/osquery-go/plugin/table"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func samplePuppetInfo() *PuppetInfo {
	return &PuppetInfo{
		CachedCatalogStatus:  "not_used",
		CatalogUUID:          "catalog-uuid",
		CodeID:               "code-id",
		ConfigurationVersion: "123",
		CorrectiveChange:     "false",
		Environment:          "production",
		Host:                 "example.local",
		Kind:                 "apply",
		MasterUsed:           "puppet.example.com",
		Noop:                 "false",
		NoopPending:          "false",
		PuppetVersion:        "8.0.0",
		ReportFormat:         "12",
		Status:               "changed",
		Time:                 "2026-01-01T00:00:00Z",
		TransactionCompleted: "true",
		TransactionUUID:      "transaction-uuid",
		Logs: []Log{{
			Level:   "notice",
			Message: "configured",
			Source:  "Puppet",
			Time:    "2026-01-01T00:00:00Z",
			File:    "/tmp/manifest.pp",
			Line:    "1",
		}},
		ResourceStatuses: map[string]ResourceStatus{
			"File[/tmp/example]": {
				Title:            "/tmp/example",
				File:             "/tmp/manifest.pp",
				Line:             "1",
				Resource:         "File[/tmp/example]",
				ResourceType:     "File",
				EvaulationTime:   "0.1",
				Failed:           "false",
				Changed:          "true",
				OutOfSync:        "true",
				Skipped:          "false",
				ChangeCount:      "1",
				OutOfSyncCount:   "1",
				CorrectiveChange: "false",
			},
		},
	}
}

func withPuppetYAML(t *testing.T, info *PuppetInfo, err error) {
	t.Helper()
	original := getPuppetYamlFunc
	getPuppetYamlFunc = func() (*PuppetInfo, error) {
		return info, err
	}
	t.Cleanup(func() {
		getPuppetYamlFunc = original
	})
}

func withPuppetFacts(t *testing.T, facts *puppetFacts, err error) {
	t.Helper()
	original := getPuppetFactsFunc
	getPuppetFactsFunc = func() (*puppetFacts, error) {
		return facts, err
	}
	t.Cleanup(func() {
		getPuppetFactsFunc = original
	})
}

func withPuppetYAMLPath(t *testing.T, path string) {
	t.Helper()
	original := puppetYAMLPath
	puppetYAMLPath = func() string {
		return path
	}
	t.Cleanup(func() {
		puppetYAMLPath = original
	})
}

func withRunPuppetFactsCmd(t *testing.T, fn func(string) ([]byte, error)) {
	t.Helper()
	original := runPuppetFactsCmd
	runPuppetFactsCmd = fn
	t.Cleanup(func() {
		runPuppetFactsCmd = original
	})
}

func TestPuppetColumns(t *testing.T) {
	assert.Contains(t, PuppetInfoColumns(), table.TextColumn("transaction_uuid"))
	assert.Equal(t, []table.ColumnDefinition{
		table.TextColumn("level"),
		table.TextColumn("message"),
		table.TextColumn("source"),
		table.TextColumn("time"),
		table.TextColumn("file"),
		table.TextColumn("line"),
	}, PuppetLogsColumns())
	assert.Contains(t, PuppetStateColumns(), table.TextColumn("resource_type"))
	assert.Equal(t, []table.ColumnDefinition{
		table.TextColumn("node"),
		table.TextColumn("fact"),
		table.TextColumn("value"),
	}, PuppetFactsColumns())
}

func TestPuppetInfoGenerate(t *testing.T) {
	withPuppetYAML(t, samplePuppetInfo(), nil)

	rows, err := PuppetInfoGenerate(context.Background(), table.QueryContext{})
	require.NoError(t, err)
	assert.Equal(t, "transaction-uuid", rows[0]["transaction_uuid"])
	assert.Equal(t, "changed", rows[0]["status"])
}

func TestPuppetLogsGenerate(t *testing.T) {
	withPuppetYAML(t, samplePuppetInfo(), nil)

	rows, err := PuppetLogsGenerate(context.Background(), table.QueryContext{})
	require.NoError(t, err)
	assert.Equal(t, []map[string]string{{
		"level":   "notice",
		"message": "configured",
		"source":  "Puppet",
		"time":    "2026-01-01T00:00:00Z",
		"file":    "/tmp/manifest.pp",
		"line":    "1",
	}}, rows)
}

func TestPuppetStateGenerate(t *testing.T) {
	withPuppetYAML(t, samplePuppetInfo(), nil)

	rows, err := PuppetStateGenerate(context.Background(), table.QueryContext{})
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, "File[/tmp/example]", rows[0]["resource"])
	assert.Equal(t, "File", rows[0]["resource_type"])
}

func TestPuppetGeneratorsReturnYAMLErrors(t *testing.T) {
	withPuppetYAML(t, nil, errors.New("yaml failed"))

	_, err := PuppetInfoGenerate(context.Background(), table.QueryContext{})
	assert.Error(t, err)
	_, err = PuppetLogsGenerate(context.Background(), table.QueryContext{})
	assert.Error(t, err)
	_, err = PuppetStateGenerate(context.Background(), table.QueryContext{})
	assert.Error(t, err)
}

func TestPuppetFactsGenerate(t *testing.T) {
	withPuppetFacts(t, &puppetFacts{
		Name: "example.local",
		Values: map[string]interface{}{
			"os":     map[string]interface{}{"family": "Darwin"},
			"uptime": "1 day",
		},
	}, nil)

	rows, err := PuppetFactsGenerate(context.Background(), table.QueryContext{})
	require.NoError(t, err)
	assert.ElementsMatch(t, []map[string]string{
		{"node": "example.local", "fact": "os", "value": `{"family":"Darwin"}`},
		{"node": "example.local", "fact": "uptime", "value": "1 day"},
	}, rows)
}

func TestPuppetFactsGenerateError(t *testing.T) {
	withPuppetFacts(t, nil, errors.New("facts failed"))

	rows, err := PuppetFactsGenerate(context.Background(), table.QueryContext{})
	assert.Error(t, err)
	assert.Nil(t, rows)
}

func TestGetPuppetYaml(t *testing.T) {
	path := filepath.Join(t.TempDir(), "last_run_report.yaml")
	require.NoError(t, os.WriteFile(path, []byte("host: example.local\rstatus: changed\rtransaction_uuid: transaction-uuid\r"), 0600))
	withPuppetYAMLPath(t, path)

	info, err := getPuppetYaml()
	require.NoError(t, err)
	assert.Equal(t, "example.local", info.Host)
	assert.Equal(t, "changed", info.Status)
	assert.Equal(t, "transaction-uuid", info.TransactionUUID)
}

func TestGetPuppetYamlErrors(t *testing.T) {
	withPuppetYAMLPath(t, filepath.Join(t.TempDir(), "missing.yaml"))
	info, err := getPuppetYaml()
	assert.Error(t, err)
	assert.NotNil(t, info)

	path := filepath.Join(t.TempDir(), "last_run_report.yaml")
	require.NoError(t, os.WriteFile(path, []byte(":\n"), 0600))
	withPuppetYAMLPath(t, path)
	info, err = getPuppetYaml()
	assert.Error(t, err)
	assert.NotNil(t, info)
}

func TestGetPuppetFacts(t *testing.T) {
	t.Setenv("PUPPET_PATH", "/tmp/puppet")
	withRunPuppetFactsCmd(t, func(execPath string) ([]byte, error) {
		assert.Equal(t, "/tmp/puppet", execPath)
		return []byte(`{"Name":"example.local","Values":{"uptime":"1 day"}}`), nil
	})

	facts, err := getPuppetFacts()
	require.NoError(t, err)
	assert.Equal(t, "example.local", facts.Name)
	assert.Equal(t, "1 day", facts.Values["uptime"])
}

func TestGetPuppetFactsErrors(t *testing.T) {
	t.Setenv("PUPPET_PATH", "/tmp/puppet")
	withRunPuppetFactsCmd(t, func(execPath string) ([]byte, error) {
		return nil, errors.New("puppet failed")
	})
	facts, err := getPuppetFacts()
	assert.Error(t, err)
	assert.Nil(t, facts)

	withRunPuppetFactsCmd(t, func(execPath string) ([]byte, error) {
		return []byte("not json"), nil
	})
	facts, err = getPuppetFacts()
	assert.Error(t, err)
	assert.Nil(t, facts)
}
