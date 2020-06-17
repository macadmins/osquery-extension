package puppet

import (
	"context"

	"github.com/kolide/osquery-go/plugin/table"
)

// PuppetInfo
type PuppetInfo struct {
	CachedCatalogStatus  string `yaml:"cached_catalog_status"`
	CatalogUUID          string `yaml:"catalog_uuid"`
	CodeID               string `yaml:"code_id"`
	ConfigurationVersion string `yaml:"configuration_version"`
	CorrectiveChange     string `yaml:"corrective_change"`
	Environment          string `yaml:"environment"`
	Host                 string `yaml:"host"`
	Kind                 string `yaml:"kind"`
	MasterUsed           string `yaml:"master_used"`
	Noop                 string `yaml:"noop"`
	NoopPending          string `yaml:"noop_pending"`
	PuppetVersion        string `yaml:"puppet_version"`
	ReportFormat         string `yaml:"report_format"`
	Status               string `yaml:"status"`
	Time                 string `yaml:"time"`
	TransactionCompleted string `yaml:"transaction_completed"`
	TransactionUUID      string `yaml:"transaction_uuid"`
	Logs                 []Log
	ResourceStatuses     map[string]ResourceStatus `yaml:"resource_statuses"`
}

func PuppetInfoColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("cached_catalog_status"),
		table.TextColumn("catalog_uuid"),
		table.TextColumn("code_id"),
		table.TextColumn("configuration_version"),
		table.TextColumn("corrective_change"),
		table.TextColumn("environment"),
		table.TextColumn("host"),
		table.TextColumn("kind"),
		table.TextColumn("master_used"),
		table.TextColumn("noop"),
		table.TextColumn("noop_pending"),
		table.TextColumn("puppet_version"),
		table.TextColumn("report_format"),
		table.TextColumn("status"),
		table.TextColumn("time"),
		table.TextColumn("transaction_completed"),
		table.TextColumn("transaction_uuid"),
	}
}

// Generate will be called whenever the table is queried. Since our data in these
// plugins is flat it will return a single row.
func PuppetInfoGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	var results []map[string]string
	runData, err := getPuppetYaml()
	if err != nil {
		return results, err
	}

	results = append(results, map[string]string{
		"cached_catalog_status": runData.CachedCatalogStatus,
		"catalog_uuid":          runData.CatalogUUID,
		"code_id":               runData.CodeID,
		"configuration_version": runData.ConfigurationVersion,
		"corrective_change":     runData.CorrectiveChange,
		"environment":           runData.Environment,
		"host":                  runData.Host,
		"kind":                  runData.Kind,
		"master_used":           runData.MasterUsed,
		"noop":                  runData.Noop,
		"noop_pending":          runData.NoopPending,
		"puppet_version":        runData.PuppetVersion,
		"report_format":         runData.ReportFormat,
		"status":                runData.Status,
		"time":                  runData.Time,
		"transaction_completed": runData.TransactionCompleted,
		"transaction_uuid":      runData.TransactionCompleted,
	})

	return results, nil
}
