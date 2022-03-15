package puppet

import (
	"context"

	"github.com/osquery/osquery-go/plugin/table"
)

type ResourceStatus struct {
	Title            string `yaml:"title"`
	File             string `yaml:"file"`
	Line             string `yaml:"line"`
	Resource         string `yaml:"resource"`
	ResourceType     string `yaml:"resource_type"`
	EvaulationTime   string `yaml:"evaluation_time"`
	Failed           string `yaml:"failed"`
	Changed          string `yaml:"changed"`
	OutOfSync        string `yaml:"out_of_sync"`
	Skipped          string `yaml:"skipped"`
	ChangeCount      string `yaml:"change_count"`
	OutOfSyncCount   string `yaml:"out_of_sync_count"`
	CorrectiveChange string `yaml:"corrective_change"`
}

// PuppetStateColumns returns the type hinted columns for the logged in user.
func PuppetStateColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("title"),
		table.TextColumn("file"),
		table.TextColumn("line"),
		table.TextColumn("resource"),
		table.TextColumn("resource_type"),
		table.TextColumn("evaluation_time"),
		table.TextColumn("failed"),
		table.TextColumn("changed"),
		table.TextColumn("out_of_sync"),
		table.TextColumn("skipped"),
		table.TextColumn("change_count"),
		table.TextColumn("out_of_sync_count"),
		table.TextColumn("corrective_change"),
	}
}

func PuppetStateGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	var results []map[string]string
	runData, err := getPuppetYaml()
	if err != nil {
		return results, err
	}

	for _, item := range runData.ResourceStatuses {
		results = append(results, map[string]string{
			"title":             item.Title,
			"file":              item.File,
			"line":              item.Line,
			"resource":          item.Resource,
			"resource_type":     item.ResourceType,
			"evaluation_time":   item.EvaulationTime,
			"failed":            item.Failed,
			"changed":           item.Changed,
			"out_of_sync":       item.OutOfSync,
			"skipped":           item.Skipped,
			"change_count":      item.ChangeCount,
			"out_of_sync_count": item.OutOfSyncCount,
			"corrective_change": item.CorrectiveChange,
		})
	}

	return results, nil
}
