package puppet

import (
	"context"

	"github.com/osquery/osquery-go/plugin/table"
)

type Log struct {
	Level   string `yaml:"level"`
	Message string `yaml:"message"`
	Source  string `yaml:"source"`
	Time    string `yaml:"time"`
	File    string `yaml:"file"`
	Line    string `yaml:"line"`
}

// Columns returns the type hinted columns for the logged in user.
func PuppetLogsColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("level"),
		table.TextColumn("message"),
		table.TextColumn("source"),
		table.TextColumn("time"),
		table.TextColumn("file"),
		table.TextColumn("line"),
	}
}

// Generate will be called whenever the table is queried. Since our data in these
// plugins is flat it will return a single row.
func PuppetLogsGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	var results []map[string]string
	runData, err := getPuppetYaml()
	if err != nil {
		return results, err
	}

	for _, item := range runData.Logs {
		results = append(results, map[string]string{
			"level":   item.Level,
			"message": item.Message,
			"source":  item.Source,
			"time":    item.Time,
			"file":    item.File,
			"line":    item.Line,
		})
	}

	return results, nil
}
