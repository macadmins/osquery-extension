package puppet

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"

	"github.com/osquery/osquery-go/plugin/table"
	"github.com/pkg/errors"
)

type puppetFacts struct {
	Name   string
	Values map[string]interface{}
}

func PuppetFactsColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("node"),
		table.TextColumn("fact"),
		table.TextColumn("value"),
	}
}

func PuppetFactsGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	var results []map[string]string

	facts, err := getPuppetFacts()
	if err != nil {
		return nil, err
	}

	for factName, factValue := range facts.Values {
		var value string

		// serialize it as json string if it is a map
		if v, ok := factValue.(map[string]interface{}); ok {
			if jsonStr, err := json.Marshal(v); err != nil {
				return nil, errors.Wrap(err, "marshal to json string")
			} else {
				value = string(jsonStr)
			}
		} else {
			// else serialize it as string
			value = fmt.Sprintf("%v", factValue)
		}

		result := map[string]string{
			"node":  facts.Name,
			"fact":  factName,
			"value": value,
		}
		results = append(results, result)
	}

	return results, nil
}

func getPuppetFacts() (*puppetFacts, error) {
	cmd := exec.Command("puppet", "facts", "--render-as", "json")

	out, err := cmd.Output()
	if err != nil {
		return nil, errors.Wrap(err, "calling puppet facts to get puppet facts")
	}

	var facts puppetFacts
	if err := json.Unmarshal(out, &facts); err != nil {
		return nil, errors.Wrap(err, "unmarshal facts output")
	}

	return &facts, nil
}
