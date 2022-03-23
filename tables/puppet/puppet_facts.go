package puppet

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"

	"github.com/osquery/osquery-go/plugin/table"
	"github.com/pkg/errors"
)

type puppetFacts struct {
	Name   string
	Values map[string]interface{}
}

var puppetPath = map[string]string{
	"linux":   "/opt/puppetlabs/bin/puppet",
	"darwin":  "/opt/puppetlabs/bin/puppet",
	"windows": "C:\\\\Program Files\\Puppet Labs\\Puppet\\bin\\puppet.bat",
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
	// check if puppet command exists
	execPath, err := getPuppetExecPath()
	if err != nil {
		return nil, err
	}

	// execute command
	cmd := exec.Command(execPath, "facts", "--render-as", "json")
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

func getPuppetExecPath() (string, error) {
	// if puppet command not in the path, try to use the predefined path
	if execPath, ok := puppetPath[runtime.GOOS]; ok {
		if _, err := os.Stat(execPath); !os.IsNotExist(err) {
			return execPath, nil
		}
	}

	// if user specified PUPPET_PATH env, try to use it
	if execPath := os.Getenv("PUPPET_PATH"); execPath != "" {
		return execPath, nil
	}

	// puppet command not found
	return "", errors.New("puppet command not found.")
}
