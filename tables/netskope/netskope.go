package netskope

import (
	"context"
	"os"
	"regexp"
	"strings"

	"github.com/macadmins/osquery-extension/pkg/utils"
	"github.com/osquery/osquery-go/plugin/table"
	"github.com/pkg/errors"
)

const nsdiag = "/Library/Application Support/Netskope/STAgent/nsdiag"

var camelSplit = regexp.MustCompile(`([a-z])([A-Z])`)

func NetskopeColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("orgname"),
		table.TextColumn("tenant_url"),
		table.TextColumn("addon_host"),
		table.TextColumn("addon_checker_host"),
		table.TextColumn("gateway"),
		table.TextColumn("gateway_ip"),
		table.TextColumn("config"),
		table.TextColumn("steering_config"),
		table.TextColumn("email"),
		table.TextColumn("peruser_config"),
		table.TextColumn("tunnel_status"),
		table.TextColumn("client_status"),
		table.TextColumn("dynamic_steering"),
		table.TextColumn("on_prem_detection"),
		table.TextColumn("explicit_proxy"),
		table.TextColumn("tunnel_protocol"),
		table.TextColumn("sni_enable"),
		table.TextColumn("traffic_mode"),
	}
}

func NetskopeGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	r := utils.NewRunner()
	fs := utils.OSFileSystem{}
	return runNsdiag(r, fs)
}

func runNsdiag(r utils.Runner, fs utils.FileSystem) ([]map[string]string, error) {
	row := emptyRow()

	_, err := fs.Stat(nsdiag)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []map[string]string{row}, nil
		}
		return nil, errors.Wrap(err, "stat nsdiag binary")
	}

	out, err := r.Runner.RunCmd(nsdiag, "-f")
	if err != nil {
		return nil, errors.Wrap(err, "run nsdiag")
	}
	parsed := parseNsdiagOutput(string(out))

	for col, val := range parsed {
		if _, known := row[col]; known {
			row[col] = val
		}
	}

	return []map[string]string{row}, nil
}

func parseNsdiagOutput(output string) map[string]string {
	result := make(map[string]string)
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "::", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		val = strings.TrimSuffix(val, ".")
		val = strings.TrimSpace(val)
		result[keyToColumn(key)] = val
	}
	return result
}

func keyToColumn(key string) string {
	key = camelSplit.ReplaceAllString(key, "${1}_${2}")
	key = strings.ReplaceAll(key, " ", "_")
	return strings.ToLower(key)
}

func emptyRow() map[string]string {
	row := make(map[string]string)
	for _, col := range NetskopeColumns() {
		row[col.Name] = ""
	}
	return row
}
