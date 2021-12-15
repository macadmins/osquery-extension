package networkquality

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"

	"github.com/kolide/osquery-go/plugin/table"
	"github.com/pkg/errors"
)

type NetworkQualityOutput struct {
	DlFlows                   int       `json:"dl_flows"`
	DlThroughput              int       `json:"dl_throughput"`
	LudForeignH2ReqResp       []int     `json:"lud_foreign_h2_req_resp"`
	LudForeignTCPHandshake443 []int     `json:"lud_foreign_tcp_handshake_443"`
	LudSelfDlH2               []float64 `json:"lud_self_dl_h2"`
	LudSelfUlH2               []float64 `json:"lud_self_ul_h2"`
	Responsiveness            int       `json:"responsiveness"`
	UlFlows                   int       `json:"ul_flows"`
	UlThroughput              int       `json:"ul_throughput"`
}

func NetworkQualityColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.IntegerColumn("dl_throughput_kbps"),
		table.IntegerColumn("ul_throughput_kbps"),
		table.TextColumn("dl_throughput_mbps"),
		table.TextColumn("ul_throughput_mbps"),
	}
}

// Generate will be called whenever the table is queried. Since our data in these
// results is flat it will return a single row.
func NetworkQualityGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	var results []map[string]string
	output, err := runNetworkQuality()
	if err != nil {
		fmt.Println(err)
		return results, err
	}

	results = append(results, map[string]string{
		"dl_throughput_kbps": strconv.Itoa(output.DlThroughput),
		"ul_throughput_kbps": strconv.Itoa(output.UlThroughput),
		"dl_throughput_mbps": fmt.Sprintf("%.2f", float64(output.DlThroughput)/1000000),
		"ul_throughput_mbps": fmt.Sprintf("%.2f", float64(output.UlThroughput)/1000000),
	})

	return results, nil
}

func runNetworkQuality() (NetworkQualityOutput, error) {
	var output NetworkQualityOutput

	// Just return if the binary isn't present
	_, err := os.Stat("/usr/bin/networkQuality")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return output, nil
		}
		return output, err
	}

	out, err := exec.Command("/usr/bin/networkQuality", "-c").Output()

	if err != nil {
		return output, errors.Wrap(err, "networkQuality -c")
	}
	if err := json.Unmarshal(out, &output); err != nil {
		return output, errors.Wrap(err, "unmarshalling networkQuality output")
	}

	return output, nil

}

func Exists(name string) (bool, error) {
	_, err := os.Stat(name)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}
