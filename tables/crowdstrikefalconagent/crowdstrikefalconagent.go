package crowdstrikefalconagent

import (
	"context"
	"fmt"
	"os"
	"os/exec"

	"github.com/groob/plist"
	"github.com/kolide/osquery-go/plugin/table"
)

const (
	_FALCONCTL             = "/Applications/Falcon.app/Contents/Resources/falconctl"
	_AGENTID               = "agentID"
	_CUSTOMERID            = "customerID"
	_SENOR_OPERATIONAL     = "sensor_operational"
	_VERSION               = "version"
	_BW_FILTER_CALLED      = "bw_filter_called"
	_BW_FILTER_FALSE       = "bw_filter_false"
	_BW_FILTER_SATISFIED   = "bw_filter_satisfied"
	_BW_FILTER_TIMEOUTS    = "bw_filter_timeouts"
	_BW_FILTER_TRUE        = "bw_filter_true"
	_BW_LATERESPONSE       = "bw_lateresponse"
	_BW_RECEIVER_CALLED    = "bw_receiver_called"
	_BW_RECEIVER_SATISFIED = "bw_receiver_satisfied"
	_DC_ENABLED            = "dc_enabled"
	_DC_FSAUTH             = "dc_fsauth"
	_DC_RULECOUNT          = "dc_rulecount"
	_ES_AUTH               = "es_auth"
	_ES_NOTIFY             = "es_notify"
	_SA_AVG                = "sa_avg"
	_SA_MAX                = "sa_max"
	_SA_READY              = "sa_ready"
	_SA_REQUESTS           = "sa_requests"
	_SA_SUCCESSES          = "sa_successes"
)

type TopLevel struct {
	AgentInfo        AgentInfo        `plist:"agent_info"`
	DeviceControl    DeviceControl    `plist:"device_control"`
	EndpointSecurity EndpointSecurity `plist:"EndpointSecurity"`
	StaticAnalysis   StaticAnalysis   `plist:"StaticAnalysis"`
	BlockWait        BlockWait        `plist:"block_wait"`
}

type AgentInfo struct {
	AgentID           string `plist:"agentID"`
	CustomerID        string `plist:"customerID"`
	SensorOperational string `plist:"sensor_operational"`
	Version           string `plist:"version"`
}

type DeviceControl struct {
	Enabled   int `plist:"enabled"`
	FSAuth    int `plist:"fs_auth"`
	RuleCount int `plist:"rule_count"`
}

type EndpointSecurity struct {
	Auth   int `plist:"auth"`
	Notify int `plist:"notify"`
}

type StaticAnalysis struct {
	AVG       int  `plist:"avg"`
	Max       int  `plist:"max"`
	Ready     bool `plist:"ready"`
	Requests  int  `plist:"requests"`
	Successes int  `plist:"successes"`
}

type BlockWait struct {
	FilterCalled      int `plist:"filter_called"`
	FilterFalse       int `plist:"filter_false"`
	FilterSatisfied   int `plist:"filter_satisfied"`
	FilterTimeouts    int `plist:"filter_timeouts"`
	FilterTrue        int `plist:"filter_true"`
	LateResponse      int `plist:"late_response"`
	ReceiverCalled    int `plist:"receiver_called"`
	ReceiverSatisfied int `plist:"receiver_satisfied"`
}

func InfoColums() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn(_AGENTID),
		table.TextColumn(_CUSTOMERID),
		table.TextColumn(_SENOR_OPERATIONAL),
		table.TextColumn(_VERSION),
		table.BigIntColumn(_DC_ENABLED),
		table.BigIntColumn(_DC_FSAUTH),
		table.BigIntColumn(_DC_RULECOUNT),
		table.BigIntColumn(_ES_AUTH),
		table.BigIntColumn(_ES_NOTIFY),
		table.BigIntColumn(_SA_AVG),
		table.BigIntColumn(_SA_MAX),
		table.BigIntColumn(_SA_READY),
		table.BigIntColumn(_SA_REQUESTS),
		table.BigIntColumn(_SA_SUCCESSES),
		table.BigIntColumn(_BW_FILTER_CALLED),
		table.BigIntColumn(_BW_FILTER_FALSE),
		table.BigIntColumn(_BW_FILTER_SATISFIED),
		table.BigIntColumn(_BW_FILTER_TIMEOUTS),
		table.BigIntColumn(_BW_FILTER_TRUE),
		table.BigIntColumn(_BW_LATERESPONSE),
		table.BigIntColumn(_BW_RECEIVER_CALLED),
		table.BigIntColumn(_BW_RECEIVER_SATISFIED),
	}
}

func InfoGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {

	err := checkFalconCtl(_FALCONCTL)
	if err != nil {
		return prepareError("not_found")
	}

	stats, err := getStatsOutputPlist(_FALCONCTL)
	if err != nil {
		return prepareError("not_loaded")
	}

	parsed, err := parseRead(stats)
	if err != nil {
		return prepareError("parse_error")
	}

	return prepareResults(parsed)
}

func prepareError(reason string) ([]map[string]string, error) {
	out := make(map[string]string)

	out[_SENOR_OPERATIONAL] = reason

	return []map[string]string{
		out,
	}, nil
}

func prepareResults(in *TopLevel) ([]map[string]string, error) {
	result := map[string]string{
		_AGENTID:               in.AgentInfo.AgentID,
		_CUSTOMERID:            in.AgentInfo.CustomerID,
		_SENOR_OPERATIONAL:     in.AgentInfo.SensorOperational,
		_VERSION:               in.AgentInfo.Version,
		_DC_ENABLED:            fmt.Sprintf("%v", in.DeviceControl.Enabled),
		_DC_FSAUTH:             fmt.Sprintf("%v", in.DeviceControl.FSAuth),
		_DC_RULECOUNT:          fmt.Sprintf("%v", in.DeviceControl.RuleCount),
		_ES_AUTH:               fmt.Sprintf("%v", in.EndpointSecurity.Auth),
		_ES_NOTIFY:             fmt.Sprintf("%v", in.EndpointSecurity.Notify),
		_SA_AVG:                fmt.Sprintf("%v", in.StaticAnalysis.AVG),
		_SA_MAX:                fmt.Sprintf("%v", in.StaticAnalysis.Max),
		_SA_READY:              fmt.Sprintf("%v", in.StaticAnalysis.Ready),
		_SA_REQUESTS:           fmt.Sprintf("%v", in.StaticAnalysis.Requests),
		_SA_SUCCESSES:          fmt.Sprintf("%v", in.StaticAnalysis.Successes),
		_BW_FILTER_CALLED:      fmt.Sprintf("%v", in.BlockWait.FilterCalled),
		_BW_FILTER_FALSE:       fmt.Sprintf("%v", in.BlockWait.FilterFalse),
		_BW_FILTER_SATISFIED:   fmt.Sprintf("%v", in.BlockWait.FilterSatisfied),
		_BW_FILTER_TIMEOUTS:    fmt.Sprintf("%v", in.BlockWait.FilterTimeouts),
		_BW_FILTER_TRUE:        fmt.Sprintf("%v", in.BlockWait.FilterTrue),
		_BW_LATERESPONSE:       fmt.Sprintf("%v", in.BlockWait.LateResponse),
		_BW_RECEIVER_CALLED:    fmt.Sprintf("%v", in.BlockWait.ReceiverCalled),
		_BW_RECEIVER_SATISFIED: fmt.Sprintf("%v", in.BlockWait.ReceiverSatisfied),
	}

	return []map[string]string{
		result,
	}, nil
}

func parseRead(in []byte) (*TopLevel, error) {

	var out TopLevel
	err := plist.Unmarshal(in, &out)
	if err != nil {
		return nil, err
	}

	return &out, err
}

func checkFalconCtl(path string) (err error) {
	_, err = os.Stat(path)
	return
}

func getStatsOutputPlist(path string) ([]byte, error) {
	cmd := exec.Command(path, "stats", "--plist")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	return out, nil
}
