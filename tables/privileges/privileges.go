package privileges

import (
	"encoding/json"
	"strings"

	"github.com/macadmins/osquery-extension/pkg/utils"
)

// cliPath is the fixed location of the PrivilegesCLI binary bundled with
// SAP's Privileges.app.
const cliPath = "/Applications/Privileges.app/Contents/MacOS/PrivilegesCLI"

// privilegesEvent models one line of NDJSON emitted by
// `PrivilegesCLI --history --json`.
type privilegesEvent struct {
	ESF struct {
		Process struct {
			CDHash           string `json:"cdhash"`
			PPID             int    `json:"ppid"`
			StartTime        string `json:"start_time"`
			Executable       string `json:"executable"`
			IsPlatformBinary bool   `json:"is_platform_binary"`
			TeamID           string `json:"team_id"`
			IsESClient       bool   `json:"is_es_client"`
			SigningID        string `json:"signing_id"`
			PID              int    `json:"pid"`
		} `json:"process"`
	} `json:"esf"`
	Privileges struct {
		Subject   string `json:"subject"`
		EventType string `json:"event_type"`
		ID        string `json:"id"`
	} `json:"privileges"`
}

func cliInstalled(fs utils.FileSystem) bool {
	info, err := fs.Stat(cliPath)
	if err != nil {
		return false
	}
	// utils.MockFileSystem returns a nil FileInfo for existing files.
	return info == nil || !info.IsDir()
}

func parseEvents(output []byte) []privilegesEvent {
	var events []privilegesEvent
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var event privilegesEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			continue
		}
		events = append(events, event)
	}
	return events
}

func boolToIntString(b bool) string {
	if b {
		return "1"
	}
	return "0"
}
