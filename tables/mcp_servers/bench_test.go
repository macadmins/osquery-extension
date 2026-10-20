package mcp_servers

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/macadmins/osquery-extension/pkg/devclients"
	"github.com/macadmins/osquery-extension/pkg/fsscan"
	"github.com/macadmins/osquery-extension/pkg/testutil"
)

// BenchmarkDiscoverRecordedProjects times one user's scan with a given number of projects
// recorded in ~/.claude.json, and reports the rows and JSON bytes the scan produces, which is
// what reaches osquery's logger. One project in ten declares two servers in its .mcp.json; one
// in ten has been deleted; the rest exist with no MCP configuration. Run with:
//
//	go test ./tables/mcp_servers/ -run '^$' -bench DiscoverRecordedProjects -benchtime 20x
func BenchmarkDiscoverRecordedProjects(b *testing.B) {
	for _, count := range []int{200, devclients.MaxProjects} {
		b.Run(strconv.Itoa(count)+"_projects", func(b *testing.B) {
			home := b.TempDir()
			entries := make([]string, 0, count)
			for index := range count {
				project := filepath.Join(home, "src", "p"+strconv.Itoa(index))
				entries = append(entries, strconv.Quote(project)+`:{}`)
				switch index % 10 {
				case 0:
					testutil.WriteFile(b, filepath.Join(project, ".mcp.json"),
						`{"mcpServers":{"docs":{"command":"npx","args":["-y","@acme/docs-mcp@1.2.3"]},`+
							`"tickets":{"type":"http","url":"https://mcp.example.com/tickets"}}}`)
				case 1:
					// recorded and since deleted
				default:
					if err := os.MkdirAll(project, 0o755); err != nil {
						b.Fatal(err)
					}
				}
			}
			testutil.WriteFile(b, filepath.Join(home, ".claude.json"),
				`{"projects":{`+strings.Join(entries, ",")+`}}`)
			account := fsscan.UserHome{Name: "alice", Path: home}

			found := discoverForHome(context.Background(), account, time.Now().Add(time.Minute))
			size := 0
			for _, s := range found {
				encoded, err := json.Marshal(serverToRow(s))
				if err != nil {
					b.Fatal(err)
				}
				size += len(encoded)
			}
			b.ResetTimer()
			for range b.N {
				discoverForHome(context.Background(), account, time.Now().Add(time.Minute))
			}
			b.ReportMetric(float64(len(found)), "rows/op")
			b.ReportMetric(float64(size), "json_bytes/op")
		})
	}
}
