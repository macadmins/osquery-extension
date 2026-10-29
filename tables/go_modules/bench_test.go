package go_modules

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/macadmins/osquery-extension/pkg/devclients"
	"github.com/macadmins/osquery-extension/pkg/testutil"
)

// BenchmarkDiscoverRecordedProjects times one user's scan with a given number of recorded
// projects, and reports the rows and JSON bytes the scan produces, which is what reaches
// osquery's logger. The mix follows what a project list holds: one project in ten is a Go
// project, with 20 requirements and 40 go.sum lines; one in ten has been deleted; the rest
// exist and hold neither file. Run with:
//
//	go test ./tables/go_modules/ -run '^$' -bench DiscoverRecordedProjects -benchtime 20x
func BenchmarkDiscoverRecordedProjects(b *testing.B) {
	for _, count := range []int{200, devclients.MaxProjects} {
		b.Run(strconv.Itoa(count)+"_projects", func(b *testing.B) {
			home := filepath.Join(b.TempDir(), "alice")
			projects := make([]string, 0, count)
			for index := range count {
				project := filepath.Join(home, "src", "p"+strconv.Itoa(index))
				projects = append(projects, project)
				switch index % 10 {
				case 0:
					writeBenchGoProject(b, project, index)
				case 1:
					// recorded and since deleted
				default:
					if err := os.MkdirAll(project, 0o755); err != nil {
						b.Fatal(err)
					}
				}
			}
			claudeList(b, home, projects...)
			clienter := roster(map[string]string{"alice": home})
			queryLimits := outputLimits{rows: maxRows, bytes: maxOutputBytes}

			found := discoverWithin(context.Background(), clienter, nil, nil, queryLimits)
			size := 0
			for _, r := range found {
				encoded, err := json.Marshal(publish(r))
				if err != nil {
					b.Fatal(err)
				}
				size += len(encoded)
			}
			b.ResetTimer()
			for range b.N {
				discoverWithin(context.Background(), clienter, nil, nil, queryLimits)
			}
			b.ReportMetric(float64(len(found)), "rows/op")
			b.ReportMetric(float64(size), "json_bytes/op")
		})
	}
}

// writeBenchGoProject writes a go.mod with 20 requirements and a go.sum recording both hashes
// for each.
func writeBenchGoProject(b *testing.B, project string, index int) {
	var mod, sum strings.Builder
	mod.WriteString("module corp.example.com/p" + strconv.Itoa(index) + "\n\ngo 1.25\n\nrequire (\n")
	for dep := range 20 {
		path := "example.com/dep" + strconv.Itoa(dep)
		mod.WriteString("\t" + path + " v1.0." + strconv.Itoa(dep) + "\n")
		sum.WriteString(path + " v1.0." + strconv.Itoa(dep) + " " + validHashField + "\n")
		sum.WriteString(path + " v1.0." + strconv.Itoa(dep) + "/go.mod " + validHashField + "\n")
	}
	mod.WriteString(")\n")
	testutil.WriteFile(b, filepath.Join(project, "go.mod"), mod.String())
	testutil.WriteFile(b, filepath.Join(project, "go.sum"), sum.String())
}
