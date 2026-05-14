package sofa

import (
	"testing"

	"github.com/osquery/osquery-go/plugin/table"
	"github.com/stretchr/testify/assert"
)

func TestSofaUnpatchedCVEsColumns(t *testing.T) {
	assert.Equal(t, []table.ColumnDefinition{
		table.TextColumn("os_version"),
		table.TextColumn("cve"),
		table.TextColumn("patched_version"),
		table.TextColumn("actively_exploited"),
		table.TextColumn("url"),
	}, SofaUnpatchedCVEsColumns())
}

func TestGetUnpatchedCVEs(t *testing.T) {
	tests := []struct {
		name      string
		root      Root
		osVersion string
		wantCVEs  []UnpatchedCVE
		wantErr   bool
	}{
		{
			name: "unpatched CVEs found",
			root: Root{
				OSVersions: []OSVersion{
					{
						SecurityReleases: []SecurityRelease{
							{
								ProductVersion: "10.1",
								CVEs: map[string]bool{
									"CVE-1234": true,
								},
							},
						},
					},
				},
			},
			osVersion: "10.0",
			wantCVEs: []UnpatchedCVE{
				{
					CVE:               "CVE-1234",
					PatchedVersion:    "10.1",
					ActivelyExploited: true,
				},
			},
			wantErr: false,
		},
		{
			name: "no unpatched CVEs found",
			root: Root{
				OSVersions: []OSVersion{
					{
						SecurityReleases: []SecurityRelease{
							{
								ProductVersion: "10.0",
								CVEs: map[string]bool{
									"CVE-1234": true,
								},
							},
						},
					},
				},
			},
			osVersion: "10.0",
			wantCVEs:  []UnpatchedCVE{},
			wantErr:   false,
		},
		{
			name:      "invalid current version",
			root:      Root{},
			osVersion: "not-a-version",
			wantCVEs:  []UnpatchedCVE{},
			wantErr:   true,
		},
		{
			name: "invalid patched version",
			root: Root{
				OSVersions: []OSVersion{
					{
						SecurityReleases: []SecurityRelease{
							{
								ProductVersion: "not-a-version",
							},
						},
					},
				},
			},
			osVersion: "14.0",
			wantCVEs:  []UnpatchedCVE{},
			wantErr:   true,
		},
		{
			name: "different major version ignored",
			root: Root{
				OSVersions: []OSVersion{
					{
						SecurityReleases: []SecurityRelease{
							{
								ProductVersion: "15.0",
								CVEs:           map[string]bool{"CVE-9999": true},
							},
						},
					},
				},
			},
			osVersion: "14.6",
			wantCVEs:  []UnpatchedCVE{},
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getUnpatchedCVEs(tt.root, tt.osVersion)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantCVEs, got)
			}
		})
	}
}
