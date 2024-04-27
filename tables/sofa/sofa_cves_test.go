package sofa

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

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
