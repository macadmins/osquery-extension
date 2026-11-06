package sofa

import (
	_ "embed"
	"errors"
	"testing"

	"github.com/macadmins/osquery-extension/pkg/utils"
	"github.com/osquery/osquery-go/plugin/table"
	"github.com/stretchr/testify/assert"
)

func TestGetSecurityReleaseInfoForOSVersion(t *testing.T) {
	tests := []struct {
		name         string
		root         Root
		osVersion    string
		wantVersions []string
		wantErr      bool
	}{
		{
			name: "security release info found",
			root: Root{
				OSVersions: []OSVersion{
					{
						SecurityReleases: []SecurityRelease{
							{
								ProductVersion: "10.0",
							},
						},
					},
				},
			},
			osVersion:    "9.0",
			wantVersions: []string{"10.0"},
			wantErr:      false,
		},
		{
			name: "security release info not found",
			root: Root{
				OSVersions: []OSVersion{
					{
						SecurityReleases: []SecurityRelease{
							{
								ProductVersion: "10.0",
							},
						},
					},
				},
			},
			osVersion: "11.0",
			wantErr:   true,
		},
		{
			name:      "invalid os version",
			root:      Root{},
			osVersion: "not-a-version",
			wantErr:   true,
		},
		{
			name: "invalid product version",
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
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getSecurityReleaseInfoForOSVersion(tt.root, tt.osVersion)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				gotVersions := make([]string, len(got))
				for i, release := range got {
					gotVersions[i] = release.ProductVersion
				}
				assert.Equal(t, tt.wantVersions, gotVersions)
			}
		})
	}
}

func TestSofaSecurityReleaseInfoColumns(t *testing.T) {
	assert.Equal(t, []table.ColumnDefinition{
		table.TextColumn("update_name"),
		table.TextColumn("product_version"),
		table.TextColumn("release_date"),
		table.TextColumn("security_info"),
		table.IntegerColumn("unique_cves_count"),
		table.IntegerColumn("days_since_previous_release"),
		table.TextColumn("os_version", table.AdditionalColumn()),
		table.TextColumn("url", table.AdditionalColumn()),
	}, SofaSecurityReleaseInfoColumns())
}

func TestGetCurrentOSVersion(t *testing.T) {
	mockClient := &utils.MockOsqueryClient{
		Data: map[string][]map[string]string{
			"SELECT * FROM os_version;": {{"version": "1.0.0"}},
		},
	}
	version, err := getCurrentOSVersion(mockClient)
	assert.NoError(t, err)
	assert.Equal(t, "1.0.0", version)
}

func TestGetCurrentOSVersionQueryError(t *testing.T) {
	_, err := getCurrentOSVersion(utils.ErrorOsqueryClient{Err: errors.New("query failed")})
	assert.Error(t, err)
	assert.ErrorContains(t, err, "query failed")
}

func TestGetVersionFromResponse(t *testing.T) {
	tt := []struct {
		name           string
		input          map[string]string
		expectedResult string
		expectedError  bool
	}{
		{"Version exists", map[string]string{"version": "1.0.0"}, "1.0.0", false},
		{"Version does not exist", map[string]string{"no_version": "1.0.0"}, "", true},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			result, err := getVersionFromResponse(tc.input)
			if tc.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tc.expectedResult, result)
		})
	}
}

func TestProcessContextConstraints(t *testing.T) {
	queryContext := table.QueryContext{
		Constraints: map[string]table.ConstraintList{
			"url": {
				Constraints: []table.Constraint{
					{
						Operator:   table.OperatorEquals,
						Expression: "http://testurl.com",
					},
				},
			},
			"os_version": {
				Constraints: []table.Constraint{
					{
						Operator:   table.OperatorEquals,
						Expression: "14.5.1",
					},
				},
			},
		},
	}

	url, osVersion := processContextConstraints(queryContext)

	assert.Equal(t, "http://testurl.com", url)
	assert.Equal(t, "14.5.1", osVersion)
}

func TestProcessContextConstraintsDefaultsAndIgnoresNonEquals(t *testing.T) {
	url, osVersion := processContextConstraints(table.QueryContext{})
	assert.Equal(t, SofaV1URL, url)
	assert.Empty(t, osVersion)

	url, osVersion = processContextConstraints(table.QueryContext{
		Constraints: map[string]table.ConstraintList{
			"url": {Constraints: []table.Constraint{{
				Operator:   table.OperatorLike,
				Expression: "ignored",
			}}},
			"os_version": {Constraints: []table.Constraint{{
				Operator:   table.OperatorGreaterThan,
				Expression: "14",
			}}},
		},
	})
	assert.Equal(t, SofaV1URL, url)
	assert.Empty(t, osVersion)
}

func TestBuildSecurityReleaseInfoOutput(t *testing.T) {
	securityReleases := []SecurityRelease{
		{
			UpdateName:               "Update Name",
			ProductVersion:           "14.5.1",
			ReleaseDate:              "2024-07-01",
			SecurityInfo:             "Available for: macOS Sonoma",
			UniqueCVEsCount:          3,
			DaysSincePreviousRelease: 30,
		},
	}

	osVersion := "14.5.1"

	expectedOutput := []map[string]string{
		{
			"update_name":                 "Update Name",
			"product_version":             "14.5.1",
			"release_date":                "2024-07-01",
			"security_info":               "Available for: macOS Sonoma",
			"unique_cves_count":           "3",
			"days_since_previous_release": "30",
			"os_version":                  "14.5.1",
			"url":                         SofaV1URL,
		},
	}

	output := buildSecurityReleaseInfoOutput(securityReleases, osVersion, SofaV1URL)

	assert.Equal(t, expectedOutput, output)
}

// TestQueriesAskOsqueryThroughTheClienter: with no os_version in the query, both tables ask
// osquery for this host's version through the clienter they are given, and report a client that
// cannot be opened.
func TestQueriesAskOsqueryThroughTheClienter(t *testing.T) {
	server := setup()
	defer teardown(server)
	queryContext := table.QueryContext{Constraints: map[string]table.ConstraintList{
		"url": {Constraints: []table.Constraint{{Operator: table.OperatorEquals, Expression: server.URL}}},
	}}
	clienter := &utils.MockOsqueryClienter{Data: map[string][]map[string]string{
		"SELECT * FROM os_version;": {{"version": "14.4.1"}},
	}}
	options := []Option{WithCacheDir(t.TempDir()), WithUserAgent("test")}

	rows, err := securityReleaseInfo(queryContext, clienter, options...)
	assert.NoError(t, err)
	assert.NotEmpty(t, rows)
	assert.Equal(t, "14.4.1", rows[0]["os_version"])
	_, err = unpatchedCVEs(queryContext, clienter, options...)
	assert.NoError(t, err)

	failing := &utils.MockOsqueryClienter{Err: errors.New("no socket")}
	_, err = securityReleaseInfo(queryContext, failing, options...)
	assert.Error(t, err)
	_, err = unpatchedCVEs(queryContext, failing, options...)
	assert.Error(t, err)
}
