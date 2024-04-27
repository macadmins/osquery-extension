package sofa

import (
	_ "embed"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

type MockOsqueryClient struct{}

func (m MockOsqueryClient) QueryRow(query string) (map[string]string, error) {
	return map[string]string{"version": "1.0.0"}, nil
}

func (m MockOsqueryClient) Close() {}

//go:embed test_data.json
var testData []byte

func TestDownloadSofaJSON(t *testing.T) {
	// start a local HTTP server to serve the test data
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(testData) //nolint:errcheck
	}))

	client := NewSofaClient(WithURL(server.URL))
	root, err := client.downloadSofaJSON()
	assert.NoError(t, err)
	assert.Equal(t, "2024-04-27T00:48:06+00:00Z", root.LastCheck)

}

func TestNewSofaClient(t *testing.T) {
	client := NewSofaClient()
	assert.Equal(t, SofaV1URL, client.endpoint)
	assert.NotNil(t, client.httpClient)
}

func TestWithHTTPClient(t *testing.T) {
	client := NewSofaClient(WithHTTPClient(&http.Client{}))
	assert.NotNil(t, client.httpClient)
}

func TestWithEndpoint(t *testing.T) {
	client := NewSofaClient(WithURL("http://example.com"))
	assert.Equal(t, "http://example.com", client.endpoint)
}

func TestGetSecurityReleaseInfoForCurrentOSVersion(t *testing.T) {
	tests := []struct {
		name        string
		root        Root
		osVersion   string
		wantVersion string
		wantErr     bool
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
			osVersion:   "10.0",
			wantVersion: "10.0",
			wantErr:     false,
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getSecurityReleaseInfoForCurrentOSVersion(tt.root, tt.osVersion)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantVersion, got.ProductVersion)
			}
		})
	}
}

func TestGetCurrentOSVersion(t *testing.T) {
	mockClient := MockOsqueryClient{}
	version, err := getCurrentOSVersion(mockClient)
	assert.NoError(t, err)
	assert.Equal(t, "1.0.0", version)
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
