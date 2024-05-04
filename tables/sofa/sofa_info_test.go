package sofa

import (
	_ "embed"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type MockOsqueryClient struct{}

func (m MockOsqueryClient) QueryRow(query string) (map[string]string, error) {
	return map[string]string{"version": "1.0.0"}, nil
}

func (m MockOsqueryClient) Close() {}

//go:embed test_data.json
var testData []byte

const (
	testCacheFile = "testCache.json"
	testEtagFile  = "testEtag.txt"
	etagValue     = "12345"
)

func setup() *httptest.Server {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Etag", etagValue)
		w.Write(testData) //nolint:errcheck
	})

	server := httptest.NewServer(handler)

	return server
}

func teardown(server *httptest.Server) {
	server.Close()
	removeTestFiles()
}

func removeTestFiles() {
	os.Remove(testCacheFile)
	os.Remove(testEtagFile)
}

// TestDownloadSofaJSON tests the downloadSofaJSON function
func TestDownloadSofaJSON(t *testing.T) {
	server := setup()
	defer teardown(server)

	client, err := NewSofaClient(
		WithURL(server.URL),
		WithLocalCache(testCacheFile, testEtagFile),
	)

	assert.NoError(t, err)

	root, err := client.downloadSofaJSON()
	assert.Equal(t, "2024-04-27T00:48:06+00:00Z", root.LastCheck)
	require.NoError(t, err, "Failed to download JSON")

	etag, err := os.ReadFile(testEtagFile)
	assert.NoError(t, err, "Failed to read etag file")
	require.Equal(t, etagValue, string(etag), "Etag value is not correctly stored")
}

func TestNewSofaClient(t *testing.T) {
	client, err := NewSofaClient()
	assert.NoError(t, err)
	assert.Equal(t, SofaV1URL, client.endpoint)
	assert.NotNil(t, client.httpClient)
}

func TestWithHTTPClient(t *testing.T) {
	client, err := NewSofaClient(WithHTTPClient(&http.Client{}))
	assert.NoError(t, err)
	assert.NotNil(t, client.httpClient)
}

func TestWithEndpoint(t *testing.T) {
	client, err := NewSofaClient(WithURL("http://example.com"))
	assert.NoError(t, err)
	assert.Equal(t, "http://example.com", client.endpoint)
}

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
