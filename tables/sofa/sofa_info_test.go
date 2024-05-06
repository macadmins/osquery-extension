package sofa

import (
	_ "embed"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/macadmins/osquery-extension/pkg/utils"
	"github.com/stretchr/testify/assert"
)

type MockOsqueryClient struct{}

func (m MockOsqueryClient) QueryRow(query string) (map[string]string, error) {
	return map[string]string{"version": "1.0.0"}, nil
}

func (m MockOsqueryClient) Close() {}

//go:embed test_data.json
var testData []byte

//go:embed test_timestamp.json
var testTimestampData []byte

//go:embed test_invalid_hash_data.json
var testInvalidHashData []byte

const (
	testCacheFile        = "testCache.json"
	testInvalidCacheFile = "testInvalidCache.json"
	testTimestampFile    = "testTimestamp.json"
)

func setupTestServer() *httptest.Server {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(testData) //nolint:errcheck
	})

	server := httptest.NewServer(handler)

	return server
}

func setupTestTimestampServer() *httptest.Server {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(testTimestampData) //nolint:errcheck
	})

	server := httptest.NewServer(handler)

	return server
}

func setupInvalidHashServer() *httptest.Server {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(testInvalidHashData) //nolint:errcheck
	})

	server := httptest.NewServer(handler)

	return server
}

func setup() (server *httptest.Server, timestampServer *httptest.Server, invalidHashServer *httptest.Server) {
	server = setupTestServer()
	timestampServer = setupTestTimestampServer()
	invalidHashServer = setupInvalidHashServer()
	return server, timestampServer, invalidHashServer
}

func teardown(server *httptest.Server, timestampServer *httptest.Server, invalidTimestampServer *httptest.Server) {
	server.Close()
	timestampServer.Close()
	invalidTimestampServer.Close()
	removeTestFiles()
}

func removeTestFiles() {
	os.Remove(testCacheFile)
	os.Remove(testTimestampFile)
	os.Remove(testInvalidCacheFile)
}

func TestDownloadFile(t *testing.T) {
	server, timestampServer, invalidCacheServer := setup()
	defer teardown(server, timestampServer, invalidCacheServer)

	client, err := NewSofaClient(
		WithURL(server.URL),
	)

	assert.NoError(t, err)

	// Define a temporary file path for the test
	tempFile := "temp.txt"

	// Call the method under test
	err = client.downloadFile(server.URL, tempFile)

	// Assert that no error occurred
	assert.NoError(t, err)

	// Check that the file was created
	_, err = os.Stat(tempFile)
	assert.NoError(t, err)

	// Clean up the temporary file
	err = os.Remove(tempFile)
	assert.NoError(t, err)
}
func TestUnmarshalJSON(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected time.Time
	}{
		{
			name:     "Valid Time String",
			input:    `"2024-05-06T17:02:57+00:00Z"`,
			expected: time.Date(2024, 5, 6, 17, 2, 57, 0, time.UTC),
		},
		{
			name:     "Empty Time String",
			input:    `""`,
			expected: time.Time{},
		},
		// Add more test cases as needed
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var st SofaTime
			err := json.Unmarshal([]byte(tc.input), &st)
			assert.NoError(t, err)

			actual := time.Time(st)
			t.Logf("Actual value: %v", actual) // Print the actual value for debugging

			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestCacheValid(t *testing.T) {
	server, timestampServer, invalidCacheServer := setup()
	defer teardown(server, timestampServer, invalidCacheServer)
	// Create a temporary file
	tempCacheFile, err := os.CreateTemp("", "test")
	assert.NoError(t, err)
	defer os.Remove(tempCacheFile.Name()) // clean up

	tempTimestampFile, err := os.CreateTemp("", "test")
	assert.NoError(t, err)
	defer os.Remove(tempTimestampFile.Name()) // clean up

	// Create a SofaClient
	client := &SofaClient{
		endpoint:          server.URL,
		timestampEndpoint: timestampServer.URL,
		cacheFile:         tempCacheFile.Name(),
		timestampFile:     tempTimestampFile.Name(),
		httpClient:        http.DefaultClient,
	}

	// Download the data and timestamp files
	err = client.downloadData()
	assert.NoError(t, err)
	err = client.downloadTimestamp()
	assert.NoError(t, err)

	// Call the method under test
	valid, err := client.cacheValid()
	// Assert that no error occurred
	assert.NoError(t, err)

	// Assert that the cache is valid
	assert.True(t, valid)

	// test invalid cache
	client.endpoint = invalidCacheServer.URL
	// Download the data and timestamp files
	err = client.downloadData()
	assert.NoError(t, err)
	err = client.downloadTimestamp()
	assert.NoError(t, err)
	invalid, err := client.cacheValid()
	assert.NoError(t, err)
	assert.False(t, invalid)
}

func TestDownloadData(t *testing.T) {
	server, timestampServer, invalidCacheServer := setup()
	defer teardown(server, timestampServer, invalidCacheServer)

	// Create a SofaClient
	client := &SofaClient{
		endpoint:   server.URL,
		cacheFile:  "tempData.txt",
		httpClient: http.DefaultClient,
	}

	// Call the method under test
	err := client.downloadData()

	// Assert that no error occurred
	assert.NoError(t, err)

	assert.True(t, utils.FileExists(client.cacheFile))

	// Check that the file was created
	_, err = os.Stat(client.cacheFile)
	assert.NoError(t, err)

	// Clean up the temporary file
	// err = os.Remove(client.cacheFile)
	assert.NoError(t, err)
}

func TestDownloadTimestamp(t *testing.T) {
	server, timestampServer, invalidCacheServer := setup()
	defer teardown(server, timestampServer, invalidCacheServer)

	// Create a SofaClient
	client := &SofaClient{
		timestampEndpoint: timestampServer.URL,
		timestampFile:     "tempTimestamp.txt",
		httpClient:        http.DefaultClient,
	}

	// Call the method under test
	err := client.downloadTimestamp()

	// Assert that no error occurred
	assert.NoError(t, err)

	// Check that the file was created
	_, err = os.Stat(client.timestampFile)
	assert.NoError(t, err)

	// Clean up the temporary file
	err = os.Remove(client.timestampFile)
	assert.NoError(t, err)
}

func TestLoadCachedData(t *testing.T) {
	// Create a temporary file
	tempFile, err := os.CreateTemp("", "test")
	assert.NoError(t, err)
	defer os.Remove(tempFile.Name()) // clean up

	var root Root
	_ = json.Unmarshal([]byte(testData), &root)

	err = json.NewEncoder(tempFile).Encode(root)
	assert.NoError(t, err)
	defer tempFile.Close() // nolint:errcheck

	// Create a SofaClient
	client := &SofaClient{
		cacheFile: tempFile.Name(),
	}

	// Call the method under test
	gotRoot, err := client.loadCachedData()

	// Assert that no error occurred and the returned Root matches the expected value
	assert.NoError(t, err)
	assert.Equal(t, root, gotRoot)
}

func TestLoadCachedTimestamp(t *testing.T) {
	// Create a temporary file
	tempFile, err := os.CreateTemp("", "test")
	assert.NoError(t, err)
	defer os.Remove(tempFile.Name()) // clean up

	var timestamp Timestamp
	_ = json.Unmarshal([]byte(testTimestampData), &timestamp)
	err = json.NewEncoder(tempFile).Encode(timestamp)

	assert.NoError(t, err)
	tempFile.Close()

	err = os.WriteFile(tempFile.Name(), testTimestampData, 0644)
	assert.NoError(t, err)

	// Create a SofaClient
	client := &SofaClient{
		timestampFile: tempFile.Name(),
	}

	// Call the method under test
	gotTimestamp, err := client.loadCachedTimestamp()

	// Assert that no error occurred and the returned Timestamp matches the expected value
	assert.NoError(t, err)
	assert.Equal(t, timestamp, gotTimestamp)
}

// TestDownloadSofaJSON tests the downloadSofaJSON function
func TestDownloadSofaJSON(t *testing.T) {
	server, timestampServer, _ := setup()
	// defer teardown(server, timestampServer, invalidCacheServer)

	client, err := NewSofaClient(
		WithURL(server.URL),
		WithTimestampURL(timestampServer.URL),
		WithLocalCache(testCacheFile, testTimestampFile),
	)

	assert.NoError(t, err)

	root, err := client.downloadSofaJSON()
	assert.NoError(t, err, "Failed to download JSON")
	assert.Equal(t, "537e88f3ce31946dbc771542e3323d78b8e1f2fb84536162e5e14f695adde7fb", root.UpdateHash)

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
