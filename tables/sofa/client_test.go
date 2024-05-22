package sofa

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	_ "embed"

	"github.com/macadmins/osquery-extension/pkg/utils"
	"github.com/stretchr/testify/assert"
)

//go:embed test_data.json
var testData []byte

//go:embed test_etag.txt
var testEtag []byte

const (
	testCacheFile = "testCache.json"
	testEtagFile  = "testetag.txt"
)

func setupTestServer() *httptest.Server {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		etag := `W/"123456789"`
		w.Header().Set("ETag", etag)
		w.Write(testData) //nolint:errcheck
	})

	server := httptest.NewServer(handler)

	return server
}

func setup() (server *httptest.Server) {
	server = setupTestServer()
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

func TestDownloadFile(t *testing.T) {
	server := setup()
	defer teardown(server)

	cwd, err := os.Getwd()
	assert.NoError(t, err)

	client, err := NewSofaClient(
		WithURL(server.URL),
		WithCacheDir(cwd),
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

func TestLoacCachedEtag(t *testing.T) {
	// Create a temporary file
	tempEtagFile, err := os.CreateTemp("", "test")
	assert.NoError(t, err)
	defer os.Remove(tempEtagFile.Name()) // clean up

	// Write the etag to the etag file
	err = os.WriteFile(tempEtagFile.Name(), testEtag, 0644)
	assert.NoError(t, err)

	// Create a SofaClient
	client := &SofaClient{
		etagFile: tempEtagFile.Name(),
	}

	// Call the method under test
	etag, err := client.loadCachedEtag()
	assert.NoError(t, err)

	// Assert that the etag was loaded correctly
	assert.Equal(t, "W/\"123456789\"", etag)
}

func TestGetEtag(t *testing.T) {
	server := setup()
	defer teardown(server)

	// Create a SofaClient
	client := &SofaClient{
		endpoint:   server.URL,
		httpClient: http.DefaultClient,
	}

	// Call the method under test
	etag, err := client.getEtag()
	assert.NoError(t, err)

	// Assert that the etag was returned correctly
	assert.Equal(t, "W/\"123456789\"", etag)
}

func TestSaveEtag(t *testing.T) {
	// Create a temporary file
	tempEtagFile, err := os.CreateTemp("", "test")
	assert.NoError(t, err)
	defer os.Remove(tempEtagFile.Name()) // clean up

	// Create a SofaClient
	client := &SofaClient{
		etagFile:   tempEtagFile.Name(),
		remoteEtag: "W/\"123456789\"",
		httpClient: http.DefaultClient,
	}

	// Call the method under test
	err = client.saveEtag()
	assert.NoError(t, err)

	// Read the etag file
	etagData, err := os.ReadFile(client.etagFile)
	assert.NoError(t, err)

	// Assert that the etag was saved correctly
	assert.Equal(t, "W/\"123456789\"", string(etagData))
}

func TestLoadCachedData(t *testing.T) {
	// Create a temporary file
	tempCacheFile, err := os.CreateTemp("", "test")
	assert.NoError(t, err)
	defer os.Remove(tempCacheFile.Name()) // clean up

	// Write the data to the cache file
	err = os.WriteFile(tempCacheFile.Name(), testData, 0644)
	assert.NoError(t, err)

	// Create a SofaClient
	client := &SofaClient{
		cacheFile: tempCacheFile.Name(),
	}

	var expectedRoot Root
	err = json.Unmarshal(testData, &expectedRoot)
	assert.NoError(t, err)

	// Call the method under test
	data, err := client.loadCachedData()
	assert.NoError(t, err)

	// Assert that the data was loaded correctly
	assert.Equal(t, expectedRoot, data)
}

func TestCacheValid(t *testing.T) {
	server := setup()
	defer teardown(server)
	// Create a temporary file
	tempCacheFile, err := os.CreateTemp("", "test")
	assert.NoError(t, err)
	defer os.Remove(tempCacheFile.Name()) // clean up

	tempEtagFile, err := os.CreateTemp("", "test")
	assert.NoError(t, err)
	defer os.Remove(tempEtagFile.Name()) // clean up

	// Create a SofaClient
	client := &SofaClient{
		endpoint:   server.URL,
		cacheFile:  tempCacheFile.Name(),
		etagFile:   tempEtagFile.Name(),
		httpClient: http.DefaultClient,
	}

	// Download the data files
	err = client.downloadData()
	assert.NoError(t, err)

	// Write the etag to the etag file
	err = os.WriteFile(client.etagFile, testEtag, 0644)
	assert.NoError(t, err)

	// Call the method under test
	valid, err := client.cacheValid()
	// Assert that no error occurred
	assert.NoError(t, err)

	// Assert that the cache is valid
	assert.True(t, valid)

}

func TestDownloadData(t *testing.T) {
	server := setup()
	defer teardown(server)

	cwd, err := os.Getwd()
	assert.NoError(t, err)

	// Create a SofaClient
	client := &SofaClient{
		endpoint:   server.URL,
		httpClient: http.DefaultClient,
		cacheDir:   cwd,
	}

	err = client.createCacheDir()
	assert.NoError(t, err)

	client.setCachePaths()

	// Call the method under test
	err = client.downloadData()

	// Assert that no error occurred
	assert.NoError(t, err)

	assert.True(t, utils.FileExists(client.cacheFile))

	// Check that the file was created
	_, err = os.Stat(client.cacheFile)
	assert.NoError(t, err)

	// Clean up the temporary file
	err = os.Remove(client.cacheFile)
	assert.NoError(t, err)
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

func TestSetCachePaths(t *testing.T) {
	client, err := NewSofaClient()
	assert.NoError(t, err)

	client.setCachePaths()

	assert.NotEmpty(t, client.cacheFile)
	assert.NotEmpty(t, client.etagFile)
}

func TestCachePath(t *testing.T) {
	client, err := NewSofaClient()
	assert.NoError(t, err)

	client.setCachePaths()

	assert.NotEmpty(t, client.cachePath("test"))
}

func TestEtagPath(t *testing.T) {
	client, err := NewSofaClient()
	assert.NoError(t, err)

	client.setCachePaths()

	assert.NotEmpty(t, client.etagPath("test"))
}

func TestCreateCacheDir(t *testing.T) {
	client, err := NewSofaClient()
	assert.NoError(t, err)

	err = client.createCacheDir()
	assert.NoError(t, err)

	assert.DirExists(t, client.cacheDir)
}
