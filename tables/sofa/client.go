package sofa

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	"github.com/macadmins/osquery-extension/pkg/utils"
)

const SofaV1URL = "https://sofa.macadmins.io/v1/macos_data_feed.json"

const UserAgent = "macadmins-osquery-extension/1.0.2" // Todo: get the version during build

type SofaClient struct {
	endpoint   string
	httpClient *http.Client
	localEtag  string
	remoteEtag string
	cacheFile  string
	cacheDir   string
	etagFile   string
	userAgent  string
}

type SofaTime time.Time

func (t SofaTime) String() string {
	return time.Time(t).String()
}

func (t SofaTime) MarshalJSON() ([]byte, error) {
	return []byte(`"` + time.Time(t).UTC().Format("2006-01-02T15:04:05Z") + `"`), nil
}

func (t *SofaTime) UnmarshalJSON(b []byte) (err error) {
	s := strings.Trim(string(b), "\"")
	// Remove trailing 'Z' to handle fixed timezone offset
	s = strings.TrimSuffix(s, "Z")

	if s == "" {
		return nil // Handle empty time string
	}

	// Manually parse the time string with timezone offset
	parsedTime, err := time.Parse("2006-01-02T15:04:05-07:00", s)
	if err != nil {
		return err
	}
	*t = SofaTime(parsedTime.UTC())
	return nil
}

func WithLocalCache(cacheFile, etagFile string) Option {
	return func(s *SofaClient) {
		s.cacheFile = cacheFile
		s.etagFile = etagFile
	}
}

func WithUserAgent(userAgent string) Option {
	return func(s *SofaClient) {
		s.userAgent = userAgent
	}
}

func WithCacheDir(cacheDir string) Option {
	return func(s *SofaClient) {
		s.cacheDir = cacheDir
	}
}

func WithURL(url string) Option {
	return func(s *SofaClient) {
		s.endpoint = url
	}
}

func WithHTTPClient(client *http.Client) Option {
	return func(s *SofaClient) {
		s.httpClient = client
	}
}

func NewSofaClient(opts ...Option) (*SofaClient, error) {

	s := &SofaClient{
		endpoint: SofaV1URL,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		cacheDir:  "/private/tmp/sofa",
		userAgent: UserAgent,
	}

	for _, opt := range opts {
		opt(s)
	}

	err := s.createCacheDir()
	if err != nil {
		return nil, err
	}

	s.setCachePaths()

	return s, nil
}

func (s *SofaClient) setCachePaths() {
	if s.etagFile == "" {
		s.etagFile = s.etagPath("macos_data_feed.json.json")
	}

	if s.cacheFile == "" {
		s.cacheFile = s.cachePath("macos_data_feed_etag.txt")
	}
}

func (s *SofaClient) cachePath(fileName string) string {
	return path.Join(s.cacheDir, fileName)
}

func (s *SofaClient) etagPath(fileName string) string {
	return path.Join(s.cacheDir, fileName)
}

func (s *SofaClient) createCacheDir() error {

	err := os.MkdirAll(s.cacheDir, 0755)
	if err != nil {
		return err
	}
	return nil
}

func (s *SofaClient) cacheValid() (bool, error) {
	if !utils.FileExists(s.cacheFile) {
		return false, nil
	}

	remoteEtag, err := s.getEtag()
	if err != nil {
		return false, err
	}

	localEtag, err := s.loadCachedEtag()
	if err != nil {
		return false, err
	}

	s.localEtag = localEtag
	s.remoteEtag = remoteEtag

	err = s.saveEtag()
	if err != nil {
		return false, err
	}

	if s.localEtag == s.remoteEtag {
		return true, nil
	}

	return false, nil
}

func (s *SofaClient) loadCachedData() (Root, error) {

	jsonData, err := os.ReadFile(s.cacheFile)
	if err != nil {
		return Root{}, err
	}

	var root Root
	if err := json.Unmarshal(jsonData, &root); err != nil {
		return Root{}, err
	}

	return root, nil

}

func (s *SofaClient) downloadData() error {
	return s.downloadFile(s.endpoint, s.cacheFile)
}

func (s *SofaClient) loadCachedEtag() (string, error) {
	if !utils.FileExists(s.etagFile) {
		return "", nil
	}

	etagData, err := os.ReadFile(s.etagFile)
	if err != nil {
		return "", err
	}

	return string(etagData), nil
}

func (s *SofaClient) getEtag() (string, error) {
	req, err := http.NewRequest("HEAD", s.endpoint, http.NoBody)
	if err != nil {
		return "", err
	}

	req.Header.Set("User-Agent", s.userAgent)
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close() // nolint: errcheck

	etag := resp.Header.Get("ETag")
	if etag == "" {
		return "", errors.New("etag not found in response")
	}

	return etag, nil
}

func (s *SofaClient) saveEtag() error {
	return os.WriteFile(s.etagFile, []byte(s.remoteEtag), 0644)
}

func (s *SofaClient) downloadFile(url, path string) error {
	req, err := http.NewRequest("GET", url, http.NoBody)
	if err != nil {
		return err
	}

	req.Header.Set("User-Agent", s.userAgent)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close() // nolint: errcheck

	file, err := os.Create(path)
	if err != nil {
		return err
	}

	defer file.Close() // nolint: errcheck
	_, err = io.Copy(file, resp.Body)
	if err != nil {
		return err
	}

	etag := resp.Header.Get("ETag")
	if etag != "" {
		s.remoteEtag = etag
		err = s.saveEtag()
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *SofaClient) downloadSofaJSON() (Root, error) {
	valid, err := s.cacheValid()
	if err != nil {
		return Root{}, err
	}

	if valid {
		return s.loadCachedData()
	}

	err = s.downloadData()
	if err != nil {
		return Root{}, err
	}

	return s.loadCachedData()
}
