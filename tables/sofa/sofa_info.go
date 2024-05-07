package sofa

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/go-version"
	"github.com/macadmins/osquery-extension/pkg/utils"
	osquery "github.com/osquery/osquery-go"
	"github.com/osquery/osquery-go/plugin/table"
)

const SofaV1URL = "https://sofa.macadmins.io/v1/macos_data_feed.json"
const SofaV1TimestampURL = "https://sofa.macadmins.io/v1/timestamp.json"

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

type Timestamp struct {
	MacOS MacOS `json:"macOS"`
	IOS   IOS   `json:"iOS"`
}
type MacOS struct {
	LastCheck  SofaTime `json:"LastCheck"`
	UpdateHash string   `json:"UpdateHash"`
}
type IOS struct {
	LastCheck  SofaTime `json:"LastCheck"`
	UpdateHash string   `json:"UpdateHash"`
}

type Latest struct {
	Build            string
	ExpirationDate   string
	ProductVersion   string
	ReleaseDate      string
	SupportedDevices []string
}

type SecurityRelease struct {
	ActivelyExploitedCVEs    []string
	CVEs                     map[string]bool
	DaysSincePreviousRelease int
	ProductVersion           string
	ReleaseDate              string
	SecurityInfo             string
	UniqueCVEsCount          int
	UpdateName               string
}

type SupportedModel struct {
	Identifiers map[string]string
	Model       string
	URL         string
}

type Root struct {
	UpdateHash              string
	OSVersions              []OSVersion
	XProtectPayloads        XProtectPayloads
	XProtectPlistConfigData XProtectPlistConfigData
	Models                  map[string]Model
	InstallationApps        InstallationApps
}

type InstallationApps struct {
	AllPreviousUMA []previousUMA `json:"AllPreviousUMA,omitempty"`
	LatestMacIPSW  LatestMacIPSW `json:"LatestMacIPSW,omitempty"`
	LatestUMA      LatestUMA     `json:"LatestUMA,omitempty"`
}

type LatestMacIPSW struct {
	MacosIpswAppleSlug string `json:"macos_ipsw_apple_slug,omitempty"`
	MacosIpswBuild     string `json:"macos_ipsw_build,omitempty"`
	MacosIpswURL       string `json:"macos_ipsw_url,omitempty"`
	MacosIpswVersion   string `json:"macos_ipsw_version,omitempty"`
}

type LatestUMA struct {
	AppleSlug string `json:"apple_slug,omitempty"`
	Build     string `json:"build,omitempty"`
	Title     string `json:"title,omitempty"`
	URL       string `json:"url,omitempty"`
	Version   string `json:"version,omitempty"`
}

type Model struct {
	MarketingName string
	OSVersions    []int
	SupportedOS   []string
}

type previousUMA struct {
	AppleSlug string `json:"apple_slug,omitempty"`
	Build     string `json:"build,omitempty"`
	Title     string `json:"title,omitempty"`
	URL       string `json:"url,omitempty"`
	Version   string `json:"version,omitempty"`
}

type XProtectPayloads struct {
	PluginService string `json:"com.apple.XprotectFramework.PluginService"`
	ReleaseDate   string
	XProtect      string `json:"com.apple.XProtectFramework.XProtect"`
}

type XProtectPlistConfigData struct {
	ReleaseDate string
	XProtect    string `json:"com.apple.XProtect"`
}

type OSVersion struct {
	Latest           Latest
	OSVersion        string
	SecurityReleases []SecurityRelease
	SupportedModels  []SupportedModel
}

type Option func(*SofaClient)

type OsqueryClient interface {
	QueryRow(query string) (map[string]string, error)
	Close()
}

type SofaClient struct {
	endpoint          string
	timestampEndpoint string
	httpClient        *http.Client
	localHash         string
	remoteHash        string
	cacheFile         string
	timestampFile     string
}

func WithLocalCache(cacheFile, timestampFile string) Option {
	return func(s *SofaClient) {
		s.cacheFile = cacheFile
		s.timestampFile = timestampFile
	}
}

func WithURL(url string) Option {
	return func(s *SofaClient) {
		s.endpoint = url
	}
}

func WithTimestampURL(url string) Option {
	return func(s *SofaClient) {
		s.timestampEndpoint = url
	}
}

func WithHTTPClient(client *http.Client) Option {
	return func(s *SofaClient) {
		s.httpClient = client
	}
}

func NewSofaClient(opts ...Option) (*SofaClient, error) {

	tempDir := os.TempDir()
	s := &SofaClient{
		endpoint:          SofaV1URL,
		timestampEndpoint: SofaV1TimestampURL,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		cacheFile:     filepath.Join(tempDir, "sofa_cache.json"),
		timestampFile: filepath.Join(tempDir, "sofa_timestamp.json"),
	}

	for _, opt := range opts {
		opt(s)
	}

	return s, nil
}

func (s *SofaClient) cacheValid() (bool, error) {
	err := s.downloadTimestamp()
	if err != nil {
		return false, err
	}

	timestamp, err := s.loadCachedTimestamp()
	if err != nil {
		return false, err
	}

	if !utils.FileExists(s.cacheFile) {
		return false, nil
	}

	root, err := s.loadCachedData()
	if err != nil {
		return false, err
	}

	s.localHash = root.UpdateHash
	s.remoteHash = timestamp.MacOS.UpdateHash

	if root.UpdateHash != timestamp.MacOS.UpdateHash {
		return false, nil
	}

	return true, nil
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

func (s *SofaClient) loadCachedTimestamp() (Timestamp, error) {
	jsonData, err := os.ReadFile(s.timestampFile)
	if err != nil {
		return Timestamp{}, err
	}

	var timestamp Timestamp
	err = json.Unmarshal(jsonData, &timestamp)
	if err != nil {
		return Timestamp{}, err
	}

	return timestamp, nil
}

func (s *SofaClient) downloadData() error {
	return s.downloadFile(s.endpoint, s.cacheFile)
}

func (s *SofaClient) downloadTimestamp() error {
	return s.downloadFile(s.timestampEndpoint, s.timestampFile)
}

func (s *SofaClient) downloadFile(url, path string) error {
	req, err := http.NewRequest("GET", url, http.NoBody)
	if err != nil {
		return err
	}

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
func SofaSecurityReleaseInfoColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("update_name"),
		table.TextColumn("product_version"),
		table.TextColumn("release_date"),
		table.TextColumn("security_info"),
		table.IntegerColumn("unique_cves_count"),
		table.IntegerColumn("days_since_previous_release"),
		table.TextColumn("os_version"),
	}
}

func SofaSecurityReleaseInfoGenerate(ctx context.Context, queryContext table.QueryContext, socketPath string) ([]map[string]string, error) {
	url := SofaV1URL
	if constraintList, present := queryContext.Constraints["url"]; present {
		// 'url' is in the where clause
		for _, constraint := range constraintList.Constraints {
			// =
			if constraint.Operator == table.OperatorEquals {
				url = constraint.Expression
			}
		}
	}
	osVersion := ""
	if constraintList, present := queryContext.Constraints["os_version"]; present {
		// 'os_version' is in the where clause
		for _, constraint := range constraintList.Constraints {
			// =
			if constraint.Operator == table.OperatorEquals {
				osVersion = constraint.Expression
			}
		}
	}

	if osVersion == "" {
		// get the current device os version from osquery
		osqueryClient, err := osquery.NewClient(socketPath, 10*time.Second)
		if err != nil {
			return nil, err
		}
		defer osqueryClient.Close()

		osVersion, err = getCurrentOSVersion(osqueryClient)
		if err != nil {
			return nil, err
		}
	}

	client, err := NewSofaClient(WithURL(url))
	if err != nil {
		return nil, err
	}

	root, err := client.downloadSofaJSON()
	if err != nil {
		return nil, err
	}

	var results []map[string]string

	// get the security release info for the current os version
	securityReleases, err := getSecurityReleaseInfoForOSVersion(root, osVersion)
	if err != nil {
		return nil, err
	}
	for _, securityRelease := range securityReleases {
		results = append(results, map[string]string{
			"update_name":                 securityRelease.UpdateName,
			"product_version":             securityRelease.ProductVersion,
			"release_date":                securityRelease.ReleaseDate,
			"security_info":               securityRelease.SecurityInfo,
			"unique_cves_count":           strconv.Itoa(securityRelease.UniqueCVEsCount),
			"days_since_previous_release": strconv.Itoa(securityRelease.DaysSincePreviousRelease),
			"os_version":                  osVersion,
		})
	}

	return results, nil
}

func getSecurityReleaseInfoForOSVersion(root Root, osVersion string) ([]SecurityRelease, error) {
	out := []SecurityRelease{}
	parsedOSVersion, err := version.NewVersion(osVersion)
	if err != nil {
		return out, err
	}
	for _, os := range root.OSVersions {
		for _, securityRelease := range os.SecurityReleases {
			parsedProductVersion, err := version.NewVersion(securityRelease.ProductVersion)
			if err != nil {
				return out, err
			}
			if parsedProductVersion.GreaterThanOrEqual(parsedOSVersion) {
				out = append(out, securityRelease)
			}
		}
	}
	if len(out) == 0 {
		return []SecurityRelease{}, errors.New("no security release info found for os version")
	}

	return out, nil
}

func getCurrentOSVersion(client OsqueryClient) (string, error) {
	osVersionQuery := "SELECT * FROM os_version;"

	resp, err := client.QueryRow(osVersionQuery)
	if err != nil {
		return "", err
	}

	version, err := getVersionFromResponse(resp)
	if err != nil {
		return "", err
	}
	return version, nil

}

func getVersionFromResponse(resp map[string]string) (string, error) {
	// test if version is in the response
	if version, ok := resp["version"]; ok {
		return version, nil
	}
	return "", errors.New("version not found in response")
}
