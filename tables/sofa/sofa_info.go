package sofa

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/hashicorp/go-version"
	osquery "github.com/osquery/osquery-go"
	"github.com/osquery/osquery-go/plugin/table"
)

const SofaV1URL = "https://sofa.macadmins.io/v1/macos_data_feed.json"

type OSVersion struct {
	OSVersion        string
	Latest           Latest
	SecurityReleases []SecurityRelease
	SupportedModels  []SupportedModel
}

type Latest struct {
	ProductVersion   string
	Build            string
	ReleaseDate      string
	ExpirationDate   string
	SupportedDevices []string
}

type SecurityRelease struct {
	UpdateName               string
	ProductVersion           string
	ReleaseDate              string
	SecurityInfo             string
	CVEs                     map[string]bool
	ActivelyExploitedCVEs    []string
	UniqueCVEsCount          int
	DaysSincePreviousRelease int
}

type SupportedModel struct {
	Model       string
	URL         string
	Identifiers map[string]string
}

type Root struct {
	LastCheck               string
	OSVersions              []OSVersion
	XProtectPayloads        XProtectPayloads
	XProtectPlistConfigData XProtectPlistConfigData
	Models                  map[string]Model
	InstallationApps        InstallationApps
}

type XProtectPayloads struct {
	XProtect      string `json:"com.apple.XProtectFramework.XProtect"`
	PluginService string `json:"com.apple.XprotectFramework.PluginService"`
	ReleaseDate   string
}

type XProtectPlistConfigData struct {
	XProtect    string `json:"com.apple.XProtect"`
	ReleaseDate string
}

type Model struct {
	MarketingName string
	SupportedOS   []string
	OSVersions    []int
}

type InstallationApps struct {
	LatestUMA      LatestUMA
	AllPreviousUMA []previousUMA
}

type LatestUMA struct {
	Title     string
	Version   string
	Build     string
	AppleSlug string
	URL       string
}

type previousUMA struct {
	Title     string
	Version   string
	Build     string
	AppleSlug string
	URL       string
}

type Option func(*SofaClient)

type OsqueryClient interface {
	QueryRow(query string) (map[string]string, error)
	Close()
}

type SofaClient struct {
	endpoint   string
	httpClient *http.Client
	etag       string
	cacheFile  string
	etagFile   string
}

func WithLocalCache(cacheFile, etagFile string) Option {
	return func(s *SofaClient) {
		s.cacheFile = cacheFile
		s.etagFile = etagFile
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

	tempDir := os.TempDir()
	s := &SofaClient{
		endpoint: SofaV1URL,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		cacheFile: filepath.Join(tempDir, "sofa_cache.json"),
		etagFile:  filepath.Join(tempDir, "sofa_etag.txt"),
	}

	for _, opt := range opts {
		opt(s)
	}

	if _, err := os.Stat(s.etagFile); err == nil {
		etag, err := os.ReadFile(s.etagFile)
		if err != nil {
			return nil, err
		}
		s.etag = string(etag)
	}

	return s, nil
}

func (s *SofaClient) downloadSofaJSON() (Root, error) {
	var root Root

	req, err := http.NewRequest("HEAD", s.endpoint, nil)
	if err != nil {
		return root, err
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return root, err
	}
	defer resp.Body.Close()

	etag := resp.Header.Get("Etag")

	// If Etags match, load from local file
	if etag == s.etag {
		file, err := os.Open(s.cacheFile)
		if err != nil {
			return root, err
		}
		defer file.Close()

		err = json.NewDecoder(file).Decode(&root)
		if err != nil {
			return root, err
		}

		return root, nil
	}

	// Otherwise, download the file
	req, err = http.NewRequest("GET", s.endpoint, nil)
	if err != nil {
		return root, err
	}

	resp, err = s.httpClient.Do(req)
	if err != nil {
		return root, err
	}
	defer resp.Body.Close()

	err = json.NewDecoder(resp.Body).Decode(&root)
	if err != nil {
		return root, err
	}

	file, err := os.Create(s.cacheFile)
	if err != nil {
		return root, err
	}
	defer file.Close()

	err = json.NewEncoder(file).Encode(root)
	if err != nil {
		return root, err
	}

	s.etag = etag
	err = os.WriteFile(s.etagFile, []byte(s.etag), 0644)
	if err != nil {
		return root, err
	}

	return root, nil
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
