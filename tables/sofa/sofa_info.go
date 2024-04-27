package sofa

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

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

type SofaClient struct {
	endpoint   string
	httpClient *http.Client
}

type OsqueryClient interface {
	QueryRow(query string) (map[string]string, error)
	Close()
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

func NewSofaClient(opts ...Option) *SofaClient {
	s := &SofaClient{
		endpoint: SofaV1URL,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}

	for _, opt := range opts {
		opt(s)
	}

	return s
}

func (s SofaClient) downloadSofaJSON() (Root, error) {
	var root Root
	resp, err := s.httpClient.Get(s.endpoint)
	if err != nil {
		return root, err
	}

	defer resp.Body.Close()

	err = json.NewDecoder(resp.Body).Decode(&root)
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
	}
}

func SofaSecurityReleaseInfoGenerate(ctx context.Context, queryContext table.QueryContext, socketPath string) ([]map[string]string, error) {

	url := SofaV1URL
	if constraintList, present := queryContext.Constraints["url"]; present {
		// 'path' is in the where clause
		for _, constraint := range constraintList.Constraints {
			// =
			if constraint.Operator == table.OperatorEquals {
				url = constraint.Expression
			}
		}
	}

	client := NewSofaClient(WithURL(url))
	root, err := client.downloadSofaJSON()
	if err != nil {
		return nil, err
	}

	var results []map[string]string
	// get the current device os version from osquery
	osqueryClient, err := osquery.NewClient(socketPath, 10*time.Second)
	if err != nil {
		return nil, err
	}
	defer osqueryClient.Close()

	osVersion, err := getCurrentOSVersion(osqueryClient)
	if err != nil {
		return nil, err
	}

	// get the security release info for the current os version
	securityRelease, err := getSecurityReleaseInfoForCurrentOSVersion(root, osVersion)
	if err != nil {
		return nil, err
	}

	results = append(results, map[string]string{
		"update_name":                 securityRelease.UpdateName,
		"product_version":             securityRelease.ProductVersion,
		"release_date":                securityRelease.ReleaseDate,
		"security_info":               securityRelease.SecurityInfo,
		"unique_cves_count":           strconv.Itoa(securityRelease.UniqueCVEsCount),
		"days_since_previous_release": strconv.Itoa(securityRelease.DaysSincePreviousRelease),
	})
	return results, nil
}

func getSecurityReleaseInfoForCurrentOSVersion(root Root, osVersion string) (SecurityRelease, error) {
	for _, os := range root.OSVersions {
		for _, securityRelease := range os.SecurityReleases {
			if securityRelease.ProductVersion == osVersion {
				return securityRelease, nil
			}
		}
	}
	return SecurityRelease{}, errors.New("no security release info found for current os version")
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
