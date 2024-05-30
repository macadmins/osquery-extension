package sofa

import (
	"context"
	"strconv"
	"time"

	"github.com/hashicorp/go-version"
	osquery "github.com/osquery/osquery-go"
	"github.com/osquery/osquery-go/plugin/table"
)

type UnpatchedCVE struct {
	CVE               string
	PatchedVersion    string
	ActivelyExploited bool
}

func SofaUnpatchedCVEsColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("os_version"),
		table.TextColumn("cve"),
		table.TextColumn("patched_version"),
		table.TextColumn("actively_exploited"),
		table.TextColumn("url"),
	}
}

func SofaUnpatchedCVEsGenerate(ctx context.Context, queryContext table.QueryContext, socketPath string, opts ...Option) ([]map[string]string, error) {
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

	defaultOpts := []Option{
		WithURL(url),
	}
	opts = append(opts, defaultOpts...)

	client, err := NewSofaClient(opts...)
	if err != nil {
		return nil, err
	}

	root, err := client.downloadSofaJSON()
	if err != nil {
		return nil, err
	}

	var results []map[string]string

	// get all unpatched cves (for any os version that is higher than the current os version)
	unpatchedCVEs, err := getUnpatchedCVEs(root, osVersion)
	if err != nil {
		return nil, err
	}

	for _, unpatchedCVE := range unpatchedCVEs {
		results = append(results, map[string]string{
			"os_version":         osVersion,
			"cve":                unpatchedCVE.CVE,
			"patched_version":    unpatchedCVE.PatchedVersion,
			"actively_exploited": strconv.FormatBool(unpatchedCVE.ActivelyExploited),
			"url":                url,
		})
	}

	return results, nil
}

func getUnpatchedCVEs(root Root, osVersion string) ([]UnpatchedCVE, error) {
	unpatchedCVEs := []UnpatchedCVE{}
	parsedCurrentVersion, err := version.NewVersion(osVersion)
	if err != nil {
		return unpatchedCVEs, err
	}
	for _, os := range root.OSVersions {
		for _, securityRelease := range os.SecurityReleases {
			parsedProductVersion, err := version.NewVersion(securityRelease.ProductVersion)
			if err != nil {
				return unpatchedCVEs, err
			}
			// are we on the same major version?
			if parsedProductVersion.Segments()[0] != parsedCurrentVersion.Segments()[0] {
				continue
			}
			// is the security release version higher than the current version?
			if parsedProductVersion.LessThanOrEqual(parsedCurrentVersion) {
				continue
			}

			for name, activelyExploited := range securityRelease.CVEs {
				unpatchedCVEs = append(unpatchedCVEs, UnpatchedCVE{
					CVE:               name,
					PatchedVersion:    securityRelease.ProductVersion,
					ActivelyExploited: activelyExploited,
				})
			}

		}
	}
	return unpatchedCVEs, nil
}
