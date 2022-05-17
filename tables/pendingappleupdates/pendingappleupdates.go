package pendingappleupdates

import (
	"context"
	"os"

	"github.com/groob/plist"
	"github.com/macadmins/osquery-extension/pkg/utils"
	"github.com/osquery/osquery-go/plugin/table"
	"github.com/pkg/errors"
)

type softwareUpdatePlist struct {
	RecommendedUpdates []recommendedUpdate `plist:"RecommendedUpdates"`
}

type recommendedUpdate struct {
	DisplayName    string `plist:"Display Name"`
	DisplayVersion string `plist:"Display Version"`
	Identifier     string `plist:"Identifier"`
	ProductKey     string `plist:"Product Key"`
}

func PendingAppleUpdatesColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("display_name"),
		table.TextColumn("display_version"),
		table.TextColumn("identifier"),
		table.TextColumn("product_key"),
	}
}

func PendingAppleUpdatesGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	updatePlist, err := readSoftwareUpdatePlist()
	if err != nil {
		return nil, err
	}
	if updatePlist == nil {
		return nil, nil
	}
	var results []map[string]string

	for _, update := range updatePlist.RecommendedUpdates {
		results = append(results, map[string]string{
			"display_name":    update.DisplayName,
			"display_version": update.DisplayVersion,
			"identifier":      update.Identifier,
			"product_key":     update.ProductKey,
		})
	}

	return results, nil
}

func readSoftwareUpdatePlist() (*softwareUpdatePlist, error) {
	var updatePlist softwareUpdatePlist
	const plistPath = "/Users/graham_gilbert/Downloads/com.apple.SoftwareUpdate.plist"
	if !utils.FileExists(plistPath) {
		return nil, nil
	}
	file, err := os.Open(plistPath)
	if err != nil {
		return &updatePlist, errors.Wrap(err, "open com.apple.SoftwareUpdate plist")
	}
	defer file.Close()

	if err := plist.NewBinaryDecoder(file).Decode(&updatePlist); err != nil {
		return &updatePlist, errors.Wrap(err, "decode com.apple.SoftwareUpdate plist")
	}

	return &updatePlist, nil
}
