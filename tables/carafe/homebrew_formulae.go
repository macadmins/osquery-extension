package carafe

import (
	"context"
	"encoding/json"
	"os"
	"strconv"

	"github.com/macadmins/osquery-extension/pkg/utils"
	"github.com/osquery/osquery-go/plugin/table"
)

var homebrewFormulaePath = "/Library/Application Support/MacAdmins/Carafe/homebrew_formulae.json"

type homebrewInventory struct {
	SchemaVersion string                `json:"schema_version"`
	GeneratedAt   string                `json:"generated_at"`
	BrewPath      string                `json:"brew_path"`
	Arch          string                `json:"arch"`
	Formulae      []homebrewFormulaeRow `json:"formulae"`
}

type homebrewFormulaeRow struct {
	Name               string `json:"name"`
	FullName           string `json:"full_name"`
	Tap                string `json:"tap"`
	InstalledVersion   string `json:"installed_version"`
	InstalledOnRequest bool   `json:"installed_on_request"`
	SourceURL          string `json:"source_url"`
	Homepage           string `json:"homepage"`
	License            string `json:"license"`
	Checksum           string `json:"checksum"`
	Outdated           bool   `json:"outdated"`
}

func HomebrewFormulaeColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("name"),
		table.TextColumn("full_name"),
		table.TextColumn("tap"),
		table.TextColumn("installed_version"),
		table.TextColumn("installed_on_request"),
		table.TextColumn("source_url"),
		table.TextColumn("homepage"),
		table.TextColumn("license"),
		table.TextColumn("checksum"),
		table.TextColumn("outdated"),
		table.TextColumn("generated_at"),
		table.TextColumn("brew_path"),
		table.TextColumn("arch"),
		table.TextColumn("schema_version"),
	}
}

func HomebrewFormulaeGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	fs := utils.OSFileSystem{}
	inventory, err := loadHomebrewFormulaeInventory(fs, homebrewFormulaePath)
	if err != nil {
		return nil, err
	}
	if inventory == nil {
		return nil, nil
	}

	var results []map[string]string
	for _, formula := range inventory.Formulae {
		results = append(results, map[string]string{
			"name":                 formula.Name,
			"full_name":            formula.FullName,
			"tap":                  formula.Tap,
			"installed_version":    formula.InstalledVersion,
			"installed_on_request": strconv.FormatBool(formula.InstalledOnRequest),
			"source_url":           formula.SourceURL,
			"homepage":             formula.Homepage,
			"license":              formula.License,
			"checksum":             formula.Checksum,
			"outdated":             strconv.FormatBool(formula.Outdated),
			"generated_at":         inventory.GeneratedAt,
			"brew_path":            inventory.BrewPath,
			"arch":                 inventory.Arch,
			"schema_version":       inventory.SchemaVersion,
		})
	}

	return results, nil
}

func loadHomebrewFormulaeInventory(fs utils.FileSystem, path string) (*homebrewInventory, error) {
	if !utils.FileExists(fs, path) {
		return nil, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var inventory homebrewInventory
	if err := json.Unmarshal(data, &inventory); err != nil {
		return nil, err
	}

	return &inventory, nil
}
