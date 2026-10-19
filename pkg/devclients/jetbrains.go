package devclients

import (
	"context"
	"encoding/xml"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/macadmins/osquery-extension/pkg/fsscan"
)

// JetBrains IDEs record the projects a user opened in options/recentProjects.xml, inside one
// configuration directory per product and version, under the application-support root:
//
//	macOS    ~/Library/Application Support/JetBrains/<product><version>
//	Windows  %APPDATA%\JetBrains\<product><version>
//	Linux    ~/.config/JetBrains/<product><version>
//
// JetBrains documents those configuration directories. It does not document the
// recentProjects.xml inside them, so the format here is the one GoLand 2026.2 and PyCharm
// 2026.2 wrote on the development machine: each project is the key of an <entry> in the map
// of the RecentProjectsManager component, written with placeholders such as
// $USER_HOME$/Documents/GitHub/project.

// MaxJetBrainsDirs bounds the listing of the JetBrains directory. It holds one directory per
// product and version ever installed plus a few of the Toolbox app's own, so a long-lived
// machine accumulates them; the development machine has nine.
const MaxJetBrainsDirs = 128

// jetBrainsProductDir matches a product configuration directory such as GoLand2026.2 or
// IdeaIC2025.3, and not the Toolbox app's own directories beside them, such as Toolbox,
// Daemon and consentOptions.
var jetBrainsProductDir = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]*20[0-9]{2}\.[0-9]+$`)

// userHomePlaceholder is the one placeholder expanded. Every other one names a location this
// reader has no way to resolve for another account, and an entry using one reaches the
// collector unexpanded, where containment refuses it as an unusable path and counts it.
const userHomePlaceholder = "$USER_HOME$"

// appConfigPlaceholder prefixes the IDE's own scratch workspace, which every product creates
// and which is not a project anyone chose. Skipped silently, as the hidden flag on it says.
const appConfigPlaceholder = "$APPLICATION_CONFIG_DIR$"

// recentProjectsFile is the projection of recentProjects.xml this reader decodes. It names the
// entry keys and the hidden flag, and the element names it needs to recognize the layout, and
// nothing else, so the window titles, timestamps and build numbers beside them are never decoded.
type recentProjectsFile struct {
	XMLName    xml.Name
	Components []struct {
		Name    string `xml:"name,attr"`
		Options []struct {
			Name string `xml:"name,attr"`
			Map  *struct {
				Entries []recentProjectEntry `xml:"entry"`
				Other   []struct {
					XMLName xml.Name
				} `xml:",any"`
			} `xml:"map"`
			Other []struct {
				XMLName xml.Name
			} `xml:",any"`
		} `xml:"option"`
	} `xml:"component"`
}

type recentProjectEntry struct {
	Key   string `xml:"key,attr"`
	Value struct {
		Meta struct {
			Hidden string `xml:"hidden,attr"`
		} `xml:"RecentProjectMetaInfo"`
	} `xml:"value"`
}

// recentEntries returns the entries of a parsed recentProjects.xml, and false when its layout is
// not the one this reader knows, so a JetBrains release that renames an element is reported
// rather than read as a list with no projects.
//
// The known layout is IntelliJ's persisted state for the component named RecentProjectsManager,
// whose project list is the map option additionalInfo (RecentProjectsManagerBase.kt and
// RecentProjectMetaInfo.kt in intellij-community). The state class omits a property that holds
// its default value, and an empty map is the default, so a list with no projects has no
// additionalInfo option, and a state with every property at its default has no component.
// Both are empty, not unfamiliar. An additionalInfo option that is present must hold a map,
// because an omitted option and a present one in another form are different facts. A map
// under any other option name is unfamiliar: the state holds no other map, so that is what a
// renamed additionalInfo looks like.
func recentEntries(file recentProjectsFile) ([]recentProjectEntry, bool) {
	if file.XMLName.Local != "application" {
		return nil, false
	}
	if len(file.Components) == 0 {
		return nil, true
	}
	var entries []recentProjectEntry
	recognized := false
	for _, component := range file.Components {
		if component.Name != "RecentProjectsManager" {
			continue
		}
		recognized = true
		for _, option := range component.Options {
			if option.Name == "additionalInfo" && (option.Map == nil || len(option.Other) > 0) {
				return nil, false
			}
			if option.Map == nil {
				continue
			}
			if option.Name != "additionalInfo" || len(option.Map.Other) > 0 {
				return nil, false
			}
			for _, entry := range option.Map.Entries {
				if entry.Key == "" {
					return nil, false
				}
				entries = append(entries, entry)
			}
		}
	}
	return entries, recognized
}

// JetBrainsProjects lists the projects recorded in each JetBrains IDE's recentProjects.xml.
//
// The result uses WorkspaceScan's fields with the same meaning: Listings holds a JetBrains
// directory that failed or was cut short, UnreadableRecords counts recentProjects.xml files
// that exist and could not be read, MalformedRecords counts ones that did not parse or whose
// layout recentEntries does not recognize, and
// Stopped reports the budget ran out. A product directory with no recentProjects.xml is
// silent, because a product that was installed and never opened a project writes none.
//
// appDataRoot is the account's redirected roaming root on Windows, or ""; see
// RedirectAppSupport. opts governs every read.
func JetBrainsProjects(ctx context.Context, home, appDataRoot string, deadline time.Time,
	opts fsscan.ReadOpts) WorkspaceScan {
	var scan WorkspaceScan
	root := filepath.Join(AppSupportDir(), "JetBrains")
	if rewritten, usable := RedirectAppSupport(root, appDataRoot, home); !usable {
		return scan
	} else if rewritten != "" {
		root = rewritten
	}
	if !budgetRemains(ctx, deadline) {
		scan.Stopped = true
		return scan
	}
	names, truncated, err := fsscan.ListDirNamesCapped(home, root, MaxJetBrainsDirs)
	if err != nil {
		scan.Listings = append(scan.Listings, WorkspaceListing{Class: fsscan.ClassifyError(err)})
		return scan
	}
	if truncated {
		scan.Listings = append(scan.Listings, WorkspaceListing{Truncated: true, Count: len(names)})
	}
	for _, name := range names {
		if !jetBrainsProductDir.MatchString(name) {
			continue
		}
		if !budgetRemains(ctx, deadline) {
			scan.Stopped = true
			break
		}
		data, readErr := fsscan.ReadBoundedUnder(home,
			filepath.Join(root, name, "options", "recentProjects.xml"), opts)
		if readErr != nil {
			if fsscan.ClassifyError(readErr) != fsscan.ClassAbsent {
				scan.UnreadableRecords++
			}
			continue
		}
		var file recentProjectsFile
		if err := xml.Unmarshal(StripBOM(data), &file); err != nil {
			scan.MalformedRecords++
			continue
		}
		entries, recognized := recentEntries(file)
		if !recognized {
			scan.MalformedRecords++
			continue
		}
		for _, entry := range entries {
			if entry.Value.Meta.Hidden == "true" || strings.HasPrefix(entry.Key, appConfigPlaceholder) {
				continue
			}
			scan.Folders = append(scan.Folders, WorkspaceFolder{
				Recorded: expandUserHome(entry.Key, home), Origin: OriginJetBrainsRecent})
		}
	}
	return scan
}

// expandUserHome replaces a leading $USER_HOME$ with home. JetBrains writes the rest of the
// path with forward slashes on every platform, so it is converted to native separators.
func expandUserHome(recorded, home string) string {
	rest, found := strings.CutPrefix(recorded, userHomePlaceholder)
	if !found {
		return recorded
	}
	return filepath.Join(home, filepath.FromSlash(rest))
}
