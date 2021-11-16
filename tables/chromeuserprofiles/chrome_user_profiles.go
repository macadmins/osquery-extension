package chromeuserprofiles

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"strconv"

	"github.com/osquery/osquery-go/plugin/table"
	"github.com/pkg/errors"
)

// Very much inspired (i.e. mostly copied, but I'm having problems importing it) by https://github.com/kolide/launcher/blob/master/pkg/osquery/table/chrome_user_profiles.go

type findFile struct {
	username string
}

type FindFileOpt func(*findFile)

func WithUsername(username string) FindFileOpt {
	return func(ff *findFile) {
		ff.username = username
	}
}

var homeDirLocations = map[string][]string{
	"windows": {"/Users"}, // windows10 uses /Users
	"darwin":  {"/Users"},
}
var homeDirDefaultLocation = []string{"/home"}

type userFileInfo struct {
	user string
	path string
}

var chromeLocalStateDirs = map[string][]string{
	"windows": []string{"Appdata/Local/Google/Chrome/User Data"},
	"darwin":  []string{"Library/Application Support/Google/Chrome"},
}

// try the list of known linux paths if runtime.GOOS doesn't match 'darwin' or 'windows'
var chromeLocalStateDirDefault = []string{".config/google-chrome", ".config/chromium", "snap/chromium/current/.config/chromium"}

type chromeLocalState struct {
	Profile struct {
		InfoCache map[string]chromeProfileInfo `json:"info_cache"`
	} `json:"profile"`
}

type chromeProfileInfo struct {
	Name      string `json:"name"`
	Ephemeral bool   `json:"is_ephemeral"`
	Email     string `json:"user_name"`
}

func GoogleChromeProfilesColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("username"),
		table.TextColumn("email"),
		table.TextColumn("name"),
		table.IntegerColumn("ephemeral"),
	}
}

func generateForPath(ctx context.Context, fileInfo userFileInfo) ([]map[string]string, error) {
	var results []map[string]string
	data, err := ioutil.ReadFile(fileInfo.path)
	if err != nil {
		return nil, errors.Wrap(err, "reading chrome local state file")
	}
	var localState chromeLocalState
	if err := json.Unmarshal(data, &localState); err != nil {
		return nil, errors.Wrap(err, "unmarshalling chome local state")
	}

	for _, profileInfo := range localState.Profile.InfoCache {
		results = append(results, map[string]string{
			"username":  fileInfo.user,
			"email":     profileInfo.Email,
			"name":      profileInfo.Name,
			"ephemeral": strconv.Itoa(btoi(profileInfo.Ephemeral)),
		})
	}

	return results, nil
}

func GoogleChromeProfilesGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	osChromeLocalStateDirs, ok := chromeLocalStateDirs[runtime.GOOS]
	if !ok {
		osChromeLocalStateDirs = chromeLocalStateDirDefault
	}

	var results []map[string]string
	for _, localStateFilePath := range osChromeLocalStateDirs {
		userFiles, err := findFileInUserDirs(filepath.Join(localStateFilePath, "Local State"))
		if err != nil {
			continue
		}
		for _, file := range userFiles {
			res, err := generateForPath(ctx, file)
			if err != nil {
				continue
			}
			results = append(results, res...)
		}
	}
	return results, nil
}

func findFileInUserDirs(pattern string, opts ...FindFileOpt) ([]userFileInfo, error) {
	ff := &findFile{}

	for _, opt := range opts {
		opt(ff)
	}

	homedirRoots, ok := homeDirLocations[runtime.GOOS]
	if !ok {
	}

	foundPaths := []userFileInfo{}

	// Redo/remove when we make username a required parameter
	if ff.username == "" {
		for _, possibleHome := range homedirRoots {

			userDirs, err := ioutil.ReadDir(possibleHome)
			if err != nil {
				// This possibleHome doesn't exist. Move on
				continue
			}

			// For each user's dir, in this possibleHome, check!
			for _, ud := range userDirs {
				userPathPattern := filepath.Join(possibleHome, ud.Name(), pattern)
				fullPaths, err := filepath.Glob(userPathPattern)
				if err != nil {
					continue
				}
				for _, fullPath := range fullPaths {
					if stat, err := os.Stat(fullPath); err == nil && stat.Mode().IsRegular() {
						foundPaths = append(foundPaths, userFileInfo{
							user: ud.Name(),
							path: fullPath,
						})
					}
				}
			}
		}

		return foundPaths, nil
	}

	// We have a username. Future normal path here
	for _, possibleHome := range homedirRoots {
		userPathPattern := filepath.Join(possibleHome, ff.username, pattern)
		fullPaths, err := filepath.Glob(userPathPattern)
		if err != nil {
			continue
		}
		for _, fullPath := range fullPaths {
			if stat, err := os.Stat(fullPath); err == nil && stat.Mode().IsRegular() {
				foundPaths = append(foundPaths, userFileInfo{
					user: ff.username,
					path: fullPath,
				})
			}
		}
	}
	return foundPaths, nil
}

func btoi(value bool) int {
	if value {
		return 1
	}
	return 0
}
