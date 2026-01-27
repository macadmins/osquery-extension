package localnetworkpermissions

import (
	"context"
	"os"
	"strconv"
	"strings"

	"github.com/micromdm/plist"
	"github.com/osquery/osquery-go/plugin/table"
	"github.com/pkg/errors"
)

// networkExtensionPlistPath is the default path to the network extension plist file.
// There might be more related plists we're not aware of, so scope may be extended.
var networkExtensionPlistPath = "/Library/Preferences/com.apple.networkextension.plist"

// LocalNetworkPermission represents a single app's local network permission entry
type LocalNetworkPermission struct {
	BundleID       string
	ExecutablePath string
	DisplayName    string
	Type           string
	State          int
	ProviderAdded  string
}

// LocalNetworkPermissionsColumns returns the column definitions for the local_network_permissions table
func LocalNetworkPermissionsColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("bundle_id"),
		table.TextColumn("executable_path"),
		table.TextColumn("display_name"),
		table.TextColumn("type"),
		table.IntegerColumn("state"),
		table.TextColumn("provider_added"),
	}
}

// LocalNetworkPermissionsGenerate generates table rows for the local_network_permissions table
func LocalNetworkPermissionsGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	permissions, err := readLocalNetworkPermissions(networkExtensionPlistPath)
	if err != nil {
		// File not found is expected when no apps have requested local network permissions
		if os.IsNotExist(err) {
			return []map[string]string{}, nil
		}
		return nil, errors.Wrap(err, "read local network permissions")
	}

	results := make([]map[string]string, 0, len(permissions))
	for _, perm := range permissions {
		results = append(results, map[string]string{
			"bundle_id":       perm.BundleID,
			"executable_path": perm.ExecutablePath,
			"display_name":    perm.DisplayName,
			"type":            perm.Type,
			"state":           strconv.Itoa(perm.State),
			"provider_added":  perm.ProviderAdded,
		})
	}

	return results, nil
}

func readLocalNetworkPermissions(plistPath string) ([]LocalNetworkPermission, error) {
	data, err := os.ReadFile(plistPath)
	if err != nil {
		return nil, err
	}

	// Unmarshal into a generic map to handle the NSKeyedArchiver structure
	var archive map[string]interface{}
	if err = plist.Unmarshal(data, &archive); err != nil {
		return nil, err
	}

	// Get the $objects array which contains all archived objects
	objects, ok := archive["$objects"].([]interface{})
	if !ok {
		return nil, nil
	}

	return extractPermissionsFromObjects(objects), nil
}

func extractPermissionsFromObjects(objects []interface{}) []LocalNetworkPermission {
	var permissions []LocalNetworkPermission

	// Iterate through all objects looking for application permission dictionaries
	for _, obj := range objects {
		dict, ok := obj.(map[string]interface{})
		if !ok {
			continue
		}

		// Check if this looks like an application permission entry
		// These have keys like: bundleid, displayname, path, state, type, providerAdded
		if !isAppPermissionDict(dict, objects) {
			continue
		}

		perm := extractPermissionFromDict(dict, objects)
		if perm.BundleID != "" || perm.ExecutablePath != "" {
			permissions = append(permissions, perm)
		}
	}

	return permissions
}

func isAppPermissionDict(dict map[string]interface{}, objects []interface{}) bool {
	// Check for NS.keys and NS.objects which indicate an NSDictionary
	nsKeys, hasKeys := dict["NS.keys"].([]interface{})
	_, hasObjects := dict["NS.objects"].([]interface{})

	if !hasKeys || !hasObjects {
		return false
	}

	// Check if the keys include characteristic app permission fields
	hasCharacteristicKeys := false
	for _, keyRef := range nsKeys {
		keyStr := resolveUID(keyRef, objects)
		if keyStr == "bundleid" || keyStr == "path" || keyStr == "displayname" {
			hasCharacteristicKeys = true
			break
		}
	}

	return hasCharacteristicKeys
}

func extractPermissionFromDict(dict map[string]interface{}, objects []interface{}) LocalNetworkPermission {
	perm := LocalNetworkPermission{}

	nsKeys, ok := dict["NS.keys"].([]interface{})
	if !ok {
		return perm
	}

	nsObjects, ok := dict["NS.objects"].([]interface{})
	if !ok {
		return perm
	}

	// Build a map of resolved keys to resolved values
	for i, keyRef := range nsKeys {
		if i >= len(nsObjects) {
			break
		}

		key := resolveUID(keyRef, objects)
		value := resolveUID(nsObjects[i], objects)

		switch key {
		case "bundleid":
			if s, ok := value.(string); ok {
				perm.BundleID = s
			}
		case "path":
			if s, ok := value.(string); ok {
				perm.ExecutablePath = strings.TrimPrefix(s, "file://")
			}
		case "displayname":
			if s, ok := value.(string); ok {
				perm.DisplayName = s
			}
		case "type":
			if s, ok := value.(string); ok {
				perm.Type = s
			}
		case "state":
			perm.State = toInt(value)
		case "providerAdded":
			if s, ok := value.(string); ok {
				perm.ProviderAdded = s
			}
		}
	}

	return perm
}

// The resolveUID resolves a plist.UID reference to its actual value in the obj array
func resolveUID(ref interface{}, objects []interface{}) interface{} {
	switch v := ref.(type) {
	case plist.UID:
		idx := int(v)
		if idx >= 0 && idx < len(objects) {
			// Don't recursively resolve - just return the direct value
			return objects[idx]
		}
	case uint64:
		idx := int(v)
		if idx >= 0 && idx < len(objects) {
			return objects[idx]
		}
	}
	return ref
}

func toInt(v interface{}) int {
	switch val := v.(type) {
	case int:
		return val
	case int64:
		return int(val)
	case uint64:
		return int(val)
	case float64:
		return int(val)
	}
	return 0
}
