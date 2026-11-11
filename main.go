package main

import (
	"context"
	"flag"
	"log"
	"runtime"
	"time"

	"github.com/macadmins/osquery-extension/pkg/utils"
	"github.com/macadmins/osquery-extension/tables/alt_system_info"
	"github.com/macadmins/osquery-extension/tables/chromeuserprofiles"
	"github.com/macadmins/osquery-extension/tables/crowdstrike_falcon"
	"github.com/macadmins/osquery-extension/tables/energyimpact"
	"github.com/macadmins/osquery-extension/tables/fileline"
	"github.com/macadmins/osquery-extension/tables/filevaultusers"
	gomodules "github.com/macadmins/osquery-extension/tables/go_modules"
	"github.com/macadmins/osquery-extension/tables/localnetworkpermissions"
	macosprofiles "github.com/macadmins/osquery-extension/tables/macos_profiles"
	"github.com/macadmins/osquery-extension/tables/macosrsr"
	mcpservers "github.com/macadmins/osquery-extension/tables/mcp_servers"
	"github.com/macadmins/osquery-extension/tables/mdm"
	"github.com/macadmins/osquery-extension/tables/munki"
	"github.com/macadmins/osquery-extension/tables/networkquality"
	"github.com/macadmins/osquery-extension/tables/pendingappleupdates"
	"github.com/macadmins/osquery-extension/tables/privileges"
	"github.com/macadmins/osquery-extension/tables/puppet"
	"github.com/macadmins/osquery-extension/tables/socpower"
	"github.com/macadmins/osquery-extension/tables/sofa"
	"github.com/macadmins/osquery-extension/tables/thermalthrottling"
	"github.com/macadmins/osquery-extension/tables/touchid"
	"github.com/macadmins/osquery-extension/tables/unifiedlog"
	"github.com/macadmins/osquery-extension/tables/wifi_network"

	"github.com/apache/thrift/lib/go/thrift"
	"github.com/macadmins/osquery-extension/tables/authdb"
	osquery "github.com/osquery/osquery-go"
	"github.com/osquery/osquery-go/plugin/table"
)

var Version = "0"

func main() {
	var (
		flSocketPath = flag.String("socket", "", "")
		flTimeout    = flag.Int("timeout", 0, "")
		_            = flag.Int("interval", 0, "")
		_            = flag.Bool("verbose", false, "")
	)
	flag.Parse()

	// allow for osqueryd to create the socket path otherwise it will error
	time.Sleep(3 * time.Second)

	if Version == "" {
		panic("Version not set")
	}

	useragent := sofa.BuildUserAgent(Version)
	sofaOpts := []sofa.Option{
		sofa.WithUserAgent(useragent),
	}

	server, err := osquery.NewExtensionManagerServer(
		"macadmins_extension",
		*flSocketPath,
		osquery.ServerTimeout(time.Duration(*flTimeout)*time.Second),
		// Buffered, so a large result is written in 16 KiB batches rather than one write per
		// Thrift primitive, as kolide/launcher does.
		osquery.WithTransportFactory(thrift.NewTBufferedTransportFactory(16*1024)),
	)
	if err != nil {
		log.Fatalf("Error creating extension: %s\n", err)
	}

	// Create and register a new table plugin with the server.
	// Adding a new table? Add it to the list and the loop below will handle
	// the registration for you.
	plugins := []osquery.OsqueryPlugin{
		newTable("puppet_info", puppet.PuppetInfoColumns(), puppet.PuppetInfoGenerate),
		newTable("puppet_logs", puppet.PuppetLogsColumns(), puppet.PuppetLogsGenerate),
		newTable("puppet_state", puppet.PuppetStateColumns(), puppet.PuppetStateGenerate),
		newTable("puppet_facts", puppet.PuppetFactsColumns(), puppet.PuppetFactsGenerate),
		newTable("google_chrome_profiles", chromeuserprofiles.GoogleChromeProfilesColumns(), chromeuserprofiles.GoogleChromeProfilesGenerate),
		newTable("file_lines", fileline.FileLineColumns(), fileline.FileLineGenerate),
	}

	// Platform specific tables
	// if runtime.GOOS == "windows" {
	// If there were windows only tables, they would go here
	// }

	// mcp_servers and go_modules are not darwin-only: pkg/fsscan has a symlink-refusing
	// backend for POSIX (iterated openat with O_NOFOLLOW) and for Windows (os.Root plus a
	// reparse-point check and a post-open identity re-check), and the per-user client
	// locations in pkg/devclients resolve per OS. Platforms with neither backend report
	// unsupported rather than degrading, so these tables are registered where they can answer
	// safely and left unregistered where they cannot.
	if runtime.GOOS == "darwin" || runtime.GOOS == "windows" || runtime.GOOS == "linux" {
		plugins = append(plugins, newTable(
			"mcp_servers", mcpservers.MCPServersColumns(),
			func(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
				return mcpservers.MCPServersGenerate(ctx, queryContext, *flSocketPath)
			}))
		plugins = append(plugins, newTable(
			"go_modules", gomodules.GoModulesColumns(),
			func(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
				return gomodules.GoModulesGenerate(ctx, queryContext, *flSocketPath)
			}))
	}

	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		linuxPlugins := []osquery.OsqueryPlugin{
			newTable(
				"crowdstrike_falcon",
				crowdstrike_falcon.CrowdstrikeFalconColumns(),
				func(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
					return crowdstrike_falcon.CrowdstrikeFalconGenerate(ctx, queryContext, *flSocketPath)
				}),
		}
		plugins = append(plugins, linuxPlugins...)
	}

	if runtime.GOOS == "darwin" {
		darwinPlugins := []osquery.OsqueryPlugin{
			newTable("energy_impact", energyimpact.EnergyImpactColumns(), energyimpact.EnergyImpactGenerate),
			newTable("filevault_users", filevaultusers.FileVaultUsersColumns(), filevaultusers.FileVaultUsersGenerate),
			newTable("local_network_permissions", localnetworkpermissions.LocalNetworkPermissionsColumns(), localnetworkpermissions.LocalNetworkPermissionsGenerate),
			newTable("macos_profiles", macosprofiles.MacOSProfilesColumns(), macosprofiles.MacOSProfilesGenerate),
			newTable("mdm", mdm.MDMInfoColumns(), mdm.MDMInfoGenerate),
			newTable("munki_info", munki.MunkiInfoColumns(), munki.MunkiInfoGenerate),
			newTable("munki_installs", munki.MunkiInstallsColumns(), munki.MunkiInstallsGenerate),
			newTable("network_quality", networkquality.NetworkQualityColumns(), networkquality.NetworkQualityGenerate),
			newTable("pending_apple_updates", pendingappleupdates.PendingAppleUpdatesColumns(), pendingappleupdates.PendingAppleUpdatesGenerate),
			newTable("privileges_events", privileges.PrivilegesEventsColumns(), privileges.PrivilegesEventsGenerate),
			newTable("macadmins_unified_log", unifiedlog.UnifiedLogColumns(), unifiedlog.UnifiedLogGenerate),
			newTable("macos_rsr", macosrsr.MacOSRsrColumns(), macosrsr.MacOSRsrGenerate),
			newTable("sofa_security_release_info", sofa.SofaSecurityReleaseInfoColumns(), func(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
				return sofa.SofaSecurityReleaseInfoGenerate(ctx, queryContext, *flSocketPath, sofaOpts...)
			}),
			newTable("sofa_unpatched_cves", sofa.SofaUnpatchedCVEsColumns(), func(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
				return sofa.SofaUnpatchedCVEsGenerate(ctx, queryContext, *flSocketPath, sofaOpts...)
			}),
			newTable("authdb", authdb.AuthDBColumns(), authdb.AuthDBGenerate),
			newTable(
				"wifi_network",
				wifi_network.WifiNetworkColumns(),
				func(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
					return wifi_network.WifiNetworkGenerate(ctx, queryContext, *flSocketPath)
				},
			),
			newTable(alt_system_info.TableName, alt_system_info.AltSystemInfoColumns(),
				func(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
					return alt_system_info.AltSystemInfoGenerate(ctx, queryContext, *flSocketPath)
				},
			),
			newTable("macos_thermal_pressure", thermalthrottling.ThermalPressureColumns(), thermalthrottling.ThermalPressureGenerate),
			newTable("macos_soc_power", socpower.SocPowerColumns(), socpower.SocPowerGenerate),
			newTable("touchid_system_config", touchid.TouchIDSystemConfigColumns(), touchid.TouchIDSystemConfigGenerate),
			newTable("touchid_user_config", touchid.TouchIDUserConfigColumns(), touchid.TouchIDUserConfigGenerate),
		}
		plugins = append(plugins, darwinPlugins...)
	}

	for _, p := range plugins {
		server.RegisterPlugin(p)
	}

	// Start the server. It will run forever unless an error bubbles up.
	if err := server.Run(); err != nil {
		log.Fatalln(err)
	}
}

// newTable registers a table with its generate function wrapped by utils.RecoverPanics, so a
// panic in one table becomes an error for that query instead of ending the process that serves
// every table.
func newTable(name string, columns []table.ColumnDefinition, generate table.GenerateFunc) *table.Plugin {
	return table.NewPlugin(name, columns, utils.RecoverPanics(name, generate))
}
