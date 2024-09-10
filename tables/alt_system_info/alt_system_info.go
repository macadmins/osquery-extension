package alt_system_info

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/groob/plist"
	"github.com/macadmins/osquery-extension/pkg/utils"
	"github.com/osquery/osquery-go/plugin/table"
	"golang.org/x/sync/errgroup"
)

func GetCPUType(cmder utils.CmdRunner) (string, error) {
	buf, err := cmder.RunCmd("machine")
	if err != nil {
		return "", fmt.Errorf("could not run machine command: %w", err)
	}
	return strings.TrimSpace(string(buf)), nil
}

type IORegData struct {
	UUID            string
	HardwareVendor  string
	HardwareModel   string
	HardwareVersion string
	HardwareSerial  string
}

func GetIORegData(cmder utils.CmdRunner) (*IORegData, error) {
	type data struct {
		Children []*struct {
			UUID            string `plist:"IOPlatformUUID"`
			HardwareVendor  []byte `plist:"manufacturer"`
			HardwareModel   []byte `plist:"model"`
			HardwareVersion []byte `plist:"version"`
			HardwareSerial  string `plist:"IOPlatformSerialNumber"`
		} `plist:"IORegistryEntryChildren"`
	}

	buf, err := cmder.RunCmd("ioreg", "-d2", "-c", "IOPlatformExpertDevice", "-a")
	if err != nil {
		return nil, fmt.Errorf("could not run ioreg command: %w", err)
	}

	d := new(data)
	if err := plist.Unmarshal(buf, d); err != nil {
		return nil, fmt.Errorf("could not unmarshal plist: %w", err)
	}

	if len(d.Children) == 0 {
		return nil, fmt.Errorf("no children found in IORegistryEntryChildren")
	}

	return &IORegData{
		UUID:            d.Children[0].UUID,
		HardwareVendor:  strings.TrimRight(string(d.Children[0].HardwareVendor), "\x00"),
		HardwareModel:   strings.TrimRight(string(d.Children[0].HardwareModel), "\x00"),
		HardwareVersion: strings.TrimRight(string(d.Children[0].HardwareVersion), "\x00"),
		HardwareSerial:  d.Children[0].HardwareSerial,
	}, nil
}

type SysctlData struct {
	CPUBrand         string
	CPUPhysicalCores string
	CPULogicalCores  string
	PhysicalMemory   string
}

func GetSysctlData(cmder utils.CmdRunner) (*SysctlData, error) {
	keys := []string{
		"machdep.cpu.brand_string",
		"machdep.cpu.core_count",
		"machdep.cpu.thread_count",
		"hw.memsize",
	}

	buf, err := cmder.RunCmd("sysctl", keys...)
	if err != nil {
		return nil, fmt.Errorf("could not run sysctl command: %w", err)
	}

	s := bufio.NewScanner(bytes.NewReader(buf))
	data := new(SysctlData)
	for s.Scan() {
		line := s.Text()
		parts := strings.Split(line, ":")
		if len(parts) != 2 {
			continue
		}
		switch strings.TrimSpace(parts[0]) {
		case "machdep.cpu.brand_string":
			data.CPUBrand = strings.TrimSpace(parts[1])
		case "machdep.cpu.core_count":
			data.CPUPhysicalCores = strings.TrimSpace(parts[1])
		case "machdep.cpu.thread_count":
			data.CPULogicalCores = strings.TrimSpace(parts[1])
		case "hw.memsize":
			data.PhysicalMemory = strings.TrimSpace(parts[1])
		}
	}
	return data, nil
}

type HostData struct {
	Hostname      string
	ComputerName  string
	LocalHostname string
}

func GetHostData(cmder utils.CmdRunner) (*HostData, error) {
	data := new(HostData)

	var wg errgroup.Group
	wg.Go(func() error {
		buf, err := cmder.RunCmd("hostname")
		if err != nil {
			return fmt.Errorf("could not run hostname command: %w", err)
		}
		data.Hostname = strings.TrimSpace(string(buf))
		return nil
	})

	wg.Go(func() error {
		buf, err := cmder.RunCmd("scutil", "--get", "ComputerName")
		if err != nil {
			return fmt.Errorf("could not run scutil --get ComputerName command: %w", err)
		}
		data.ComputerName = strings.TrimSpace(string(buf))
		return nil
	})

	wg.Go(func() error {
		buf, err := cmder.RunCmd("scutil", "--get", "LocalHostName")
		if err != nil {
			return fmt.Errorf("could not run scutil --get LocalHostname command: %w", err)
		}
		data.LocalHostname = strings.TrimSpace(string(buf))
		return nil
	})

	return data, wg.Wait()
}

func AltSystemInfoColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("hostname"),
		table.TextColumn("uuid"),
		table.TextColumn("cpu_type"),
		table.TextColumn("cpu_subtype"),
		table.TextColumn("cpu_brand"),
		table.IntegerColumn("cpu_physical_cores"),
		table.IntegerColumn("cpu_logical_cores"),
		table.IntegerColumn("cpu_sockets"),
		table.BigIntColumn("cpu_microcode"),
		table.TextColumn("physical_memory"),
		table.TextColumn("hardware_vendor"),
		table.TextColumn("hardware_model"),
		table.TextColumn("hardware_version"),
		table.TextColumn("hardware_serial"),
		table.TextColumn("board_vendor"),
		table.TextColumn("board_model"),
		table.TextColumn("board_version"),
		table.TextColumn("board_serial"),
		table.TextColumn("computer_name"),
		table.TextColumn("local_hostname"),
	}
}

// IsMacOS150 returns true if the host is running macOS 15.0
func IsMacOS150(client utils.OsqueryClient) (bool, error) {
	versionQuery := "select * from os_version where name = 'macOS' and major = '15' and minor = 0;"

	resp, err := client.QueryRows(versionQuery)
	if err != nil {
		return false, err
	}

	return len(resp) > 0, nil
}

// Fallback returns the fields from the system_info table
func Fallback(client utils.OsqueryClient) ([]map[string]string, error) {
	infoQuery := "select * from system_info;"

	resp, err := client.QueryRow(infoQuery)
	if err != nil {
		return nil, err
	}
	return []map[string]string{resp}, nil
}

type Cache struct {
	IsMacOS15  *bool
	CPUType    string
	IORegData  *IORegData
	SysctlData *SysctlData
	HostData   *HostData
	lastHost   time.Time
	mu         sync.Mutex
}

// nolint:gochecknoglobals
var globalCache = new(Cache)

// AltSystemInfoGenerate returns system information about the host, mirroring osquery's builtin system_info table.
// Most data is cached forever because it never changes. Hostname data is cached for 5 minutes.
func AltSystemInfoGenerate(ctx context.Context, queryContext table.QueryContext, socketPath string) ([]map[string]string, error) {
	return GenerateInfo(
		utils.NewRunner().Runner,
		&utils.SocketOsqueryClienter{SocketPath: socketPath, Timeout: 10 * time.Second},
		globalCache,
	)
}

func GenerateInfo(
	runner utils.CmdRunner,
	clienter utils.OsqueryClienter,
	cache *Cache,
) ([]map[string]string, error) {
	cache.mu.Lock()
	defer cache.mu.Unlock()

	// If not macOS 15, fallback to system_info table
	if cache.IsMacOS15 != nil && !*cache.IsMacOS15 {
		osqueryClient, err := clienter.NewOsqueryClient()
		if err != nil {
			return nil, fmt.Errorf("could not create osquery client: %w", err)
		}
		defer osqueryClient.Close()

		return Fallback(osqueryClient)
	}

	if cache.IsMacOS15 == nil {
		// this is the first time we're running this query, so check if we're on macOS 15.0
		osqueryClient, err := clienter.NewOsqueryClient()
		if err != nil {
			return nil, fmt.Errorf("could not create osquery client: %w", err)
		}
		defer osqueryClient.Close()

		isMacOS15, err := IsMacOS150(osqueryClient)
		if err != nil {
			return nil, fmt.Errorf("could not determine if host is running macOS 15.0: %w", err)
		}

		cache.IsMacOS15 = &isMacOS15

		// if the host is not running macOS 15.0, fallback to the system_info table
		if !isMacOS15 {
			return Fallback(osqueryClient)
		}
	}

	var wg errgroup.Group
	if cache.CPUType == "" {
		wg.Go(func() error {
			var err error
			cache.CPUType, err = GetCPUType(runner)
			if err != nil {
				return fmt.Errorf("could not get cpu type: %w", err)
			}
			return nil
		})
	}

	if cache.IORegData == nil {
		wg.Go(func() error {
			var err error
			cache.IORegData, err = GetIORegData(runner)
			if err != nil {
				return fmt.Errorf("could not get ioreg data: %w", err)
			}
			return nil
		})
	}

	if cache.SysctlData == nil {
		wg.Go(func() error {
			var err error
			cache.SysctlData, err = GetSysctlData(runner)
			if err != nil {
				return fmt.Errorf("could not get sysctl data: %w", err)
			}
			return nil
		})
	}

	if time.Since(cache.lastHost) > 5*time.Minute {
		wg.Go(func() error {
			var err error
			cache.HostData, err = GetHostData(runner)
			if err != nil {
				return fmt.Errorf("could not get host data: %w", err)
			}
			return nil
		})

	}

	if err := wg.Wait(); err != nil {
		return nil, err
	}

	return []map[string]string{{
		"hostname":           cache.HostData.Hostname,
		"uuid":               cache.IORegData.UUID,
		"cpu_type":           cache.CPUType,
		"cpu_subtype":        "", // always empty
		"cpu_brand":          cache.SysctlData.CPUBrand,
		"cpu_physical_cores": cache.SysctlData.CPUPhysicalCores,
		"cpu_logical_cores":  cache.SysctlData.CPULogicalCores,
		"cpu_sockets":        "", // always empty
		"cpu_microcode":      "", // always empty
		"physical_memory":    cache.SysctlData.PhysicalMemory,
		"hardware_vendor":    cache.IORegData.HardwareVendor,
		"hardware_model":     cache.IORegData.HardwareModel,
		"hardware_version":   cache.IORegData.HardwareVersion,
		"hardware_serial":    cache.IORegData.HardwareSerial,
		"board_vendor":       "", // always empty
		"board_model":        "", // always empty
		"board_version":      "", // always empty
		"board_serial":       "", // always empty
		"computer_name":      cache.HostData.ComputerName,
		"local_hostname":     cache.HostData.LocalHostname,
	}}, nil
}
