package alt_system_info_test

import (
	"testing"

	"github.com/macadmins/osquery-extension/pkg/utils"
	alt_system_info "github.com/macadmins/osquery-extension/tables/alt_system_info"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var mockIOReg = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>IORegistryEntryChildren</key>
	<array>
		<dict>
			<key>IOPlatformSerialNumber</key>
			<string>MYSERIAL</string>
			<key>IOPlatformUUID</key>
			<string>F6C0D60A-C485-4E40-A4DC-FE6A38C42CE3</string>
			<key>manufacturer</key>
			<data>
			QXBwbGUgSW5jLgA=
			</data>
			<key>model</key>
			<data>
			TWFjMTQsNQA=
			</data>
			<key>version</key>
			<data>
			MS4wAA==
			</data>
		</dict>
	</array>
	<key>IORegistryEntryID</key>
	<integer>4294967552</integer>
	<key>IORegistryEntryName</key>
	<string>Root</string>
</dict>
</plist> `

var mockSysctl = `machdep.cpu.brand_string: Apple M2 Max
machdep.cpu.core_count: 12
machdep.cpu.thread_count: 12
hw.memsize: 34359738368
`

var mockCmdRunner = &utils.MultiMockCmdRunner{
	Commands: map[string]utils.MockCmdRunner{
		"machine":                                {Output: "arm64e\n"},
		"ioreg -d2 -c IOPlatformExpertDevice -a": {Output: mockIOReg},
		"sysctl machdep.cpu.brand_string machdep.cpu.core_count machdep.cpu.thread_count hw.memsize": {Output: mockSysctl},
		"hostname":                   {Output: "myhostname.local\n"},
		"scutil --get ComputerName":  {Output: "mycomputername\n"},
		"scutil --get LocalHostName": {Output: "mylocalhostname\n"},
	},
}

func TestGetCPUType(t *testing.T) {
	cpuType, err := alt_system_info.GetCPUType(mockCmdRunner)
	require.NoError(t, err)
	assert.Equal(t, "arm64e", cpuType)
}

func TestGetIORegData(t *testing.T) {
	data, err := alt_system_info.GetIORegData(mockCmdRunner)
	require.NoError(t, err)
	assert.Equal(t, "F6C0D60A-C485-4E40-A4DC-FE6A38C42CE3", data.UUID)
	assert.Equal(t, "Apple Inc.", data.HardwareVendor)
	assert.Equal(t, "Mac14,5", data.HardwareModel)
	assert.Equal(t, "1.0", data.HardwareVersion)
	assert.Equal(t, "MYSERIAL", data.HardwareSerial)
}

func TestGetSysctlData(t *testing.T) {
	data, err := alt_system_info.GetSysctlData(mockCmdRunner)
	require.NoError(t, err)
	assert.Equal(t, "Apple M2 Max", data.CPUBrand)
	assert.Equal(t, "12", data.CPUPhysicalCores)
	assert.Equal(t, "12", data.CPULogicalCores)
	assert.Equal(t, "34359738368", data.PhysicalMemory)
}

func TestGetHostData(t *testing.T) {
	data, err := alt_system_info.GetHostData(mockCmdRunner)
	require.NoError(t, err)
	assert.Equal(t, "myhostname.local", data.Hostname)
	assert.Equal(t, "mycomputername", data.ComputerName)
	assert.Equal(t, "mylocalhostname", data.LocalHostname)
}

var (
	isMacOS15Query  = "select * from os_version where name = 'macOS' and major = '15' and minor = 0;"
	systemInfoQuery = "select * from system_info;"
)

func TestIsMacOS15(t *testing.T) {
	mockOsquery := &utils.MockOsqueryClient{
		Data: map[string][]map[string]string{
			isMacOS15Query: {},
		},
	}

	isMacOS15, err := alt_system_info.IsMacOS150(mockOsquery)
	require.NoError(t, err)
	assert.False(t, isMacOS15)

	mockOsquery.Data[isMacOS15Query] = []map[string]string{{"version": "15.0"}}
	isMacOS15, err = alt_system_info.IsMacOS150(mockOsquery)
	require.NoError(t, err)
	assert.True(t, isMacOS15)
}

func TestFallback(t *testing.T) {
	mockOsquery := &utils.MockOsqueryClient{
		Data: map[string][]map[string]string{
			systemInfoQuery: {{"key": "value"}},
		},
	}

	value, err := alt_system_info.Fallback(mockOsquery)
	require.NoError(t, err)
	assert.Equal(t, mockOsquery.Data[systemInfoQuery], value)
}

func TestGenerateInfo(t *testing.T) {
	mockOsquery := &utils.MockOsqueryClienter{
		Data: map[string][]map[string]string{
			isMacOS15Query:  {{"version": "15.0"}},
			systemInfoQuery: {{"key": "value"}},
		},
	}

	// Test with macOS 15.0 multiple times to ensure cache is working
	cache := new(alt_system_info.Cache)
	for i := 0; i < 3; i++ {
		data, err := alt_system_info.GenerateInfo(mockCmdRunner, mockOsquery, cache)
		require.NoError(t, err)
		require.Len(t, data, 1)
		assert.Equal(t, "arm64e", data[0]["cpu_type"])
		assert.Equal(t, "F6C0D60A-C485-4E40-A4DC-FE6A38C42CE3", data[0]["uuid"])
		assert.Equal(t, "Apple Inc.", data[0]["hardware_vendor"])
		assert.Equal(t, "Mac14,5", data[0]["hardware_model"])
		assert.Equal(t, "1.0", data[0]["hardware_version"])
		assert.Equal(t, "MYSERIAL", data[0]["hardware_serial"])
		assert.Equal(t, "Apple M2 Max", data[0]["cpu_brand"])
		assert.Equal(t, "12", data[0]["cpu_physical_cores"])
		assert.Equal(t, "12", data[0]["cpu_logical_cores"])
		assert.Equal(t, "34359738368", data[0]["physical_memory"])
		assert.Equal(t, "myhostname.local", data[0]["hostname"])
		assert.Equal(t, "mycomputername", data[0]["computer_name"])
		assert.Equal(t, "mylocalhostname", data[0]["local_hostname"])
		require.NotNil(t, cache.IsMacOS15)
		assert.True(t, *cache.IsMacOS15)
	}

	// Test not macOS 15.0 multiple times to ensure cache is working
	mockOsquery.Data[isMacOS15Query] = []map[string]string{}
	cache = new(alt_system_info.Cache)
	for i := 0; i < 3; i++ {
		data, err := alt_system_info.GenerateInfo(mockCmdRunner, mockOsquery, cache)
		require.NoError(t, err)
		require.Len(t, data, 1)
		assert.Equal(t, "value", data[0]["key"])
		require.NotNil(t, cache.IsMacOS15)
		assert.False(t, *cache.IsMacOS15)
	}
}
