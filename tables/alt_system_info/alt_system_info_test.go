package alt_system_info_test

import (
	"errors"
	"testing"

	"github.com/macadmins/osquery-extension/pkg/utils"
	alt_system_info "github.com/macadmins/osquery-extension/tables/alt_system_info"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type errorOsqueryClienter struct {
	err error
}

func (e errorOsqueryClienter) NewOsqueryClient() (utils.OsqueryClient, error) {
	return nil, e.err
}

type errorOsqueryClient struct {
	rowsErr error
	rowErr  error
}

func (e errorOsqueryClient) QueryRows(query string) ([]map[string]string, error) {
	return nil, e.rowsErr
}

func (e errorOsqueryClient) QueryRow(query string) (map[string]string, error) {
	return nil, e.rowErr
}

func (e errorOsqueryClient) Close() {}

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

func TestGetCPUTypeCommandError(t *testing.T) {
	_, err := alt_system_info.GetCPUType(utils.MockCmdRunner{Err: errors.New("machine failed")})
	require.Error(t, err)
	assert.ErrorContains(t, err, "could not run machine command")
	assert.ErrorContains(t, err, "machine failed")
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

func TestGetIORegDataErrors(t *testing.T) {
	t.Run("command error", func(t *testing.T) {
		_, err := alt_system_info.GetIORegData(utils.MockCmdRunner{Err: errors.New("ioreg failed")})
		require.Error(t, err)
		assert.ErrorContains(t, err, "could not run ioreg command")
	})

	t.Run("invalid plist", func(t *testing.T) {
		_, err := alt_system_info.GetIORegData(utils.MockCmdRunner{Output: "not plist"})
		require.Error(t, err)
		assert.ErrorContains(t, err, "could not unmarshal plist")
	})

	t.Run("no children", func(t *testing.T) {
		plistWithoutChildren := `<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict></dict></plist>`
		_, err := alt_system_info.GetIORegData(utils.MockCmdRunner{Output: plistWithoutChildren})
		require.Error(t, err)
		assert.ErrorContains(t, err, "no children found")
	})
}

func TestGetSysctlData(t *testing.T) {
	data, err := alt_system_info.GetSysctlData(mockCmdRunner)
	require.NoError(t, err)
	assert.Equal(t, "Apple M2 Max", data.CPUBrand)
	assert.Equal(t, "12", data.CPUPhysicalCores)
	assert.Equal(t, "12", data.CPULogicalCores)
	assert.Equal(t, "34359738368", data.PhysicalMemory)
}

func TestGetSysctlDataCommandError(t *testing.T) {
	_, err := alt_system_info.GetSysctlData(utils.MockCmdRunner{Err: errors.New("sysctl failed")})
	require.Error(t, err)
	assert.ErrorContains(t, err, "could not run sysctl command")
}

func TestGetSysctlDataIgnoresMalformedLines(t *testing.T) {
	data, err := alt_system_info.GetSysctlData(utils.MockCmdRunner{Output: `ignored line
machdep.cpu.brand_string: Apple M3
too:many:colons
hw.memsize: 17179869184
`})
	require.NoError(t, err)
	assert.Equal(t, "Apple M3", data.CPUBrand)
	assert.Equal(t, "17179869184", data.PhysicalMemory)
	assert.Empty(t, data.CPUPhysicalCores)
	assert.Empty(t, data.CPULogicalCores)
}

func TestGetHostData(t *testing.T) {
	data, err := alt_system_info.GetHostData(mockCmdRunner)
	require.NoError(t, err)
	assert.Equal(t, "myhostname.local", data.Hostname)
	assert.Equal(t, "mycomputername", data.ComputerName)
	assert.Equal(t, "mylocalhostname", data.LocalHostname)
}

func TestGetHostDataCommandError(t *testing.T) {
	runner := &utils.MultiMockCmdRunner{
		Commands: map[string]utils.MockCmdRunner{
			"hostname":                   {Output: "myhostname.local\n"},
			"scutil --get ComputerName":  {Err: errors.New("scutil failed")},
			"scutil --get LocalHostName": {Output: "mylocalhostname\n"},
		},
	}

	_, err := alt_system_info.GetHostData(runner)
	require.Error(t, err)
	assert.ErrorContains(t, err, "could not run scutil --get ComputerName command")
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

func TestIsMacOS15QueryError(t *testing.T) {
	_, err := alt_system_info.IsMacOS150(errorOsqueryClient{rowsErr: errors.New("query failed")})
	require.Error(t, err)
	assert.ErrorContains(t, err, "query failed")
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

func TestFallbackQueryError(t *testing.T) {
	_, err := alt_system_info.Fallback(errorOsqueryClient{rowErr: errors.New("system_info failed")})
	require.Error(t, err)
	assert.ErrorContains(t, err, "system_info failed")
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

func TestGenerateInfoClientCreationError(t *testing.T) {
	_, err := alt_system_info.GenerateInfo(
		mockCmdRunner,
		errorOsqueryClienter{err: errors.New("socket unavailable")},
		new(alt_system_info.Cache),
	)
	require.Error(t, err)
	assert.ErrorContains(t, err, "could not create osquery client")
}

func TestGenerateInfoCommandError(t *testing.T) {
	mockOsquery := &utils.MockOsqueryClienter{
		Data: map[string][]map[string]string{
			isMacOS15Query: {{"version": "15.0"}},
		},
	}
	runner := &utils.MultiMockCmdRunner{
		Commands: map[string]utils.MockCmdRunner{
			"machine":                                {Err: errors.New("machine failed")},
			"ioreg -d2 -c IOPlatformExpertDevice -a": {Output: mockIOReg},
			"sysctl machdep.cpu.brand_string machdep.cpu.core_count machdep.cpu.thread_count hw.memsize": {Output: mockSysctl},
			"hostname":                   {Output: "myhostname.local\n"},
			"scutil --get ComputerName":  {Output: "mycomputername\n"},
			"scutil --get LocalHostName": {Output: "mylocalhostname\n"},
		},
	}

	_, err := alt_system_info.GenerateInfo(runner, mockOsquery, new(alt_system_info.Cache))
	require.Error(t, err)
	assert.ErrorContains(t, err, "could not get cpu type")
}
