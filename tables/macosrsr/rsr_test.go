package macosrsr

import (
	"context"
	_ "embed"
	"errors"
	"testing"

	"github.com/osquery/osquery-go/plugin/table"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//go:embed test_SystemVersion.plist
var testSystemVersion []byte

func withReadSystemVersionPlistToBytes(t *testing.T, fn func() ([]byte, error)) {
	t.Helper()
	original := readSystemVersionPlistToBytes
	readSystemVersionPlistToBytes = fn
	t.Cleanup(func() {
		readSystemVersionPlistToBytes = original
	})
}

func withRunSwVersCmd(t *testing.T, fn func() ([]byte, error)) {
	t.Helper()
	original := runSwVersCmd
	runSwVersCmd = fn
	t.Cleanup(func() {
		runSwVersCmd = original
	})
}

func TestMacOSRsrColumns(t *testing.T) {
	assert.Equal(t, []table.ColumnDefinition{
		table.TextColumn("rsr_version"),
		table.TextColumn("macos_version"),
		table.TextColumn("full_macos_version"),
		table.TextColumn("rsr_supported"),
	}, MacOSRsrColumns())
}

func TestMacOSRsrGenerate(t *testing.T) {
	t.Parallel()
	type testData struct {
		expectedRows  []map[string]string
		systemVersion SystemVersionPlist
		bytes         []byte
	}

	testCases := []testData{
		{
			systemVersion: SystemVersionPlist{
				ProductVersion:      "13.3.1",
				ProductBuildVersion: "22E261",
			},
			bytes: []byte{40, 97, 41},
			expectedRows: []map[string]string{
				{

					"full_macos_version": "13.3.1 (a)",
					"macos_version":      "13.3.1",
					"rsr_supported":      "true",
					"rsr_version":        "(a)",
				},
			},
		},

		{
			systemVersion: SystemVersionPlist{
				ProductVersion:      "13.3.1",
				ProductBuildVersion: "22E261",
			},
			bytes: []byte{},
			expectedRows: []map[string]string{
				{

					"full_macos_version": "13.3.1",
					"macos_version":      "13.3.1",
					"rsr_supported":      "true",
					"rsr_version":        "",
				},
			},
		},
		{
			systemVersion: SystemVersionPlist{
				ProductVersion:      "12.3.1",
				ProductBuildVersion: "ABC123",
			},
			bytes: []byte{},
			expectedRows: []map[string]string{
				{

					"full_macos_version": "12.3.1",
					"macos_version":      "12.3.1",
					"rsr_supported":      "false",
					"rsr_version":        "",
				},
			},
		},
	}

	for _, test := range testCases {
		isRsrCompatible, err := rsrCompatible(test.systemVersion)
		if err != nil {
			assert.Nil(t, err)
		}

		rsrOutput := buildOutput(test.bytes, test.systemVersion, isRsrCompatible)

		rows := generateResults(rsrOutput)
		assert.Equal(t, rows, test.expectedRows)
	}

}

func TestBuildOutput(t *testing.T) {
	t.Parallel()
	type buildOutputTest struct {
		bytes          []byte
		systemVersion  SystemVersionPlist
		expectedOutput RSROutput
	}
	testCases := []buildOutputTest{
		// rsr installed
		{
			bytes: []byte{40, 97, 41},
			systemVersion: SystemVersionPlist{
				ProductVersion:      "13.3.1",
				ProductBuildVersion: "22E261",
			},
			expectedOutput: RSROutput{
				RSRVersion:   "(a)",
				FullVersion:  "13.3.1 (a)",
				MacOSVersion: "13.3.1",
				RSRSupported: true,
			},
		},
		// rsr not installed
		{
			bytes: []byte{},
			systemVersion: SystemVersionPlist{
				ProductVersion:      "13.3.1",
				ProductBuildVersion: "22E261",
			},
			expectedOutput: RSROutput{
				RSRVersion:   "",
				FullVersion:  "13.3.1",
				MacOSVersion: "13.3.1",
				RSRSupported: true,
			},
		},
	}

	for _, test := range testCases {
		isRsrCompatible, err := rsrCompatible(test.systemVersion)
		if err != nil {
			assert.Nil(t, err)
		}
		rsrOutput := buildOutput(test.bytes, test.systemVersion, isRsrCompatible)
		assert.Equal(t, test.expectedOutput, rsrOutput)
	}

}

func TestUnmarshalSystemVersionBytesToStruct(t *testing.T) {
	t.Parallel()
	expectedOutput := SystemVersionPlist{
		ProductVersion:      "13.3.1",
		ProductBuildVersion: "22E261",
	}

	out, err := unmarshalSystemVersionBytesToStruct(testSystemVersion)
	assert.Nil(t, err, "unmarshalSystemVersionBytesToStruct erorr not nil")

	assert.Equal(t, expectedOutput, out, "output from unmarshalSystemVersionBytesToStruct does not match expected output")
}

func TestUnmarshalSystemVersionBytesToStructInvalidPlist(t *testing.T) {
	t.Parallel()
	out, err := unmarshalSystemVersionBytesToStruct([]byte("not plist"))
	assert.Error(t, err)
	assert.Empty(t, out)
}

func TestGetSystemVersionReadError(t *testing.T) {
	withReadSystemVersionPlistToBytes(t, func() ([]byte, error) {
		return nil, errors.New("read failed")
	})

	out, err := getSystemVersion()
	assert.Error(t, err)
	assert.Empty(t, out)
	assert.ErrorContains(t, err, "readSystemVersionPlistToBytes")
}

func TestMacOSRsrGenerateSupportedWithRsr(t *testing.T) {
	withReadSystemVersionPlistToBytes(t, func() ([]byte, error) {
		return testSystemVersion, nil
	})
	withRunSwVersCmd(t, func() ([]byte, error) {
		return []byte("(a)\n"), nil
	})

	rows, err := MacOSRsrGenerate(context.Background(), table.QueryContext{})
	require.NoError(t, err)
	assert.Equal(t, []map[string]string{{
		"full_macos_version": "13.3.1 (a)",
		"macos_version":      "13.3.1",
		"rsr_supported":      "true",
		"rsr_version":        "(a)",
	}}, rows)
}

func TestMacOSRsrGenerateUnsupportedSkipsSwVers(t *testing.T) {
	withReadSystemVersionPlistToBytes(t, func() ([]byte, error) {
		return []byte(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>ProductVersion</key><string>12.6.1</string>
<key>ProductBuildVersion</key><string>21G217</string>
</dict></plist>`), nil
	})
	swVersCalled := false
	withRunSwVersCmd(t, func() ([]byte, error) {
		swVersCalled = true
		return []byte("(a)\n"), nil
	})

	rows, err := MacOSRsrGenerate(context.Background(), table.QueryContext{})
	require.NoError(t, err)
	assert.False(t, swVersCalled)
	assert.Equal(t, []map[string]string{{
		"full_macos_version": "12.6.1",
		"macos_version":      "12.6.1",
		"rsr_supported":      "false",
		"rsr_version":        "",
	}}, rows)
}

func TestMacOSRsrGenerateSwVersError(t *testing.T) {
	withReadSystemVersionPlistToBytes(t, func() ([]byte, error) {
		return testSystemVersion, nil
	})
	withRunSwVersCmd(t, func() ([]byte, error) {
		return nil, errors.New("sw_vers failed")
	})

	rows, err := MacOSRsrGenerate(context.Background(), table.QueryContext{})
	assert.Error(t, err)
	assert.Nil(t, rows)
	assert.ErrorContains(t, err, "run sw_vers command")
}

func TestMacOSRsrGenerateCompatibilityError(t *testing.T) {
	withReadSystemVersionPlistToBytes(t, func() ([]byte, error) {
		return []byte(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>ProductVersion</key><string>not-a-version</string>
</dict></plist>`), nil
	})

	rows, err := MacOSRsrGenerate(context.Background(), table.QueryContext{})
	assert.Error(t, err)
	assert.Nil(t, rows)
	assert.ErrorContains(t, err, "rsrCompatible")
}

func TestRsrCompatible(t *testing.T) {
	type testData struct {
		input          SystemVersionPlist
		expectedOutput bool
		shouldErr      bool
	}

	tests := []testData{
		{
			input:          SystemVersionPlist{ProductVersion: "13.3.1"},
			expectedOutput: true,
			shouldErr:      false,
		},
		{
			input:          SystemVersionPlist{ProductVersion: "12.3.1"},
			expectedOutput: false,
			shouldErr:      false,
		},
		{
			input:          SystemVersionPlist{ProductVersion: "14.3.1"},
			expectedOutput: true,
			shouldErr:      false,
		},
		{
			input:          SystemVersionPlist{ProductVersion: "abc123"},
			expectedOutput: false,
			shouldErr:      true,
		},
	}

	for _, test := range tests {
		out, err := rsrCompatible(test.input)
		if test.shouldErr {
			// we expect this to fail
			assert.NotNil(t, err)
		} else {
			assert.Nil(t, err)
		}

		assert.Equal(t, out, test.expectedOutput, test.input)

	}
}
