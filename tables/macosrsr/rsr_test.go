package macosrsr

import (
	_ "embed"
	"testing"

	"github.com/stretchr/testify/assert"
)

//go:embed test_sw_vers_output.txt
var testSwVersOutput []byte

//go:embed test_SystemVersion.plist
var testSystemVersion []byte

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
					"rsr_compatible":     "true",
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
					"rsr_compatible":     "true",
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
					"rsr_compatible":     "false",
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
