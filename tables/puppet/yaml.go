package puppet

import (
	"bytes"
	"log"
	"os"
	"runtime"
	"strings"

	"gopkg.in/yaml.v3"
)

func yamlPath() string {
	if runtime.GOOS == "windows" {
		return "C:\\ProgramData\\PuppetLabs\\puppet\\cache\\state\\last_run_report.yaml"
	}

	return "/opt/puppetlabs/puppet/cache/state/last_run_report.yaml"
}

var getPuppetYamlFunc = getPuppetYaml

var puppetYAMLPath = yamlPath

func getPuppetYaml() (*PuppetInfo, error) {
	var yamlData PuppetInfo

	yamlFile, err := os.Open(puppetYAMLPath())
	if err != nil {
		log.Print(err)
		return &yamlData, err
	}
	defer func() {
		if err := yamlFile.Close(); err != nil {
			log.Printf("close Puppet yaml: %v", err)
		}
	}()

	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(yamlFile)
	if err != nil {
		return &yamlData, err
	}

	yamlString := buf.String()
	yamlString = strings.ReplaceAll(yamlString, "\r", "\n")

	err = yaml.Unmarshal([]byte(yamlString), &yamlData)
	if err != nil {
		return &yamlData, err
	}

	return &yamlData, nil
}
