package fileline

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kolide/osquery-go/plugin/table"
)

type FileLine struct {
	Line string
	Path string
}

func FileLineColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("line"),
		table.TextColumn("path"),
	}
}

func FileLineGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {

	path := ""

	if constraintList, present := queryContext.Constraints["path"]; present {
		// 'path' is in the where clause
		for _, constraint := range constraintList.Constraints {
			if constraint.Operator == table.OperatorEquals {
				path = constraint.Expression
			}
		}
	}

	output, err := processFile(path)
	if err != nil {
		return nil, err
	}

	return output, nil
}

func processFile(path string) ([]map[string]string, error) {

	var output []map[string]string

	// Replace % for * for glob
	replacedPath := strings.ReplaceAll(path, "%", "*")

	files, err := filepath.Glob(replacedPath)
	if err != nil {
		return nil, err
	}

	for _, file := range files {
		// get slice of lines
		lines, _ := readLines(file)

		for _, line := range lines {
			output = append(output, map[string]string{
				"line": line,
				"path": file,
			})
		}
	}

	return output, nil

}

func readLines(path string) ([]string, error) {
	var output []string
	fmt.Println(path)
	if !fileExists(path) {
		err := errors.New("File does not exist")
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		output = append(output, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return output, nil
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}
