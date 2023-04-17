package filevaultusers

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/osquery/osquery-go/plugin/table"
	"github.com/pkg/errors"
)

// FileVaultUsers
type FileVaultUser struct {
	Username string
	UUID     string
}

func FileVaultUsersColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("username"),
		table.TextColumn("uuid"),
	}
}

// Generate will be called whenever the table is queried. Since our data in these
// plugins is flat it will return a single row.
func FileVaultUsersGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	var results []map[string]string
	users, err := getFileVaultUsers()
	if err != nil {
		fmt.Println(err)
		return results, err
	}

	for _, item := range users {
		results = append(results, map[string]string{
			"username": item.Username,
			"uuid":     item.UUID,
		})
	}

	return results, nil
}

func getFileVaultUsers() ([]FileVaultUser, error) {
	var users []FileVaultUser

	bytes, err := runFDESetupList()

	if err != nil {
		return users, errors.Wrap(err, "runFDESetupList")
	}

	users, err = processFDESetupToUsers(bytes)
	if err != nil {
		return users, errors.Wrap(err, "processFDESetupToUsers")
	}

	return users, nil

}

func runFDESetupList() ([]byte, error) {
	var out []byte
	out, err := exec.Command("/usr/bin/fdesetup", "list").Output()

	if err != nil {
		return out, errors.Wrap(err, "fdesetup list")
	}

	return out, nil
}

func processFDESetupToUsers(bytes []byte) ([]FileVaultUser, error) {
	var users []FileVaultUser
	scanner := bufio.NewScanner(strings.NewReader(string(bytes)))
	for scanner.Scan() {
		if scanner.Text() == "" {
			continue
		}
		split := strings.Split(scanner.Text(), ",")
		if len(split) != 2 {
			err := errors.New("Split string does not contain exactly two elements")
			return users, err
		}
		var user FileVaultUser
		user.Username = split[0]
		user.UUID = split[1]
		users = append(users, user)
	}

	return users, nil
}
