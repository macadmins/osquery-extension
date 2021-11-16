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

	out, err := exec.Command("/usr/bin/fdesetup", "list").Output()

	if err != nil {
		return users, errors.Wrap(err, "fdesetup list")
	}
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		if scanner.Text() == "" {
			continue
		}
		split := strings.Split(scanner.Text(), ",")
		var user FileVaultUser
		user.Username = split[0]
		user.UUID = split[1]
		users = append(users, user)
	}

	return users, nil

}
