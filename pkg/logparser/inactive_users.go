package logparser

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"

	"github.com/klouddb/klouddbshield/pkg/config"
	"github.com/klouddb/klouddbshield/pkg/parselog"
	"github.com/klouddb/klouddbshield/pkg/utils"
)

type InactiveUsersHelper struct {
	*parselog.UniqueUserParser
	store *sql.DB

	finalResult [][]string
}

func NewInactiveUsersHelper(store *sql.DB) *InactiveUsersHelper {
	return &InactiveUsersHelper{store: store}
}

func (i *InactiveUsersHelper) Init(ctx context.Context, cnf *config.Config, baseParser parselog.BaseParser) error {
	// check if postgres setting contains required variable or connection logs
	if !strings.Contains(cnf.LogParser.PgSettings.LogLinePrefix, "%u") && !cnf.LogParser.PgSettings.LogConnections {
		return fmt.Errorf("Please set log_line_prefix to '%%u' or enable log_connections")
	}

	i.UniqueUserParser = parselog.NewUserParser(cnf, baseParser)
	return nil
}

func (i *InactiveUsersHelper) CalculateResult(ctx context.Context) error {
	uniqueUsers := i.GetUniqueUser()

	usersFromLog := sort.StringSlice{}
	for user := range uniqueUsers {
		usersFromLog = append(usersFromLog, user)
	}
	usersFromLog.Sort()

	if i.store == nil {
		i.finalResult = [][]string{nil, usersFromLog, nil}
		return nil
	}

	usersFromDb, err := utils.GetPGUsers(ctx, i.store)

	inactiveUsers := sort.StringSlice{}
	for _, user := range usersFromDb {
		_, ok := uniqueUsers[user]
		if !ok {
			inactiveUsers = append(inactiveUsers, user)
		}
	}
	inactiveUsers.Sort()

	if err != nil {
		usersFromDb = []string{"Error fetching users from DB " + err.Error()}
	}

	i.finalResult = [][]string{usersFromDb, usersFromLog, inactiveUsers}
	return nil
}

func (i *InactiveUsersHelper) GetResult(ctx context.Context) [][]string {
	return i.finalResult
}
