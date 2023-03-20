package permissions

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/klouddb/klouddbshield/model"
	cons "github.com/klouddb/klouddbshield/pkg/const"
	"github.com/klouddb/klouddbshield/pkg/utils"
)

// 2.1 Ensure the file permissions mask is correct
func CheckSystemdServiceFiles(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:   "2.1",
		Title:     "Ensure the file permissions mask is correct",
		Rationale: `The Linux OS defaults the umask to 002, which means the owner and primary group can read and write the file, and other accounts are permitted to read the file.`,
		Procedure: `# whoami
		root
		# su - postgres
		# whoami
		postgres
		# umask
		0022
		As discussed above umask of 077 can help`,
		References: `CIS PostgreSQL 13 Benchmark
v1.0.0 - 02-26-2021`,
		Description: "The postgres user account should use a umask of 077 to deny file access to all user accounts except the owner.",
	}
	cmd := "su -c 'umask' -l postgres"

	out, errStr, err := utils.ExecBash(cmd)
	if errStr != "" && err != nil {
		result.FailReason = fmt.Sprintf(cons.ErrFmt, cmd, err.Error(), errStr)
		result.Status = "Fail"
		return result, nil
	}
	if strings.Contains(out, "0022") || strings.Contains(out, "0002") {
		result.FailReason = "umask for postgres user is " + out
		result.Status = "Fail"
		return result, nil
	}
	if out == "" {
		result.FailReason = "Unable to fetch umask"
		result.Status = "Fail"
		return result, nil
	}

	result.Status = "Pass"
	return result, nil
}
