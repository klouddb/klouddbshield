package permissions

import (
	"bytes"
	"context"
	"database/sql"
	"os/exec"

	"github.com/klouddb/klouddbshield/model"
)

// 2.1 Ensure the file permissions mask is correct
func CheckSystemdServiceFiles(store *sql.DB, ctx context.Context) (*model.Result, error) {
	result := &model.Result{
		Control:     "2.1",
		Description: "Ensure the file permissions mask is correct",
	}

	cmd := exec.Command("sudo", "su", "postgres", "-c", "umask")
	var stdout, stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdout = &stdout

	err := cmd.Run()
	switch stdout.String() {
	case "0022\n", "0002\n":
		result.FailReason = "umask for postgres user is " + stdout.String()
		result.Status = "Fail"
	case "":
		result.FailReason = "Unable to fetch umask\nError:	" + err.Error()
		result.Status = "Fail"
	default:
		result.Status = "Pass"
	}

	return result, nil
}
