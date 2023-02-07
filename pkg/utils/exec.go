package utils

import (
	"bytes"
	"os/exec"

	"github.com/rs/zerolog/log"
)

func ExecBash(script string) (string, string, error) {
	cmd := exec.Command("bash", "-c", script)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err

}
func Exec(name string, args ...string) (outStr, errStr string, err error) {
	cmd := exec.Command(name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	if err != nil {
		log.Print("cmd.Run() failed with", err.Error())
		return
	}
	outStr, errStr = stdout.String(), stderr.String()
	return
}
func CheckAppExists(app string) bool {
	path, err := exec.LookPath(app)
	if err != nil {
		log.Printf("didn't find executable for %s\n", app)
		return false
	}
	log.Printf(app, " executable is in %s\n", path)
	return true
}
