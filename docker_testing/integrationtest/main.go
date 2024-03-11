// this file is simple go translation of runner.sh. need to work on that to make it use full.

package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

// Define flags
var prefix, filesize string
var index, timeForPgExecution int
var rootCmd = &cobra.Command{}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
	}
}
