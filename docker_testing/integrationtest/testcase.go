package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"

	cons "github.com/klouddb/klouddbshield/pkg/const"
	"github.com/spf13/cobra"
)

// init for testing command
func init() {
	var filename string
	testCmd := cobra.Command{
		Use:   "test",
		Short: "this will test the postgres setup",
		Run: func(cmd *cobra.Command, args []string) {
			testInactiveUser(prefix, filename)
			// testMissingIPs(prefix, filename)
			testUniqueIPs(prefix, filename)
			testUnusedHbaLines(prefix, filename)
		},
	}

	testCmd.Flags().StringVarP(&filename, "file", "f", "", "pass file for testing")
	err := testCmd.MarkFlagRequired("file")
	if err != nil {
		fmt.Println("error while setting required flag:", err)
		os.Exit(1)
	}

	rootCmd.AddCommand(&testCmd)
}

func testUniqueIPs(prefix, file string) {
	cmd := exec.Command("ciscollector",
		"-logparser", cons.LogParserCMD_UniqueIPs,
		"-prefix", prefix,
		"-file-path", file,
		"-output-type", "json",
	)

	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println("execution error from unique_ips:", err)
		os.Exit(1)
	}

	if !strings.Contains(string(out), "Successfully parsed all files") {
		fmt.Println("Successful log is not available in output (unique_ips):", string(out))
		// fail the command
		os.Exit(1)
	}

	if !strings.Contains(string(out), `Unique IPs found from given log file:
[
	"192.168.0.1",
	"192.168.0.25",
	"192.168.0.26",
	"192.168.0.27",
	"192.168.0.28",
	"192.168.0.29",
	"192.168.0.30"
]`) {
		fmt.Println("not getting valid ips in output for unique ips:", string(out))
		os.Exit(1)
	}

	fmt.Println("unique_ip test is working fine for prefix:", prefix)
}

func testInactiveUser(prefix, file string) {
	cmd := exec.Command("ciscollector",
		"-logparser", cons.LogParserCMD_InactiveUsr,
		"-prefix", prefix,
		"-file-path", file,
		"-output-type", "json",
	)

	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println("execution error from inactive_users:", err, string(out))
		os.Exit(1)
	}

	if !strings.Contains(string(out), "Successfully parsed all files") {
		fmt.Println("Successful log is not available in output (inactive_users):", string(out))
		// fail the command
		os.Exit(1)
	}

	if !strings.Contains(string(out), `[
	[
		"myuser",
		"user0",
		"user1",
		"user2",
		"user3",
		"user4",
		"user5"
	],
	[
		"myuser",
		"user0",
		"user1",
		"user2",
		"user3",
		"user4"
	],
	[
		"user5"
	]
]`) {
		fmt.Println("not getting valid users in output (inactive_users):", string(out))
		os.Exit(1)
	}

	fmt.Println("Inactive user test is working fine for prefix:", prefix)
}

// func testMissingIPs(prefix, file string) {
// 	cmd := exec.Command("ciscollector",
// 		"-logparser", cons.LogParserCMD_MismatchIPs,
// 		"-prefix", prefix,
// 		"-file-path", file,
// 		"-output-type", "json",
// 		"-ip-file-path", "./ips.txt",
// 	)

// 	out, err := cmd.CombinedOutput()
// 	if err != nil {
// 		fmt.Println("execution error from mismatch_ips:", err, string(out))
// 		os.Exit(1)
// 	}

// 	if !strings.Contains(string(out), "Successfully parsed all files") {
// 		fmt.Println("Successful message is not available (mismatch_ips):", string(out))
// 		// fail the command
// 		os.Exit(1)
// 	}

// 	if !strings.Contains(string(out), `Mismatch IPs:
// [
// 	"192.168.1.26",
// 	"192.168.2.26",
// 	"192.168.3.26"
// ]`) {
// 		fmt.Println("not getting valid ips in output for missing ips:", string(out))
// 		os.Exit(1)
// 	}

// 	fmt.Println("mismatch ip test is working fine for prefix:", prefix)
// }

func testUnusedHbaLines(prefix, file string) {
	cmd := exec.Command("ciscollector",
		"-logparser", cons.LogParserCMD_HBAUnusedLines,
		"-prefix", prefix,
		"-file-path", file,
		"-output-type", "json",
		"-hba-file", "./pg_hba.conf",
	)

	// create io.Writer to store output and print it later
	var buf bytes.Buffer

	cmd.Stdout = &buf
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	err := cmd.Run()
	if err != nil {
		fmt.Println("Got error while parsing file:", err)
		os.Exit(1)
	}

	out := buf.String()
	if strings.Contains(out, "In logline prefix, please set '%u' and '%d'") || strings.Contains(out, "Please set log_line_prefix to '%h' or '%r' or enable log_connections") {
		fmt.Println("skipping test for unused files as required details are not available in prefix:", prefix)
		return
	}

	if !strings.Contains(out, "Successfully parsed all files") {
		fmt.Println("Got error while parsing file:", out)
		// fail the command
		os.Exit(1)
	}

	if strings.Contains(out, `Unused lines found from given log file: [11 23 28]`) {
		fmt.Println("unused lines test is working fine for prefix:", prefix)
		return
	}

	fmt.Println("not getting valid unused lines:", out)
	os.Exit(1)
}
