package main

import (
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

func testMissingIPs(prefix, file string) {
	cmd := exec.Command("ciscollector",
		"-logparser", cons.LogParserCMD_MismatchIPs,
		"-prefix", prefix,
		"-file-path", file,
		"-output-type", "json",
		"-ip-file-path", "./ips.txt",
	)

	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println("execution error from mismatch_ips:", err, string(out))
		os.Exit(1)
	}

	if !strings.Contains(string(out), "Successfully parsed all files") {
		fmt.Println("Successful message is not available (mismatch_ips):", string(out))
		// fail the command
		os.Exit(1)
	}

	if !strings.Contains(string(out), `Mismatch IPs:
[
	"192.168.1.26",
	"192.168.2.26",
	"192.168.3.26"
]`) {
		fmt.Println("not getting valid ips in output for missing ips:", string(out))
		os.Exit(1)
	}

	fmt.Println("mismatch ip test is working fine for prefix:", prefix)
}
