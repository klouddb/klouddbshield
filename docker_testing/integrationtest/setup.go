package main

import (
	"fmt"
	"os"
	"os/exec"
	"sync"

	"github.com/spf13/cobra"
)

// init for setup command
func init() {

	setupCmd := cobra.Command{
		Use:   "setup",
		Short: "it will setup the postgres server for give configuration",

		Run: func(cmd *cobra.Command, args []string) {
			startPostgres()
			createUSers()

			m := map[string]string{
				"user0,user1,user3,user4":  "192.168.0.26",
				"myuser,user2,user3,user4": "192.168.0.27",
				"user0,user2":              "192.168.0.28",
				"user3,user4":              "192.168.0.29",
				"user0,user4":              "192.168.0.30",
			}

			var wg sync.WaitGroup
			for user, ip := range m {
				wg.Add(1)
				go execPgbench(&wg, user, ip)
			}

			wg.Wait()
		},
	}

	setupCmd.Flags().StringVarP(&filesize, "size", "s", "10MB", "to update log file size")
	setupCmd.Flags().IntVarP(&index, "index", "i", 0, "to handle mutiple prefix at once")
	setupCmd.Flags().IntVarP(&timeForPgExecution, "time", "t", 1, "how much time we should execute pgbench command")
	rootCmd.PersistentFlags().StringVarP(&prefix, "prefix", "p", "", "prefix for setup")
	err := rootCmd.MarkPersistentFlagRequired("prefix")
	if err != nil {
		fmt.Println("Got error while marking flag required:", err)
		return
	}

	rootCmd.AddCommand(&setupCmd)

}

func startPostgres() {
	cmd := exec.Command("docker", "compose", "up", "--build", "-d", "postgres")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	cmd.Env = append(os.Environ(),
		"PREFIX="+prefix,
		"FILE_SIZE="+filesize,
		"INDEX="+fmt.Sprint(index),
	)
	err := cmd.Run()
	if err != nil {
		fmt.Println("Got error while starting postgres:", err)
		os.Exit(1)
		return
	}
}

func createUSers() {
	cmd := exec.Command("docker", "compose", "run", "--rm", "createuser")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	cmd.Env = append(os.Environ(),
		"PREFIX="+prefix,
		"FILE_SIZE="+filesize,
		"INDEX="+fmt.Sprint(index),
	)
	err := cmd.Run()
	if err != nil {
		fmt.Println("Got error while creating users:", err)
		os.Exit(1)
		return
	}
}

func execPgbench(wg *sync.WaitGroup, pgUsers, ip string) {
	defer wg.Done()
	fmt.Println("executing pgbench command for users:", pgUsers, "and ip:", ip)
	cmd := exec.Command("docker", "compose", "run", "--rm", "pgbench")
	cmd.Env = append(os.Environ(),
		"PGUSERS="+pgUsers,
		"IP="+ip,
		"PREFIX="+prefix,
		"FILE_SIZE="+filesize,
		"INDEX="+fmt.Sprint(index),
		"TIME="+fmt.Sprint(timeForPgExecution),
	)

	err := cmd.Run()
	if err != nil {
		fmt.Println("Got error while executing pgbench command:", err)
	}
	fmt.Println("pgbench command executed for users:", pgUsers, "and ip:", ip)
}
