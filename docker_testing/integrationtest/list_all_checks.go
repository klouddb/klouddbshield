package main

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"

	"github.com/klouddb/klouddbshield/pkg/postgresdb"
	"github.com/klouddb/klouddbshield/pkg/utils"
	"github.com/klouddb/klouddbshield/postgres"
	"github.com/spf13/cobra"
)

// init for setup command
func init() {

	type report struct {
		Group       string `json:"group"`
		Number      string `json:"number"`
		Description string `json:"description"`
	}

	createReportListForVersion := func(version string) ([]report, error) {
		postgresStore, _, err := postgresdb.Open(postgresdb.Postgres{
			Host:     "127.0.0.1",
			Port:     "5432",
			User:     "pradip",
			Password: "password",
			DBName:   "testing",
		})
		if err != nil {
			return nil, err
		}

		results, _, err := postgres.PerformAllChecks(postgresStore, rootCmd.Context(), version, utils.NewDummyContainsAllSet[string]())
		if err != nil {
			return nil, err
		}

		titleReports := []report{
			{
				Group:       "CIS Benchmark",
				Number:      "1",
				Description: "Installation and Patches",
			},
			{
				Group:       "CIS Benchmark",
				Number:      "2",
				Description: "Directory and File Permissions",
			},
			{
				Group:       "CIS Benchmark",
				Number:      "3",
				Description: "Logging Monitoring and Auditing",
			},
			{
				Group:       "CIS Benchmark",
				Number:      "4",
				Description: "User Access and Authorization",
			},
			{
				Group:       "CIS Benchmark",
				Number:      "5",
				Description: "Connection and Login",
			},
			{
				Group:       "CIS Benchmark",
				Number:      "6",
				Description: "Postgres Settings",
			},
			{
				Group:       "CIS Benchmark",
				Number:      "7",
				Description: "Replication",
			},
			{
				Group:       "CIS Benchmark",
				Number:      "8",
				Description: "Special Configuration Considerations",
			},
		}
		titleAdded := map[int]bool{}

		var reports []report
		for _, result := range results {
			title, err := strconv.Atoi(strings.Split(result.Control, ".")[0])
			if err != nil {
				return nil, err
			}

			if _, ok := titleAdded[title]; !ok {
				reports = append(reports, titleReports[title-1])
				titleAdded[title] = true
			}

			reports = append(reports, report{
				Group:       "CIS Benchmark",
				Number:      result.Control,
				Description: result.Title,
			})
		}

		return reports, nil
	}

	listcheck := cobra.Command{
		Use:   "list-all-checks",
		Short: "it will list all postgres cis checks we support",

		RunE: func(cmd *cobra.Command, args []string) error {
			m := map[string][]report{}

			for _, version := range []string{"13", "14", "15", "16"} {
				reports, err := createReportListForVersion(version)
				if err != nil {
					return err
				}

				m[version] = reports
			}

			f, err := os.Create("all_checks.json")
			if err != nil {
				return err
			}
			defer f.Close()

			return json.NewEncoder(f).Encode(m)
		},
	}

	rootCmd.AddCommand(&listcheck)

}
