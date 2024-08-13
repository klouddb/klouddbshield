package main

import (
	"database/sql"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/klouddb/klouddbshield/pkg/config"
	"github.com/klouddb/klouddbshield/pkg/postgresdb"
	"github.com/spf13/cobra"
)

// //go:embed migrations/*
// var migrationFile embed.FS

func init() {
	var migrationPath string
	generateDataCMD := cobra.Command{
		Use:   "generate-data",
		Short: "Generate PII data in database",
		RunE: func(cmd *cobra.Command, args []string) error {
			return generatePiiDataInDatabase(migrationPath)
		},
	}

	generateDataCMD.Flags().StringVarP(&migrationPath, "migration-path", "m", "./migrations", "Path to migration files")

	rootCmd.AddCommand(&generateDataCMD)
}

func generatePiiDataInDatabase(migrationPath string) error {
	cnf, err := config.LoadConfig()
	if err != nil {
		return err
	}

	postgresStore, _, err := postgresdb.Open(*cnf.Postgres)
	if err != nil {
		return err
	}
	defer postgresStore.Close()

	return RunMigration(postgresStore, cnf.Postgres, migrationPath)
}

func RunMigration(db *sql.DB, cnf *postgresdb.Postgres, migrationPath string) error {
	driver, err := postgres.WithInstance(db, &postgres.Config{})
	if err != nil {
		return err
	}

	m, err := migrate.NewWithDatabaseInstance(
		"file://"+migrationPath,
		cnf.DBName, driver)

	if err != nil {
		return err
	}

	version, dirtyVersion, err := m.Version()
	if err != nil && err != migrate.ErrNilVersion {
		return err
	}

	if dirtyVersion {
		err = m.Force(int(version) - 1)
		if err != nil || err == migrate.ErrNilVersion {
			return err
		}
	}

	err = m.Up()
	if err != nil && err != migrate.ErrNoChange {
		return err
	}

	return nil
}
