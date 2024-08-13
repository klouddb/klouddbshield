package main

import (
	"context"
	"runtime"
	"testing"

	"github.com/klouddb/klouddbshield/htmlreport"
	"github.com/klouddb/klouddbshield/pkg/piiscanner"
	"github.com/klouddb/klouddbshield/pkg/postgresdb"
)

func Benchmark_piiDbScaner_run(b *testing.B) {
	runtime.GOMAXPROCS(12)

	for i := 0; i < b.N; i++ {
		pgconfig := &postgresdb.Postgres{
			Host:     "127.0.0.1",
			Port:     "5432",
			User:     "pradip",
			Password: "password",
			DBName:   "pagila",
		}

		piiConfig, err := piiscanner.NewConfig(pgconfig, piiscanner.RunOption_DataScan_String, "", "", "", "", false, false, true)
		if err != nil {
			b.Fatal(err)
		}

		h := newPiiDbScanner(
			pgconfig,
			piiConfig,
			htmlreport.NewHtmlReportHelper())

		err = h.run(context.Background())
		if err != nil {
			b.Fatal(err)
		}
	}
}
