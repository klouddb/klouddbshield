package main

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/klouddb/klouddbshield/htmlreport"
	cons "github.com/klouddb/klouddbshield/pkg/const"
	"github.com/klouddb/klouddbshield/pkg/postgresdb"
	"github.com/klouddb/klouddbshield/postgres/calctransactions"
)

type calTransactionRunner struct {
	postgresCnf      *postgresdb.Postgres
	htmlReportHelper *htmlreport.HtmlReportHelper
	printSummary     bool
}

func newCalTransactionRunner(postgresCnf *postgresdb.Postgres, htmlReportHelper *htmlreport.HtmlReportHelper,
	printSummary bool) *calTransactionRunner {
	return &calTransactionRunner{
		postgresCnf:      postgresCnf,
		htmlReportHelper: htmlReportHelper,
		printSummary:     printSummary,
	}
}

func (c *calTransactionRunner) run(_ context.Context) error {
	if c.postgresCnf == nil {
		return fmt.Errorf(cons.Err_PostgresConfig_Missing)
	}

	// connect to db
	postgresStore, _, err := postgresdb.Open(*c.postgresCnf)
	if err != nil {
		return fmt.Errorf("failed to connect to postgres: %v", err)
	}

	defer postgresStore.Close()

	// check cluster
	clusterStats := calctransactions.RunClusterQuery(calctransactions.Autovacuum_alerts_query, postgresStore)

	// check databases
	databaseStats := calctransactions.RunPerDatabaseStats(c.postgresCnf, calctransactions.GET_DATABASE_STATS, postgresStore, clusterStats)

	// calculate the TxID age details
	TxIDAgeDetails, err := calctransactions.GetTxIDAgeDetails(postgresStore)
	if err != nil {
		return fmt.Errorf("failed to get TxID age details: %v", err)
	}
	// println("Please wait for 60 seconds, while we are calculating Transactions Per Seconds for your database server...")

	// calculate the TPS
	TxPerSec, err := calctransactions.GetTxPerSec(postgresStore)
	if err != nil {
		return fmt.Errorf("failed to get Tx per sec: %v", err)
	}

	//  create reports
	data := calctransactions.ReportData{
		ClusterStats:   clusterStats,
		DatabaseStats:  databaseStats,
		TPS:            TxPerSec / 60.00,
		TxIDAgeDetails: TxIDAgeDetails,
	}

	if !c.printSummary {
		fmt.Println(text.Bold.Sprint("Transactions Per Second:"))
		printReport(data)
	}

	c.htmlReportHelper.RegisterCalcTranx(data)

	return nil
}

func printReport(data calctransactions.ReportData) {
	// Initialize a new tab writer
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', tabwriter.Debug)

	// Print cluster stats
	fmt.Fprintln(w, "Cluster Stats:")
	fmt.Fprintf(w, "Oldest Current XID:\t%d\n", data.ClusterStats.OldestCurrentXID)
	fmt.Fprintf(w, "Percent Towards Wraparound:\t%.2f%%\n", data.ClusterStats.PercentTowardsWraparound)
	fmt.Fprintf(w, "Percent Towards Emergency Autovac:\t%.2f%%\n", data.ClusterStats.PercentTowardsEmergencyAutovac)
	fmt.Fprintln(w)

	fmt.Println("============================================================")
	// Print TPS
	fmt.Fprintln(w, "TPS (Transactions Per Second):")
	fmt.Fprintf(w, "%d\n", data.TPS)
	fmt.Fprintln(w)

	fmt.Println("============================================================")

	// Print TxID Age Details
	fmt.Fprintln(w, "TxID Age Details:")
	fmt.Fprintf(w, "Oldest Running Xact Age:\t%.2f\n", data.TxIDAgeDetails.OldestRunningXactAge.Float64)
	fmt.Fprintf(w, "Oldest Prepared Xact Age:\t%.2f\n", data.TxIDAgeDetails.OldestPreparedXactAge.Float64)
	fmt.Fprintf(w, "Oldest Replication Slot Age:\t%.2f\n", data.TxIDAgeDetails.OldestReplicationSlotAge.Float64)
	fmt.Fprintf(w, "Oldest Replica Xact Age:\t%.2f\n", data.TxIDAgeDetails.OldestReplicaXactAge.Float64)
	fmt.Fprintf(w, "Oldest Running Xact Left:\t%.2f\n", data.TxIDAgeDetails.OldestRunningXactLeft.Float64)
	fmt.Fprintf(w, "Oldest Prepared Xact Left:\t%.2f\n", data.TxIDAgeDetails.OldestPreparedXactLeft.Float64)
	fmt.Fprintf(w, "Oldest Replication Slot Left:\t%.2f\n", data.TxIDAgeDetails.OldestReplicationSlotLeft.Float64)
	fmt.Fprintf(w, "Oldest Replica Xact Left:\t%.2f\n", data.TxIDAgeDetails.OldestReplicaXactLeft.Float64)
	fmt.Fprintln(w)

	// Flush the writer
	w.Flush()
}
