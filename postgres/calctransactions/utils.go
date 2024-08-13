package calctransactions

import (
	"database/sql"
	"fmt"
	"log"

	"github.com/klouddb/klouddbshield/pkg/postgresdb"
)

type ClusterStats struct {
	OldestCurrentXID               int
	PercentTowardsWraparound       float32
	PercentTowardsEmergencyAutovac float32
}

type TableStats struct {
	OID          string
	Age          int
	PgSizePretty string
}

type DatabaseStats struct {
	Datname        string
	Age            int32
	CurrentSetting int32
	TableStats     []TableStats
}

type ReportData struct {
	ClusterStats   ClusterStats
	DatabaseStats  []DatabaseStats
	TPS            int64
	TxIDAgeDetails *TxIDAgeDetails
}

type TxIDAgeDetails struct {
	OldestRunningXactAge      sql.NullFloat64
	OldestPreparedXactAge     sql.NullFloat64
	OldestReplicationSlotAge  sql.NullFloat64
	OldestReplicaXactAge      sql.NullFloat64
	OldestRunningXactLeft     sql.NullFloat64
	OldestPreparedXactLeft    sql.NullFloat64
	OldestReplicationSlotLeft sql.NullFloat64
	OldestReplicaXactLeft     sql.NullFloat64
}

func RunClusterQuery(query string, store *sql.DB) ClusterStats {

	var clusterStats ClusterStats

	rows, err := store.Query(query)
	if err != nil {
		log.Fatal("query : ", err)
	}
	defer rows.Close()

	for rows.Next() {
		err := rows.Scan(&clusterStats.OldestCurrentXID, &clusterStats.PercentTowardsWraparound, &clusterStats.PercentTowardsEmergencyAutovac)
		if err != nil {
			log.Fatal(err)
		}
	}

	return clusterStats
}

func RunPerDatabaseStats(postgresCnf *postgresdb.Postgres, query string, store *sql.DB, clusterStats ClusterStats) []DatabaseStats {
	var databaseStats []DatabaseStats

	if clusterStats.PercentTowardsEmergencyAutovac >= 0 {
		db_rows, err := store.Query(GET_DATABASE_STATS)

		if err != nil {
			log.Fatal("query : ", err)
		}

		for db_rows.Next() {
			var database DatabaseStats
			err = db_rows.Scan(&database.Datname, &database.Age, &database.CurrentSetting)
			if err != nil {
				panic(err)
			}
			if database.Datname == "template0" {
				continue
			}

			copyPostgresCnf := *postgresCnf
			copyPostgresCnf.DBName = database.Datname

			database.TableStats, err = getTableStats(&copyPostgresCnf)
			if err != nil {
				log.Fatal(err)
			}
			databaseStats = append(databaseStats, database)
		}
	}
	return databaseStats
}

func getTableStats(postgresCnf *postgresdb.Postgres) ([]TableStats, error) {
	store, _, err := postgresdb.Open(*postgresCnf)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to postgres: %v", err)
	}

	defer store.Close()

	var tableStats []TableStats

	rows, err := store.Query(GET_TABLE_STATS)
	if err != nil {
		log.Fatal(err)
	}
	for rows.Next() {
		var tableStat TableStats
		err = rows.Scan(&tableStat.OID, &tableStat.Age, &tableStat.PgSizePretty)
		if err != nil {
			panic(err)
		}
		tableStats = append(tableStats, tableStat)
	}

	return tableStats, nil
}

func GetTxPerSec(store *sql.DB) (int64, error) {

	var txid1, txid2 int64
	rows, err := store.Query(GET_CURRENT_TX_ID)
	if err != nil {
		return 0, err
	}

	for rows.Next() {
		err = rows.Scan(&txid1)
		if err != nil {
			return 0, err
		}
	}

	// time.Sleep(1 * time.Minute)

	rows, err = store.Query(GET_CURRENT_TX_ID)
	if err != nil {
		return 0, err
	}
	for rows.Next() {
		err = rows.Scan(&txid2)
		if err != nil {
			return 0, err
		}
	}

	return txid2 - txid1, nil
}

func GetTxIDAgeDetails(store *sql.DB) (*TxIDAgeDetails, error) {
	rows, err := store.Query(GET_TXID_AGE_DETAILS)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var details TxIDAgeDetails

	for rows.Next() {
		err := rows.Scan(
			&details.OldestRunningXactAge,
			&details.OldestPreparedXactAge,
			&details.OldestReplicationSlotAge,
			&details.OldestReplicaXactAge,
			&details.OldestRunningXactLeft,
			&details.OldestPreparedXactLeft,
			&details.OldestReplicationSlotLeft,
			&details.OldestReplicaXactLeft,
		)
		if err != nil {
			return nil, err
		}
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return &details, nil
}
