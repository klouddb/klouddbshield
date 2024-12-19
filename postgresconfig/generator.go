package postgresconfig

import (
	_ "embed"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
)

const (
	DiskType_SSD = 1
	DiskType_HDD = 2
	DiskType_SAN = 3
)

//go:embed examplepostgres.conf
var examplePostgresConf string

// Helper function to safely get an integer from interface{}
func getInt(input interface{}) (int, error) {
	switch v := input.(type) {
	case int:
		return v, nil
	case int64:
		return int(v), nil
	case float64:
		return int(v), nil
	case string:
		return strconv.Atoi(v)
	default:
		return 0, fmt.Errorf("expected int, got %T", v)
	}
}

func getFloat(input interface{}) (float64, error) {
	i, err := getInt(input)
	if err != nil {
		return 0, err
	}
	return float64(i), nil
}

// Calculates the nearest power of two for a given number, adjusting for non-negative values.
// func nearestPowerOfTwo(num float64) float64 {
// 	if num < 0 {
// 		num = -num
// 	}
// 	base := 1.0
// 	for base < num {
// 		if num-base < math.Floor(base/2) {
// 			return base
// 		}
// 		base *= 2
// 	}
// 	return base
// }

// SelectWorkerMem
// Selects the worker memory based on total memory, shared buffers, max connections, and parallel settings
func calculateWorkerMem(totalRam, sharedBuffersValue, maxConnectionsValue int, dbType int) int {

	// Ram passed in GB, convert to KB
	// 1 GB = 1048576 KB

	workMemValue := (totalRam*1048576 - sharedBuffersValue) / (maxConnectionsValue * 3)
	printTestLog("Work Mem: (totalRam*1048576 - sharedBuffersValue) / (maxConnectionsValue * 3) = (%d*1048576 - %d) / (%d * 3) = %d", totalRam, sharedBuffersValue, maxConnectionsValue, workMemValue)

	var workMemResult int
	switch dbType {
	case 1: // web
		workMemResult = workMemValue
		printTestLog("\tfor web setting workMemResult to %d", workMemResult)

	case 2: // oltp
		workMemResult = workMemValue
		printTestLog("\tfor oltp setting workMemResult to %d", workMemResult)

	case 3: // data warehouse
		workMemResult = workMemValue / 2
		printTestLog("\tfor data warehouse setting workMemResult to %d", workMemResult)

	case 4: // desktop
		workMemResult = workMemValue / 6
		printTestLog("\tfor desktop setting workMemResult to %d", workMemResult)

	case 5: // mixed
		workMemResult = workMemValue / 2
		printTestLog("\tfor mixed setting workMemResult to %d", workMemResult)

	default:
		workMemResult = workMemValue
		printTestLog("\tfor unknown setting workMemResult to %d", workMemResult)
	}

	if workMemResult < 4096 {
		workMemResult = 4096
		printTestLog("\tworkMemResult < 4096 so setting to 4096")
	}

	return workMemResult
}

// Helper function to parse sizes like "1GB" or "1TB" into GB units
func parseSize(sizeStr string) int {
	sizeStr = strings.TrimSpace(sizeStr)
	if strings.HasSuffix(sizeStr, "GB") {
		valueStr := strings.TrimSuffix(sizeStr, "GB")
		value, _ := strconv.Atoi(valueStr)
		return value
	} else if strings.HasSuffix(sizeStr, "TB") {
		valueStr := strings.TrimSuffix(sizeStr, "TB")
		value, _ := strconv.Atoi(valueStr)
		return value * 1024 // Convert TB to GB
	}
	return 0 // Default to 0 if parsing fails
}

// ConfigGenerator generates a PostgreSQL configuration string based on various parameters.
func ConfigGenerator(inputMap map[string]string) string {

	printTestLog("Starting config generation calculations...")

	// Extract and type assert values from inputMap
	version, err := getInt(inputMap["version"])
	if err != nil {
		fmt.Println("Error parsing 'version':", err)
		return ""
	}

	ram := parseSize(inputMap["ram"])

	cpu, err := getInt(inputMap["cpu"])
	if err != nil {
		fmt.Println("Error parsing 'cpu':", err)
		return ""
	}

	diskType, err := getInt(inputMap["diskType"])
	if err != nil {
		fmt.Println("Error parsing 'diskType':", err)
		return ""
	}

	// databaseSize := parseSize(inputMap["databaseSize"])

	dbType, err := getInt(inputMap["dbType"])
	if err != nil {
		fmt.Println("Error parsing 'dbType':", err)
		return ""
	}

	replicas, err := getInt(inputMap["replica"])
	if err != nil {
		fmt.Println("Error parsing 'replica':", err)
		return ""
	}

	maxWalSize, err := getFloat(inputMap["max_wal_size"])
	if err != nil {
		fmt.Println("Error parsing 'max_wal_size':", err)
		return ""
	}
	if maxWalSize < 512 {
		maxWalSize = 512
		printTestLog("Max Wal Size is less than 512MB so setting to 512MB")
	}

	// Determine the number of connections based on the database type
	var connections int
	var defaultStatisticsTarget int
	switch dbType {
	case 1: // web
		connections = 200
		defaultStatisticsTarget = 100
		printTestLog("Database type is web so setting connections to %d and defaultStatisticsTarget to %d", connections, defaultStatisticsTarget)

	case 2: // oltp
		connections = 300
		defaultStatisticsTarget = 100
		printTestLog("Database type is oltp so setting connections to %d and defaultStatisticsTarget to %d", connections, defaultStatisticsTarget)

	case 3: // data warehouse
		connections = 40
		defaultStatisticsTarget = 500
		printTestLog("Database type is data warehouse so setting connections to %d and defaultStatisticsTarget to %d", connections, defaultStatisticsTarget)

	case 4: // desktop
		connections = 20
		defaultStatisticsTarget = 100
		printTestLog("Database type is desktop so setting connections to %d and defaultStatisticsTarget to %d", connections, defaultStatisticsTarget)

	case 5: // mixed
		connections = 100
		defaultStatisticsTarget = 100
		printTestLog("Database type is mixed so setting connections to %d and defaultStatisticsTarget to %d", connections, defaultStatisticsTarget)

	default:
		connections = 100 // Default value
		defaultStatisticsTarget = 100
		printTestLog("Database type is unknown so setting connections to %d and defaultStatisticsTarget to %d", connections, defaultStatisticsTarget)
	}

	// Shared_buffers
	// sharedBuffers = 1/4 * ram
	// if sharedBuffers > databaseSize * 1024 { sharedBuffers = databaseSize * 1024 }
	sharedBuffers := int(math.Round(float64(1024*ram) / 4))
	printTestLog("Shared Buffers: RAM/4 : (%d*1024)/4 = %d", ram, sharedBuffers)

	// Work_mem
	workMem := calculateWorkerMem(ram, int(sharedBuffers), connections, dbType)
	printTestLog("Work Mem: calculateWorkerMem(%d, %d, %d, %d) = %d\n", ram, sharedBuffers, connections, dbType, workMem)

	// maintenance_work_mem
	// Total RAM * 0.05
	// if maintenanceWorkMem < 64MB { maintenanceWorkMem = 64MB }

	maintenanceWorkMem := math.Round(float64(ram*1024) * 0.05)
	printTestLog("Maintenance Work Mem: RAM*1024*0.05 = %d*1024*0.05 = %f", ram, maintenanceWorkMem)

	if maintenanceWorkMem < 64 {
		maintenanceWorkMem = 64
		printTestLog("Maintenance Work Mem is less than 64MB so setting to 64MB")
	}
	printTestLog("\n")

	hugePages := "off"
	if ram >= 32 {
		hugePages = "'try' # NOTE- You also need to make linux level changes https://www.postgresql.org/docs/current/static/kernel-resources.html#LINUX-HUGE-PAGES'"
		printTestLog("Huge Pages: RAM >= 32 so setting to 'try'")
	} else {
		printTestLog("Huge Pages: RAM < 32 so setting to 'off'")
	}
	printTestLog("\n")

	// Effective_cache_size
	// 3/4 * RAM
	effectiveCacheSize := math.Round(float64(ram) * 0.75)
	printTestLog("Effective Cache Size: RAM*0.75 = %d*0.75 = %f", ram, effectiveCacheSize)
	printTestLog("\n")

	// Effective_io_concurrency
	// 200 for SSD
	// 2 for HDD
	// 3 for SAN
	var effectiveIOConcurrency float64
	switch diskType {
	case DiskType_SSD:
		effectiveIOConcurrency = 200
		printTestLog("Disk Type is SSD so setting effectiveIOConcurrency to 200")

	case DiskType_HDD:
		effectiveIOConcurrency = 2
		printTestLog("Disk Type is HDD so setting effectiveIOConcurrency to 2")

	case DiskType_SAN:
		effectiveIOConcurrency = 300
		printTestLog("Disk Type is SAN so setting effectiveIOConcurrency to 300")
	}
	printTestLog("\n")

	// randomPageCost
	// 1.1 for SSD
	// 4.0 for HDD
	randomPageCost := 1.1
	if diskType == DiskType_HDD {
		randomPageCost = 4.0
		printTestLog("Disk Type is HDD so setting randomPageCost to 4.0")
	} else {
		printTestLog("Disk Type is not HDD so setting randomPageCost to 1.1")
	}
	printTestLog("\n")

	// walLevel := "replica"
	maxWalSenders := math.Max(10, float64(replicas+4))
	printTestLog("Max Wal Senders: math.Max(10, replicas+4) = math.Max(10, %d+4) = %f", replicas, maxWalSenders)
	printTestLog("\n")

	// SKIPPED
	// TODO
	minWalSize := maxWalSize / 2 // Adjust as needed
	printTestLog("Min Wal Size: maxWalSize/2 = %f/2 = %f", maxWalSize, minWalSize)
	if minWalSize < 512 {
		minWalSize = 512
		printTestLog("Min Wal Size is less than 512MB so setting to 512MB")
	}

	walKeepSegments := math.Ceil((100+maxWalSize*2)/16/10) * 10
	printTestLog("Wal Keep Segments: (100+maxWalSize*2)/16/10 = (100+%f*2)/16/10 = %f", maxWalSize, walKeepSegments)

	walKeepSize := math.Ceil((100*16+maxWalSize*2)/10) * 10
	printTestLog("Wal Keep Size: (100*16+maxWalSize*2)/10 = (100*16+%f*2)/10 = %f", maxWalSize, walKeepSize)
	walLevel := inputMap["wal_level"]
	walArchiving := ""
	if walLevel != "minimal" {
		walArchiving = "\n# WAL archiving\narchive_mode=on\narchive_command='/bin/true'\n"
		printTestLog("WAL Archiving: walLevel != 'minimal' so setting to on")
	} else {
		printTestLog("WAL Level is minimal so not setting WAL Archiving and setting Max WAL Senders as 0")
		maxWalSenders = 0
	}
	printTestLog("\n")

	replication := ""
	if replicas > 0 {
		if version >= 13 {
			replication = fmt.Sprintf("wal_keep_size='%.0f MB'\n", walKeepSize)
			printTestLog("replica > 0 and version >= 13 so setting WAL Keep Size to %.0f MB", walKeepSize)
		} else {
			replication = fmt.Sprintf("wal_keep_segments=%.0f\n", walKeepSegments)
			printTestLog("replica > 0 and version < 13 so setting WAL Keep Segments to %.0f", walKeepSegments)
		}
	}
	printTestLog("\n")

	parallel := ""
	// advanced := ""
	if version > 10 {
		printTestLog("Version is greater than 10 so setting parallel settings")

		maxParallelWorkersPerGather := cpu / 2
		parallel = fmt.Sprintf(
			"max_worker_processes=%d\nmax_parallel_workers_per_gather=%d\nmax_parallel_maintenance_workers=%d\nmax_parallel_workers=%d\nparallel_leader_participation=on",
			cpu,
			maxParallelWorkersPerGather,
			maxParallelWorkersPerGather,
			cpu,
		)
		printTestLog("\tParallel Settings: max_worker_processes=%d\nmax_parallel_workers_per_gather=%d\nmax_parallel_maintenance_workers=%d\nmax_parallel_workers=%d\nparallel_leader_participation=on",
			cpu,
			maxParallelWorkersPerGather,
			maxParallelWorkersPerGather,
			cpu,
		)

		// advanced = "enable_partitionwise_join=on\nenable_partitionwise_aggregate=on"
		// printTestLog("\tAdvanced Settings: enable_partitionwise_join=on\n\t\tenable_partitionwise_aggregate=on")

		// if inputMap["jit"] == "on" {
		// 	advanced += "\njit=on"
		// 	printTestLog("\tAdvanced Settings: jit=on")
		// }

		// if version >= 14 {
		// printTestLog("Version is greater than or equal to 14 so setting max slot wal keep size and track wal io timing")

		// maxSlotWalKeepSize := math.Max(float64(databaseSize)*0.1, 1000)
		// printTestLog("\tMax Slot Wal Keep Size: math.Max(databaseSize*0.1, 1000) = math.Max(%d*0.1, 1000) = %f", databaseSize, maxSlotWalKeepSize)

		// advanced += fmt.Sprintf("\nmax_slot_wal_keep_size='%.0f MB'\ntrack_wal_io_timing=on",
		// 	maxSlotWalKeepSize,
		// )
		// printTestLog("\tAdvanced Settings: max_slot_wal_keep_size='%.0f MB'\ntrack_wal_io_timing=on",
		// 	maxSlotWalKeepSize,
		// )
		// }

	} else {
		parallel = fmt.Sprintf("max_worker_processes=%d\nmax_parallel_workers_per_gather=%d\nmax_parallel_workers=%d",
			cpu, cpu/2, cpu)
		printTestLog("Version is less than 10 so setting parallel settings to max_worker_processes=%d\nmax_parallel_workers_per_gather=%d\nmax_parallel_workers=%d",
			cpu, cpu/2, cpu)
	}
	printTestLog("\n")

	printTestLog("All Calculations Complete")

	output := fmt.Sprintf(examplePostgresConf,
		connections,
		inputMap["superuser_reserved_connections"],
		inputMap["listen_addr"],
		inputMap["port"],
		sharedBuffers,
		workMem,
		int(maintenanceWorkMem),
		hugePages,
		int(effectiveCacheSize),
		int(effectiveIOConcurrency),
		randomPageCost,
		inputMap["log_connections"],
		inputMap["log_disconnections"],
		inputMap["log_statement"],
		inputMap["ssl"],
		inputMap["log_line_prefix"],
		inputMap["logging_collector"],
		inputMap["log_destination"],
		inputMap["log_checkpoints"],
		inputMap["log_lock_waits"],
		inputMap["log_temp_files"],
		inputMap["log_autovacuum_min_duration"],
		inputMap["log_min_duration_statement"],
		walLevel,
		int(maxWalSenders),
		inputMap["synchronous_commit"],
		maxWalSize,
		minWalSize,
		inputMap["wal_compression"],
		replication,
		walArchiving,
		parallel,
		inputMap["synchronous_standby_names"],
		inputMap["temp_file_limit"],
		inputMap["autovacuum_naptime"],
		inputMap["autovacuum_vacuum_cost_limit"],
		inputMap["autovacuum_vacuum_cost_delay"],
		inputMap["autovacuum_max_workers"],
		defaultStatisticsTarget,
		inputMap["statement_timeout"],
		inputMap["idle_in_transaction_session_timeout"],
	)

	return output
}

func WriteToFile(configString, filepath string) error {
	file, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.WriteString(configString)
	return err
}

// var logOutput *os.File

func init() {
	// var err error
	// logOutput, err = os.Create("testoutput.log")
	// if err != nil {
	// 	panic(err)
	// }
}

func printTestLog(str string, args ...interface{}) {

	// fmt.Fprintf(logOutput, " > "+str+"\n", args...)
}
