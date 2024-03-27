package passwordmanager

import (
	"bufio"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/jackc/pgx/v4"
	"github.com/klouddb/klouddbshield/pkg/utils"
)

var (
	ChannelBufferSize int = 1000000
	GoroutinesPerUser int = 0
)

var TotalPasswordstoScan int64
var errNoReportPending = errors.New("no report pending")

type Report struct {
	authSucceeded bool
	username      string
	password      string
	err           error
}

// passwordChan is a buffered channel used to communicate passwords from
// input files to worker goroutines
var passwordChan = make(chan string, ChannelBufferSize)

// reportCh is a buffered channel used to communicate auth status
var reportCh = make(chan Report, ChannelBufferSize)

// processFile reads passwords from the file and sends them over
// passwordChan channel
func processFile(ctx context.Context, wg *sync.WaitGroup, path string) {
	defer wg.Done()

	log.Print("processing file", path)
	defer log.Print("done processing file", path)

	// read file if not a directory
	fileInfo, err := os.Stat(path)
	if err != nil {
		fmt.Println(err)
		return
	}
	if fileInfo.IsDir() {
		return
	}

	// open the file for reading
	file, err := os.Open(path)
	if err != nil {
		fmt.Println("error opening the file", "path:", path, "error", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		// Check for interrupt signal during file reading
		sent := false
		for !sent {
			select {
			case <-ctx.Done():
				fmt.Printf("\nAborted reading file %s due to interrupt signal.\n", path)
				return
			case passwordChan <- line:
				sent = true
			default:
				time.Sleep(time.Millisecond * 20)
				sent = false
			}
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("Error reading file %s: %s\n", path, err)
	}
}

const (
	// This value is sent to the worker goroutines to ask them to exit
	// at the end of the program
	exitSignal = "__AllFilesProcessed__"
)

var (
	// specify the parent directory to read from
	ParentDir string = "./passwords"
)

// readPassWordInDir walks through a directory to find text
// files and spawns goroutines to concurrently read them
func readPassWordInDir(ctx context.Context) {
	var fileWg sync.WaitGroup
	// traverse directory tree and send files to worker pool
	err := filepath.Walk(ParentDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			fileWg.Add(1)
			go processFile(ctx, &fileWg, path)
		}

		if ctx.Err() != nil {
			return ctx.Err()
		}

		return nil
	})

	if err != nil {
		fmt.Println(err)
	}

	log.Println("waiting for all fileWg processes...")
	fileWg.Wait()

	// Send exit signal after all files are read
	passwordChan <- exitSignal

	log.Println("Done waiting for all fileWg processes...")
}

// statusTracker keeps track of all the passwords processed
// and prints the status to terminal in real time
func statusTracker(wg *sync.WaitGroup) {
	defer wg.Done()

	var total, success, failure int
	successCombinations := []string{}
	for report := range reportCh {
		if report.err == errNoReportPending {
			log.Printf("Final Report - Total: %v, Success: %v, Failure: %v", total, success, failure)
			log.Print("Successful username and passwords combinations are:")
			for _, comb := range successCombinations {
				fmt.Println(comb)
			}
			return
		}

		total++
		if report.authSucceeded {
			success++
			successCombinations = append(successCombinations, fmt.Sprintf("%s %s", report.username, report.password))
		} else {
			failure++
		}

		fmt.Printf("Credentials Processed - Total: %v, Success: %v, Failure: %v\r", total, success, failure)
	}
}

func Track(name string) func() {
	start := time.Now()
	return func() {
		fmt.Printf("%s, execution time %s\n", name, time.Since(start))
	}
}

// PostgresPasswordScanner is called in the main() goroutine to start
// the password scanning process.
func PostgresPasswordScanner(ctx context.Context, host, port string, listOfUsers []string) {
	defer Track("PostgresPasswordScanner")()

	// Spawn a goroutine to track current status of the scan
	var statusTrackerWg sync.WaitGroup
	statusTrackerWg.Add(1)
	go statusTracker(&statusTrackerWg)

	// Create a wait group to wait for user goroutines
	var userWg sync.WaitGroup
	userPasswordChannels := []chan string{}

	// If number of goroutines per user is more than 1, then
	// concurrentProcessingAllowed is true, else it's false
	concurrentProcessingAllowed := GoroutinesPerUser > 1

	// Spawn a goroutine for every user to test passwords against them
	for _, user := range listOfUsers {
		userWg.Add(1)

		// Create a channel to receive passwords for each user goroutine
		userPasswordCh := make(chan string, 1000000)

		// Keep track of all user goroutines created in a list
		userPasswordChannels = append(userPasswordChannels, userPasswordCh)

		// Here we spawn a user goroutine
		go func(ctx context.Context, username string, pwdCh <-chan string) {
			defer userWg.Done()
			log.Println("Started worker for user", username)
			defer log.Println("Finished worker for user", username)

			// This counter keeps track of number of auth goroutines
			// spawned for the user
			authGoroutineCtr := 0

			// This WaitGroup waits for auth goroutines to finish
			var authWg sync.WaitGroup

		passwordLoop:
			for {
				select {
				case <-ctx.Done():
					break passwordLoop
				case password := <-pwdCh:
					// Break loop when exit signal is received over the channel
					if password == exitSignal {
						break passwordLoop
					}

					// Do not spawn auth goroutines if concurrent processing is not allowed
					if !concurrentProcessingAllowed {
						err := connectAuth(ctx, username, password, host, port)
						reportCh <- Report{
							authSucceeded: err == nil,
							username:      username,
							password:      password,
							err:           err,
						}

					} else {
						// Wait for auth goroutines to finish when they reach
						// the number of goroutines per user
						if authGoroutineCtr >= GoroutinesPerUser {
							authWg.Wait()
							authGoroutineCtr = 0
						}

						// Spawn an auth goroutine
						authWg.Add(1)
						go func(ctx context.Context,
							authWg *sync.WaitGroup,
							user, pass, host, port string) {

							defer authWg.Done()

							// Perform authentication for the username and password
							err := connectAuth(ctx, username, password, host, port)

							// Send error and other details over the channel
							// for tracking and compiling current status
							reportCh <- Report{
								authSucceeded: err == nil,
								username:      username,
								password:      password,
								err:           err,
							}
						}(ctx, &authWg, username, password, host, port)

						// Increment counter
						authGoroutineCtr++
					}
				}
			}

			// Wait for last few auth goroutines if any exist
			if authGoroutineCtr > 0 {
				authWg.Wait()
			}

		}(ctx, user, userPasswordCh)
	}

	// Spawn a gorutine to read password files from a directory
	go readPassWordInDir(ctx)

	// This loop sends passwords to user goroutines
	// It also sends a exit signal to them when all
	// files are read.
filePasswordLoop:
	for {
		select {
		case <-ctx.Done():
			break filePasswordLoop
		case passwd := <-passwordChan:
			for _, ch := range userPasswordChannels {
				sent := false
				for !sent {
					select {
					case <-ctx.Done():
						break filePasswordLoop
					case ch <- passwd:
						sent = true
					default:
						time.Sleep(time.Millisecond * 20)
						sent = false
					}
				}
			}

			// Break loop after all files are read.
			if passwd == exitSignal {
				break filePasswordLoop
			}
		}
	}

	// Wait for all user goroutines
	log.Println("waiting for all wg processes...")
	userWg.Wait()
	log.Println("waiting for status report to finish...")

	// Send exit signal to the status tracker goroutine
	reportCh <- Report{
		err: errNoReportPending,
	}

	// Wait for status tracker goroutine to finish
	statusTrackerWg.Wait()
	log.Println("status report finished...")
	log.Println("done waiting for all wg processes...")
}

// connectAuth performs an authentication for a user and password
func connectAuth(ctx context.Context, user, pass, host, port string) error {
	connStr := fmt.Sprintf("user=%s password=%s host=%s port=%s database=postgres", user, pass, host, port)

	config, err := pgx.ParseConfig(connStr)
	if err != nil {
		return err
	}

	conn, err := pgx.ConnectConfig(ctx, config)

	if err == nil && conn != nil {
		conn.Close(ctx)
	}

	return err

}

// GetPostgresUsers gets all usernames present in the db
func GetPostgresUsers(store *sql.DB) ([]string, error) {
	query := `SELECT distinct usename FROM pg_shadow;`
	data, err := utils.GetJSON(store, query)
	if err != nil {
		return nil, err
	}

	listOfUsers := []string{}
	for _, obj := range data {
		if obj["usename"] != nil {
			listOfUsers = append(listOfUsers, fmt.Sprint(obj["usename"]))
		}
	}
	return listOfUsers, err
}
