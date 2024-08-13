package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/jedib0t/go-pretty/text"
	"github.com/klouddb/klouddbshield/htmlreport"
	"github.com/klouddb/klouddbshield/passwordmanager"
	"github.com/klouddb/klouddbshield/pkg/config"
	"github.com/klouddb/klouddbshield/pkg/postgresdb"
	"golang.org/x/term"
)

type postgresPasswordScanner struct {
	postgresCnf *postgresdb.Postgres
}

func newPostgresPasswordScanner(postgresCnf *postgresdb.Postgres) *postgresPasswordScanner {
	return &postgresPasswordScanner{
		postgresCnf: postgresCnf,
	}
}

func (p *postgresPasswordScanner) run(ctx context.Context) error {

	fmt.Print("\n****************************************************************")
	fmt.Print("\n** Don't use Password attack simulator feature in production. **")
	fmt.Print("\n** Please copy your users to test environment and try there.  **")
	fmt.Print("\n****************************************************************\n\n")

	// var host, port string
	// fmt.Printf("Enter Your Postgres Host (Default localhost): ")
	// fmt.Scanln(&host)
	// if host == "" {
	// 	host = "localhost"
	// }
	// fmt.Printf("Enter Your Postgres Port for Host %s (Default 5432): ", host)
	// fmt.Scanln(&port)
	// if port == "" {
	// 	port = "5432"
	// }

	// var bufferSize int
	// fmt.Printf("Enter number of passwords to be bufferred (Default 1000000): ")
	// fmt.Scanln(&bufferSize)
	// if bufferSize != 0 {
	// 	passwordmanager.ChannelBufferSize = bufferSize
	// }

	// var attemptSize int
	// fmt.Printf("Enter number of auths to be performed in parallel for a user (Disabled for 0 & 1): ")
	// fmt.Scanln(&attemptSize)
	// if attemptSize != 0 {
	// 	passwordmanager.GoroutinesPerUser = attemptSize
	// }

	var path string
	fmt.Printf("Enter path to the passwords files (Default /etc/klouddbshield/passwords): ")
	fmt.Scanln(&path) //nolint:errcheck
	if path == "" {
		path = "/etc/klouddbshield/passwords"
	}
	passwordmanager.ParentDir = path

	postgresStore, _, err := postgresdb.Open(*p.postgresCnf)
	if err != nil {
		return err
	}
	defer postgresStore.Close()

	listOfUsers, _ := passwordmanager.GetPostgresUsers(postgresStore)
	fmt.Println("listOfUsers:", listOfUsers)
	ctx, cancelFunc := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer cancelFunc()

	host := p.postgresCnf.Host
	port := p.postgresCnf.Port

	passwordmanager.PostgresPasswordScanner(ctx, host, port, listOfUsers)
	return nil
}

type pwnedPasswordGenerator struct {
	generatedPasswordCnf *config.GeneratePassword
}

func newPwnedPasswordGenerator(generatedPasswordCnf *config.GeneratePassword) *pwnedPasswordGenerator {
	return &pwnedPasswordGenerator{
		generatedPasswordCnf: generatedPasswordCnf,
	}
}

func (p *pwnedPasswordGenerator) run(_ context.Context) error {
	var passwordLength, digitsCount, uppercaseCount, specialCount int

	fmt.Printf("Enter password length (Default %v): ", p.generatedPasswordCnf.Length)
	fmt.Scanln(&passwordLength) //nolint:errcheck
	if passwordLength == 0 {
		passwordLength = p.generatedPasswordCnf.Length
	}

	fmt.Printf("Enter number of digits (Default %v): ", p.generatedPasswordCnf.NumberCount)
	fmt.Scanln(&digitsCount) //nolint:errcheck
	if digitsCount == 0 {
		digitsCount = p.generatedPasswordCnf.NumberCount
	}

	fmt.Printf("Enter number of uppercase characters (Default %v): ", p.generatedPasswordCnf.NumUppercase)
	fmt.Scanln(&uppercaseCount) //nolint:errcheck
	if uppercaseCount == 0 {
		uppercaseCount = p.generatedPasswordCnf.NumUppercase
	}

	fmt.Printf("Enter number of special characters (Default %v): ", p.generatedPasswordCnf.SpecialCharCount)
	fmt.Scanln(&specialCount) //nolint:errcheck
	if specialCount == 0 {
		specialCount = p.generatedPasswordCnf.SpecialCharCount
	}

	passwd := passwordmanager.GeneratePassword(passwordLength, digitsCount, uppercaseCount, specialCount)

	fmt.Println(text.Bold.Sprint("Here's the password:"), passwd)

	encryptedPassword, err := passwordmanager.GenerateEncryptedPassword([]byte(passwd))
	if err != nil {
		return err
	}

	fmt.Println(text.Bold.Sprint("Here's the encrypted password:"), encryptedPassword)
	return nil
}

type encryptedPasswordGenerator struct{}

func newEncryptedPasswordGenerator() *encryptedPasswordGenerator {
	return &encryptedPasswordGenerator{}
}

func (*encryptedPasswordGenerator) run(_ context.Context) error {

	fmt.Print("Enter password: ")
	passwd, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return err
	}
	fmt.Print("\r                    \n")

	encryptedPassword, err := passwordmanager.GenerateEncryptedPassword(passwd)
	if err != nil {
		return err
	}

	fmt.Println(text.Bold.Sprint("Here's the encrypted password:"), encryptedPassword)
	fmt.Println()

	return nil
}

type pwnedUserRunner struct {
	postgresDatabase *postgresdb.Postgres
	builder          *strings.Builder
	printSummaryOnly bool
	htmlReportHelper *htmlreport.HtmlReportHelper
}

func newPwnedUserRunner(postgresDatabase *postgresdb.Postgres, printSummaryOnly bool,
	builder *strings.Builder, htmlReportHelper *htmlreport.HtmlReportHelper) *pwnedUserRunner {
	return &pwnedUserRunner{
		postgresDatabase: postgresDatabase,
		builder:          builder,
		printSummaryOnly: printSummaryOnly,
		htmlReportHelper: htmlReportHelper,
	}
}

func (p *pwnedUserRunner) cronProcess(ctx context.Context) error {
	return p.run(ctx)
}

func (p *pwnedUserRunner) run(ctx context.Context) error {
	pgUsernameMap := map[string]struct{}{}
	for _, userName := range passwordmanager.PGUsernameList {
		pgUsernameMap[userName] = struct{}{}
	}

	postgresStore, _, err := postgresdb.Open(*p.postgresDatabase)
	if err != nil {
		return fmt.Errorf("error opening postgres connection: %v", err)
	}
	defer postgresStore.Close()

	listOfUsers, _ := passwordmanager.GetPostgresUsers(postgresStore)

	commonUserNames := []string{}
	for _, userName := range listOfUsers {
		if _, exists := pgUsernameMap[userName]; exists {
			commonUserNames = append(commonUserNames, userName)
		}
	}

	if p.printSummaryOnly {
		fmt.Println(text.Bold.Sprint("Password Manager Report:"))

		p.builder.WriteString(fmt.Sprintln("Password Manager Report:"))
		if len(commonUserNames) > 0 {
			p.builder.WriteString(fmt.Sprintf("> Found these common usernames in the database: %s\n", strings.Join(commonUserNames, ", ")))
		} else {
			p.builder.WriteString(fmt.Sprintln("> No common usernames found in the database."))
		}
	}
	if len(commonUserNames) > 0 {
		fmt.Printf("> Found these common usernames in the database: %s\n", strings.Join(commonUserNames, ", "))
	} else {
		fmt.Println("> No common usernames found in the database.")
	}
	fmt.Println("")

	p.htmlReportHelper.RenderPasswordManagerReport(ctx, commonUserNames)
	return nil
}

type pwnedPasswordRunner struct {
	inputDirectory string
}

func newPwnedPasswordRunner(inputDirectory string) *pwnedPasswordRunner {
	return &pwnedPasswordRunner{inputDirectory: inputDirectory}
}

func (p *pwnedPasswordRunner) run(_ context.Context) error {
	dir := "./pwnedpasswords"
	if p.inputDirectory != "" {
		dir = p.inputDirectory
	}

	stat, err := os.Stat(dir)
	if err != nil || !stat.IsDir() {
		fmt.Println("You need to download the pawnedpasswords file and put it under pwnedpasswords subdirectory to use this feature. Please refer to our github repo readme for further instructions.")
		return err
	}

	password := ""
	fmt.Print("Enter password to be checked: ")
	fmt.Scanln(&password) //nolint:errcheck
	if password == "" {
		fmt.Println("Password cannot be blank")
		return nil
	}

	times, err := passwordmanager.IsPasswordPwned(password, dir)
	if err != nil {
		if err == passwordmanager.ErrPasswordIsPwned {
			fmt.Println("The password is pwned for", times, "times")
		} else {
			fmt.Println("Error:", text.FgHiRed.Sprint(err))
		}
	} else {
		fmt.Println("Congratulations! The password is not pwned.")
	}

	return nil
}
