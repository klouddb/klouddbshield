package config

import (
	"fmt"
	"os"

	"github.com/jedib0t/go-pretty/v6/text"
	cons "github.com/klouddb/klouddbshield/pkg/const"
)

/*
1.
2.
3.
4.
5. all: To run all log parser commands at once
NOTE: --begin-time and --end-time are optional flags and --prefix, --file-path and --hba-file are required flags if you are using --logparser=all
If you have postgres connection details in config file then you don't need to provide --hba-file flag
e.g
* ciscollector --logparser all --file-path /location/to/log/file.log --begin-time "2021-01-01 00:00:00" --end-time "2021-01-01 23:59:59" --prefix <logline prefix> --hba-file /location/to/pg_hba.conf
* ciscollector --logparser all --file-path /location/to/log/file.log --prefix <logline prefix> --hba-file /location/to/pg_hba.conf
* ciscollector --logparser all --file-path /location/to/log/file.log --prefix <logline prefix>
* ciscollector --logparser all --file-path /location/to/log/*.log --begin-time "2021-01-01 00:00:00" --end-time "2021-01-01 23:59:59" --prefix <logline prefix> --hba-file /location/to/pg_hba.conf
* ciscollector --logparser all --file-path /location/to/log/*.log --prefix <logline prefix> --hba-file /location/to/pg_hba.conf
* ciscollector --logparser all --file-path /location/to/log/*.log --prefix <logline prefix>


*/

func PrintHelp() {
	fmt.Println()
	fmt.Println(text.FgCyan.Sprint("Please select a feature you'd like to try from the list below. We will provide instructions for that specific feature"))
	fmt.Print(cons.MSG_Choise)
	choice := 0
	fmt.Scanln(&choice) //nolint:errcheck
	fmt.Println()
	switch choice {
	case 1: // All Postgres checks(Recommended)
		filePath := text.FgMagenta.Sprint("/etc/klouddbshield/kshieldconfig.toml")
		dirPath := text.FgMagenta.Sprint("/etc/klouddbshield")
		command := text.FgMagenta.Sprint(`"ciscollector -r"`)
		option := text.FgMagenta.Sprint(`"All Postgres Checks"`)
		fmt.Println("> Once you install package or cloned the repo, you need to populate the config file " + filePath + " in " + dirPath + " directory . Please fill username, dbname and password (sample entry below).")
		fmt.Println("> Once config file is ready please execute " + command + " and and pick option for " + option + " (First option in the list).")
		fmt.Println(text.FgCyan.Sprint("[postgres]"))
		fmt.Println(text.FgCyan.Sprint(`host="54.xxx.xxx.xx"`))
		fmt.Println(text.FgCyan.Sprint(`port="5432"`))
		fmt.Println(text.FgCyan.Sprint(`user="xxxxx"`))
		fmt.Println(text.FgCyan.Sprint(`dbname="postgres"`))
		fmt.Println(text.FgCyan.Sprint(`password="xxxxx"`))
		fmt.Println(text.FgCyan.Sprint(`maxIdleConn = 2`))
		fmt.Println(text.FgCyan.Sprint(`maxOpenConn = 2`))

	case 2: // Postgres CIS and User Security checks
		filePath := text.FgMagenta.Sprint("/etc/klouddbshield/kshieldconfig.toml")
		dirPath := text.FgMagenta.Sprint("/etc/klouddbshield")
		command := text.FgMagenta.Sprint(`"ciscollector -r"`)
		option := text.FgMagenta.Sprint(`"Postgres CIS and User Security checks"`)
		fmt.Println("> Once you install package or cloned the repo, you need to populate the config file " + filePath + " in " + dirPath + " directory . Please fill username, dbname and password (sample entry below).")
		fmt.Println("> Once config file is ready please execute " + command + " and and pick option for " + option)
		fmt.Println(text.FgCyan.Sprint("[postgres]"))
		fmt.Println(text.FgCyan.Sprint(`host="54.xxx.xxx.xx"`))
		fmt.Println(text.FgCyan.Sprint(`port="5432"`))
		fmt.Println(text.FgCyan.Sprint(`user="xxxxx"`))
		fmt.Println(text.FgCyan.Sprint(`dbname="postgres"`))
		fmt.Println(text.FgCyan.Sprint(`password="xxxxx"`))
		fmt.Println(text.FgCyan.Sprint(`maxIdleConn = 2`))
		fmt.Println(text.FgCyan.Sprint(`maxOpenConn = 2`))

	case 3: // HBA Scanner
		filePath := text.FgMagenta.Sprint("/etc/klouddbshield/kshieldconfig.toml")
		dirPath := text.FgMagenta.Sprint("/etc/klouddbshield")
		command := text.FgMagenta.Sprint(`"ciscollector -r"`)
		option := text.FgMagenta.Sprint(`"HBA Scanner"`)
		fmt.Println("> Once you install package or cloned the repo, you need to populate the config file " + filePath + " in " + dirPath + " directory . Please fill username, dbname and password (sample entry below).")
		fmt.Println("> Once config file is ready please execute " + command + " and and pick option for " + option)
		fmt.Println(text.FgCyan.Sprint("[postgres]"))
		fmt.Println(text.FgCyan.Sprint(`host="54.xxx.xxx.xx"`))
		fmt.Println(text.FgCyan.Sprint(`port="5432"`))
		fmt.Println(text.FgCyan.Sprint(`user="xxxxx"`))
		fmt.Println(text.FgCyan.Sprint(`dbname="postgres"`))
		fmt.Println(text.FgCyan.Sprint(`password="xxxxx"`))
		fmt.Println(text.FgCyan.Sprint(`maxIdleConn = 2`))
		fmt.Println(text.FgCyan.Sprint(`maxOpenConn = 2`))

	case 4: // Inactive user report
		fmt.Println(text.Bold.Sprint("inactive_users") + ": To get inactive users from log file")

		command := text.FgMagenta.Sprint(`"ciscollector -r"`)
		option := text.FgMagenta.Sprint(`"Inactive user report"`)
		fmt.Printf("> Please run %s and pick option for %s.\n", command, option)

		fmt.Println("\n> You can also run the command directly as below:")
		mainCommand := text.FgHiCyan.Sprint("ciscollector --logparser inactive_users")
		filepathFlag := text.FgCyan.Sprint("--file-path /location/to/log/file.log")
		fileRegexFlag := text.FgCyan.Sprint("--file-regex /location/to/log/*.log")
		beginTimeFlag := text.FgCyan.Sprint("--begin-time \"2021-01-01 00:00:00\"")
		endTimeFlag := text.FgCyan.Sprint("--end-time \"2021-01-01 23:59:59\"")
		prefixFlag := text.FgCyan.Sprint("--prefix <logline prefix>")

		fmt.Println("$ " + mainCommand + " " + filepathFlag + " " + beginTimeFlag + " " + endTimeFlag + " " + prefixFlag)
		fmt.Println("$ " + mainCommand + " " + filepathFlag + " " + prefixFlag)
		fmt.Println("$ " + mainCommand + " " + fileRegexFlag + " " + beginTimeFlag + " " + endTimeFlag + " " + prefixFlag)
		fmt.Println("$ " + mainCommand + " " + fileRegexFlag + " " + prefixFlag)
		fmt.Println("\n> " + text.Bold.Sprint("NOTE: --begin-time and --end-time are optional flags and --prefix and --file-path are required flags if you are using --logparser=inactive_users"))
	case 5: // Client ip report
		fmt.Println(text.Bold.Sprint("unique_ip") + ": To get client IPs from log file")

		command := text.FgMagenta.Sprint(`"ciscollector -r"`)
		option := text.FgMagenta.Sprint(`"Client ip report"`)
		fmt.Printf("> Please run %s and pick option for %s.\n", command, option)

		fmt.Println("\n> You can also run the command directly as below:")
		mainCommand := text.FgHiCyan.Sprint("ciscollector --logparser unique_ip")
		filepathFlag := text.FgCyan.Sprint("--file-path /location/to/log/file.log")
		fileRegexFlag := text.FgCyan.Sprint("--file-regex /location/to/log/*.log")
		beginTimeFlag := text.FgCyan.Sprint("--begin-time \"2021-01-01 00:00:00\"")
		endTimeFlag := text.FgCyan.Sprint("--end-time \"2021-01-01 23:59:59\"")
		prefixFlag := text.FgCyan.Sprint("--prefix <logline prefix>")

		fmt.Println("$ " + mainCommand + " " + filepathFlag + " " + beginTimeFlag + " " + endTimeFlag + " " + prefixFlag)
		fmt.Println("$ " + mainCommand + " " + filepathFlag + " " + prefixFlag)
		fmt.Println("$ " + mainCommand + " " + fileRegexFlag + " " + beginTimeFlag + " " + endTimeFlag + " " + prefixFlag)
		fmt.Println("$ " + mainCommand + " " + fileRegexFlag + " " + prefixFlag)
		fmt.Println("\n> " + text.Bold.Sprint("NOTE: --begin-time and --end-time are optional flags and --prefix and --file-path are required flags if you are using --logparser=unique_ip"))

	case 6: // HBA unused lines report
		fmt.Println(text.Bold.Sprint("unused_lines") + ": To get unused lines from pg_hba.conf file by comparing that with log file")

		command := text.FgMagenta.Sprint(`"ciscollector -r"`)
		option := text.FgMagenta.Sprint(`"HBA unused lines report"`)
		fmt.Printf("> Please run %s and pick option for %s.\n", command, option)

		fmt.Println("\n> You can also run the command directly as below:")
		mainCommand := text.FgHiCyan.Sprint("ciscollector --logparser unused_lines")
		filepathFlag := text.FgCyan.Sprint("--file-path /location/to/log/file.log")
		fileRegexFlag := text.FgCyan.Sprint("--file-regex /location/to/log/*.log")
		beginTimeFlag := text.FgCyan.Sprint("--begin-time \"2021-01-01 00:00:00\"")
		endTimeFlag := text.FgCyan.Sprint("--end-time \"2021-01-01 23:59:59\"")
		prefixFlag := text.FgCyan.Sprint("--prefix <logline prefix>")
		hbaFileFlag := text.FgCyan.Sprint("--hba-file /location/to/pg_hba.conf")

		fmt.Println("$ " + mainCommand + " " + filepathFlag + " " + beginTimeFlag + " " + endTimeFlag + " " + prefixFlag + " " + hbaFileFlag)
		fmt.Println("$ " + mainCommand + " " + filepathFlag + " " + prefixFlag + " " + hbaFileFlag)
		fmt.Println("$ " + mainCommand + " " + fileRegexFlag + " " + beginTimeFlag + " " + endTimeFlag + " " + prefixFlag + " " + hbaFileFlag)
		fmt.Println("$ " + mainCommand + " " + fileRegexFlag + " " + prefixFlag + " " + hbaFileFlag)
		fmt.Println("\n> " + text.Bold.Sprint("NOTE: --begin-time and --end-time are optional flags and --prefix, --file-path and --hba-file are required flags if you are using --logparser=unused_lines"))

	case 7: // Password Manager
		fmt.Println("This module has 3 different active features 1) Password generator 2) Password attack simulator 3) Common usernames detector")

		command := text.FgMagenta.Sprint(`"ciscollector -r"`)
		option := text.FgMagenta.Sprint(`"Password Manager"`)
		fmt.Printf("> Please run %s and pick option for %s.\n", command, option)
		fmt.Println("> From there, you can choose one of the following three sub-options:")
		fmt.Println("\t" + text.FgCyan.Sprint("1. Password generator"))
		fmt.Println("\t" + text.FgCyan.Sprint("2. Password attack simulator"))
		fmt.Println("\t" + text.FgCyan.Sprint("3. Common usernames detector"))

	case 8: // Password leak scanner
		fmt.Println(text.Bold.Sprint("password_leak_scanner") + ": To get password leak scanner from log file")

		command := text.FgMagenta.Sprint(`"ciscollector -r"`)
		option := text.FgMagenta.Sprint(`"Password leak scanner"`)
		fmt.Printf("> Please run %s and pick option for %s.\n", command, option)

		fmt.Println("\n> You can also run the command directly as below:")
		mainCommand := text.FgHiCyan.Sprint("ciscollector --logparser password_leak_scanner")
		filepathFlag := text.FgCyan.Sprint("--file-path /location/to/log/file.log")
		fileRegexFlag := text.FgCyan.Sprint("--file-regex /location/to/log/*.log")
		beginTimeFlag := text.FgCyan.Sprint("--begin-time \"2021-01-01 00:00:00\"")
		endTimeFlag := text.FgCyan.Sprint("--end-time \"2021-01-01 23:59:59\"")
		prefixFlag := text.FgCyan.Sprint("--prefix <logline prefix>")

		fmt.Println("$ " + mainCommand + " " + filepathFlag + " " + beginTimeFlag + " " + endTimeFlag + " " + prefixFlag)
		fmt.Println("$ " + mainCommand + " " + filepathFlag + " " + prefixFlag)
		fmt.Println("$ " + mainCommand + " " + fileRegexFlag + " " + beginTimeFlag + " " + endTimeFlag + " " + prefixFlag)
		fmt.Println("$ " + mainCommand + " " + fileRegexFlag + " " + prefixFlag)
		fmt.Println("\n> " + text.Bold.Sprint("NOTE: --begin-time and --end-time are optional flags and --prefix and --file-path are required flags if you are using --logparser=password_leak_scanner"))

	case 9, 10: // AWS RDS Sec Report
		fmt.Println("> Make sure you have properly configured your AWS-CLI with a valid Access Key and Region or declare AWS variables properly.")
		fmt.Println("> NOTE: Please run this tool from a bastion host or another location where you have access to your RDS instances. It only requires basic AWS RDS 'describe' privileges and SNS 'read' privileges.")

		fmt.Println("\t $" + text.FgCyan.Sprintf(`export AWS_ACCESS_KEY_ID="ASXXXXXXX"`))
		fmt.Println("\t $" + text.FgCyan.Sprintf(`export AWS_SECRET_ACCESS_KEY="XXXXXXXXX"`))
		fmt.Println("\t $" + text.FgCyan.Sprintf(`export AWS_SESSION_TOKEN="XXXXXXXXX"`))
		fmt.Println("\t $" + text.FgCyan.Sprintf(`export AWS_REGION="XXXXXXXXX"`))

		command := text.FgMagenta.Sprint(`"ciscollector -r"`)
		option := text.FgMagenta.Sprint(`"AWS RDS Sec Report"`)
		fmt.Printf("> Once above is done please run %s and pick option for %s.\n", command, option)

	case 11: // MySQL Report
		filePath := text.FgMagenta.Sprint("/etc/klouddbshield/kshieldconfig.toml")
		dirPath := text.FgMagenta.Sprint("/etc/klouddbshield")
		command := text.FgMagenta.Sprint(`"ciscollector -r"`)
		option := text.FgMagenta.Sprint(`"Postgres CIS and User Security checks"`)
		fmt.Println("> Once you install package or cloned the repo, you need to populate the config file " + filePath + " in " + dirPath + " directory . Please fill username, dbname and password (sample entry below).")
		fmt.Println("> Once config file is ready please execute " + command + " and and pick option for " + option + " (First option in the list).")
		fmt.Println(text.FgCyan.Sprint("[mysql]"))
		fmt.Println(text.FgCyan.Sprint(`host="localhost"`))
		fmt.Println(text.FgCyan.Sprint(`port="3306"`))
		fmt.Println(text.FgCyan.Sprint(`user="xxxxx"`))
		fmt.Println(text.FgCyan.Sprint(`password="xxxxx"`))
		fmt.Println(text.FgCyan.Sprint(`maxIdleConn = 2`))
		fmt.Println(text.FgCyan.Sprint(`maxOpenConn = 2`))

	case 12: // Exit
		os.Exit(0)

	default:
		fmt.Println("Invalid Choice, Please Try Again.")
		os.Exit(1)
	}

	refMessage := "> " + text.FgGreen.Sprint("Refer to the detailed guide at "+text.Underline.Sprint("'https://klouddb.gitbook.io/klouddb_shield'"))
	fmt.Println(refMessage)
}
