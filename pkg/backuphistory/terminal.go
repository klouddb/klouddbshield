package backuphistory

import (
	"fmt"
)

func PrintBackupHistory(output BackupHistoryOutput) {
	fmt.Println("Backup Scanning Period: " + output.StartDate + " - " + output.EndDate)

	if len(output.MissingDates) == 0 {
		fmt.Println("No missing dates found")
		return
	}

	fmt.Println("Backup History:")

	for _, v := range output.MissingDates {
		fmt.Println("> " + v)
	}

	fmt.Println("")
}
