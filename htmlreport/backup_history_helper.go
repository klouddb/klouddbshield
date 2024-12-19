package htmlreport

import "github.com/klouddb/klouddbshield/pkg/backuphistory"

func (h *HtmlReportHelper) RegisterBackupHistory(output backuphistory.BackupHistoryOutput) {
	h.AddTab("Backup Audit Tool", output)
}
