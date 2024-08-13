package htmlreport

import "github.com/klouddb/klouddbshield/postgres/calctransactions"

func (h *HtmlReportHelper) RegisterCalcTranx(data calctransactions.ReportData) {
	h.AddTab("Wraparound Report", data)
}
