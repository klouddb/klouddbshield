package htmlreport

import "github.com/klouddb/klouddbshield/pkg/piiscanner"

func (h *HtmlReportHelper) RegisterPIIReport(result *piiscanner.DatabasePIIScanOutput) {
	h.AddTab("PII Scanner Report", result)
}
