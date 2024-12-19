package htmlreport

import "github.com/klouddb/klouddbshield/pkg/piiscanner"

func (h *HtmlReportHelper) RegisterPIIReport(result *piiscanner.DatabasePIIScanOutput) {
	if result == nil {
		return
	}

	if len(result.Data) == 0 {
		return
	}

	h.AddTab("PII Scanner Report", result)
}
