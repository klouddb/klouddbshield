package htmlreport

import (
	"context"
)

type PasswordManagerHTMLReport struct {
	CommanUsernames *CommonUsernamesRenderData
}

type CommonUsernamesRenderData struct {
	Usernames []string
}

func (h *HtmlReportHelper) RenderPasswordManagerReport(ctx context.Context, commonUsernames []string) {
	h.AddTab("Password Manager", PasswordManagerHTMLReport{
		CommanUsernames: &CommonUsernamesRenderData{
			Usernames: commonUsernames,
		},
	})
}
