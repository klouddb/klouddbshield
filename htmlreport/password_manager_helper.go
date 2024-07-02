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

func RenderPasswordManagerReport(ctx context.Context, commonUsernames []string) {
	templateData = append(templateData, Tab{
		Title: "Password Manager",
		Body: PasswordManagerHTMLReport{
			CommanUsernames: &CommonUsernamesRenderData{
				Usernames: commonUsernames,
			},
		},
	})
}
