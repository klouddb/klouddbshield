package email

import (
	"fmt"

	"gopkg.in/gomail.v2"
)

type EmailHelper struct {
	host     string
	port     int
	username string
	password string
}

func NewEmailHelper(host string, port int, username, password string) *EmailHelper {
	return &EmailHelper{
		host:     host,
		port:     port,
		username: username,
		password: password,
	}
}

func (e *EmailHelper) VerifyConfig() error {
	if e.host == "" || e.port == 0 || e.username == "" || e.password == "" {
		return fmt.Errorf("missing email configuration")
	}

	return nil
}

func (e *EmailHelper) Send(to, subject, body string, attachmentPaths []string) error {
	if e.host == "" || e.port == 0 || e.username == "" || e.password == "" {
		return fmt.Errorf("missing email configuration")
	}

	m := gomail.NewMessage()
	m.SetHeader("From", e.username)
	m.SetHeader("To", to)
	m.SetHeader("Subject", subject)
	m.SetBody("text/html; charset=UTF-8", body)

	// Attach the file if an attachment path is provided
	for _, attachmentPath := range attachmentPaths {
		m.Attach(attachmentPath, gomail.SetHeader(map[string][]string{
			"Content-Type": {"text/html; charset=UTF-8"},
		}))
	}

	d := gomail.NewDialer(e.host, e.port, e.username, e.password)

	return d.DialAndSend(m)
}
