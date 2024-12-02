package sslaudit

import (
	"context"
	"database/sql"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/klouddb/klouddbshield/model"
	"github.com/klouddb/klouddbshield/pkg/utils"
	"github.com/klouddb/klouddbshield/postgres/hbascanner"
)

func AuditSSL(ctx context.Context, store *sql.DB, host string, port string) (*model.SSLScanResult, error) {
	out := &model.SSLScanResult{}

	// Check if SSL is enabled
	result, err := CheckSSLEnabled(ctx, store)
	if err != nil {
		return nil, err
	}
	out.Cells = append(out.Cells, result)

	// Check SSL Parameters
	sslParams, err := CheckSSLParameters(ctx, store)
	if err != nil {
		return nil, err
	}
	out.SSLParams = sslParams

	// Check SSL Certificate Expiry
	results, err := ValidateCertificate(ctx, host, port)
	if err != nil {
		return nil, err
	}
	out.Cells = append(out.Cells, results...)

	// Check SSL HBA
	result, failRows, err := CheckSSLHBA(ctx, store)
	if err != nil {
		return nil, err
	}
	out.Cells = append(out.Cells, result)
	out.HBALines = failRows

	return out, nil
}

func CheckSSLEnabled(ctx context.Context, store *sql.DB) (*model.SSLScanResultCell, error) {
	result := &model.SSLScanResultCell{
		Title:  "SSL Enabled Check",
		Status: "Pass",
	}

	query := `SELECT name, setting FROM pg_settings WHERE name = 'ssl';`
	data, err := utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.Message = "failed to get ssl status " + err.Error()
		return result, nil
	}

	for _, obj := range data {
		if obj["setting"] != nil && fmt.Sprint(obj["setting"]) != "on" {
			result.Status = "Critical"
			result.Message = "SSL is not enabled"
			return result, nil
		}
	}

	return result, nil
}

func CheckSSLParameters(ctx context.Context, store *sql.DB) (map[string]string, error) {

	query := `SELECT name, setting FROM pg_settings WHERE name IN 
		('ssl_ciphers', 'ssl_key_file', 'ssl_cert_file',
			'ssl_ca_file', 'ssl_prefer_server_ciphers');`
	data, err := utils.GetJSON(store, query)
	if err != nil {
		return nil, err
	}

	result := make(map[string]string)
	for _, obj := range data {
		result[fmt.Sprint(obj["name"])] = fmt.Sprint(obj["setting"])
	}

	return result, nil
}

func ValidateCertificate(ctx context.Context, host, port string) ([]*model.SSLScanResultCell, error) {
	out := []*model.SSLScanResultCell{
		{
			Title:  "Self-Signed Certificate Check",
			Status: "Pass",
		},
		{
			Title:  "SSL Certificate Expiry Check",
			Status: "Pass",
		},
	}

	cmd := exec.Command("openssl", "s_client", "-connect", fmt.Sprintf("%s:%s", host, port), "-starttls", "postgres")

	output, err := cmd.CombinedOutput()
	if err != nil {
		if strings.Contains(string(output), "no peer certificate available") {
			out[0].Status = "Critical"
			out[1].Status = "Critical"
			out[0].Message = "No certificate available"
			out[1].Message = "No certificate available"
		} else {
			out[0].Status = "Fail"
			out[1].Status = "Fail"
			out[0].Message = fmt.Sprintf("Failed to check certificate: %v", string(output))
			out[1].Message = fmt.Sprintf("Failed to check certificate: %v", string(output))
		}

		return out, nil
	}

	outputStr := string(output)
	if strings.Contains(outputStr, "self-signed certificate") {
		out[0].Status = "Warning"
		out[0].Message = "Using self-signed certificate"
	} else {
		subject, issuer := getSubjectAndIssuer(outputStr)

		if subject != "" && subject == issuer {
			out[0].Status = "Warning"
			out[0].Message = "Seems like certificate is not signed by a trusted CA [subject and issuer are the same]"
		}
	}

	expiryDate, err := ParseNotAfter(outputStr)
	if err != nil {
		return nil, err
	}

	if expiryDate.Before(time.Now().AddDate(0, 0, 45)) {
		out[1].Status = "Critical"
		out[1].Message = fmt.Sprintf("SSL Certificate will expire in %d days", int(time.Until(expiryDate).Hours()/24))
	} else if expiryDate.Before(time.Now()) {
		out[1].Status = "Critical"
		out[1].Message = "SSL Certificate has expired"
	}

	return out, nil
}

func CheckSSLHBA(ctx context.Context, store *sql.DB) (*model.SSLScanResultCell, []string, error) {
	result, failRows, err := checkSSLHbaByQuery(store)
	if err == nil {
		return result, failRows, nil
	}
	// if query fails then try by file
	result, failRows, err = checkSSLHbaByFile(ctx, store)
	if err != nil {
		return nil, nil, err
	}

	return result, failRows, nil
}

func checkSSLHbaByFile(ctx context.Context, store *sql.DB) (*model.SSLScanResultCell, []string, error) {
	listRows, listOfLineNums, err := hbascanner.GetHBAFileData(store, ctx)
	if err != nil {
		return nil, nil, err
	}

	var failRows []string
	var lineNumbers []string
	for i, line := range listRows {
		if strings.Contains(line, "host") && !strings.Contains(line, "ssl") {
			row := fmt.Sprintf("%d: %s", listOfLineNums[i], line)
			failRows = append(failRows, row)
			lineNumbers = append(lineNumbers, fmt.Sprint(listOfLineNums[i]))
		}
	}

	result := &model.SSLScanResultCell{
		Title:  "SSL HBA Check",
		Status: "Pass",
	}

	if len(failRows) > 0 {
		result.Status = "Warning"
		result.Message = "Line number without ssl: " + strings.Join(lineNumbers, ",")
	}

	return result, failRows, nil
}

func checkSSLHbaByQuery(store *sql.DB) (*model.SSLScanResultCell, []string, error) {
	query := `select * from pg_hba_file_rules where type='host';`
	data, err := utils.GetJSON(store, query)
	if err != nil {
		return nil, nil, err
	}

	var failRows []string
	var lineNumbers []string
	for _, obj := range data {
		row := fmt.Sprintf("%d: %s %s %s %s", obj["line_number"], obj["type"], obj["database"], obj["user_name"], obj["address"])
		failRows = append(failRows, row)
		lineNumbers = append(lineNumbers, fmt.Sprint(obj["line_number"]))
	}

	result := &model.SSLScanResultCell{
		Title:  "SSL HBA Check",
		Status: "Pass",
	}

	if len(failRows) > 0 {
		result.Status = "Warning"
		result.Message = "Line number without ssl: " + strings.Join(lineNumbers, ",")
	}

	return result, failRows, nil
}

// ParseNotAfter extracts the NotAfter date from the certificate text and returns it as a time.Time object.
func ParseNotAfter(certText string) (time.Time, error) {
	// Define a regex pattern to match the NotAfter line
	re := regexp.MustCompile(`\bNotAfter:\s*(\w+\s+\d+\s+\d{2}:\d{2}:\d{2} \d{4} \w+)\b`)

	// Find the match
	matches := re.FindStringSubmatch(certText)
	if len(matches) < 2 {
		return time.Time{}, nil // or return an error if preferred
	}

	// Extract the date string
	dateStr := strings.TrimSpace(matches[1])

	// Parse the date string
	notAfterTime, err := time.Parse("Jan 02 15:04:05 2006 MST", dateStr)
	if err != nil {
		return time.Time{}, err
	}

	return notAfterTime, nil
}

func getSubjectAndIssuer(certText string) (string, string) {
	re := regexp.MustCompile(`subject=(.+)\n`)
	matches := re.FindStringSubmatch(certText)
	if len(matches) < 2 {
		return "", ""
	}
	subject := strings.TrimSpace(matches[1])

	re = regexp.MustCompile(`issuer=(.+)\n`)
	matches = re.FindStringSubmatch(certText)
	if len(matches) < 2 {
		return "", ""
	}
	issuer := strings.TrimSpace(matches[1])

	return subject, issuer
}
