package configaudit

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/klouddb/klouddbshield/model"
	"github.com/klouddb/klouddbshield/pkg/utils"
)

var LogLinePrefixSubstrings = []string{"%m", "%p", "%q", "%u", "%d", "%a"}

func AuditConfig(ctx context.Context, store *sql.DB) ([]*model.ConfigAuditResult, error) {
	out := make([]*model.ConfigAuditResult, 0, 5)

	result, err := CheckFsyncFlag(ctx, store)
	if err != nil {
		return nil, err
	}
	out = append(out, result)

	result, err = PreloadLibraryCheck(ctx, store)
	if err != nil {
		return nil, err
	}

	out = append(out, result)

	result, err = SharedBuffer(ctx, store)
	if err != nil {
		return nil, err
	}
	out = append(out, result)

	result, err = AutoVacumeCheck(ctx, store)
	if err != nil {
		return nil, err
	}

	out = append(out, result)

	result, err = TempFileLimit(ctx, store)
	if err != nil {
		return nil, err
	}
	out = append(out, result)

	result, err = FullPageWrites(ctx, store)
	if err != nil {
		return nil, err
	}
	out = append(out, result)

	result, err = MaxWalSize(ctx, store)
	if err != nil {
		return nil, err
	}
	out = append(out, result)

	result, err = LogLinePrefix(ctx, store)
	if err != nil {
		return nil, err
	}
	out = append(out, result)

	result, err = LogConnections(ctx, store)
	if err != nil {
		return nil, err
	}
	out = append(out, result)

	result, err = StatementTimeout(ctx, store)
	if err != nil {
		return nil, err
	}
	out = append(out, result)

	result, err = IdleInTransationSessionTimeout(ctx, store)
	if err != nil {
		return nil, err
	}
	out = append(out, result)

	return out, nil
}

func CheckFsyncFlag(ctx context.Context, store *sql.DB) (*model.ConfigAuditResult, error) {

	result := &model.ConfigAuditResult{
		Name:       "CheckFsyncFlag",
		Status:     "Pass",
		FailReason: "", // Placeholder, replace with actual implementation when implemented in CheckFsyncFlag function.
	}

	// If fsync is set to off - CRITICAL
	query := `SELECT name, setting
		FROM pg_settings
		WHERE name = 'fsync';`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}

	for _, obj := range data {
		if obj["setting"] != nil && fmt.Sprint(obj["setting"]) != "on" {
			result.Status = "Critical"
			result.FailReason = fmt.Sprintf("fsync is set to '%s', it should be 'on'", fmt.Sprint(obj["setting"]))
			return result, nil
		}
	}

	return result, nil // Placeholder, replace with actual implementation
}

func PreloadLibraryCheck(ctx context.Context, store *sql.DB) (*model.ConfigAuditResult, error) {

	result := &model.ConfigAuditResult{
		Name:       "PreloadLibraryCheck",
		Status:     "Pass",
		FailReason: "", // Placeholder, replace with actual implementation when implemented in CheckFsyncFlag function.
	}

	// If fsync is set to off - CRITICAL
	query := `SELECT name, setting
	FROM pg_settings
	WHERE name = 'shared_preload_libraries';`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}

	containsPreloadLibraries := false
	for _, obj := range data {
		if obj["setting"] != nil && strings.Contains(fmt.Sprint(obj["setting"]), "pg_stat_statements") {
			containsPreloadLibraries = true
			break
		}
	}

	if !containsPreloadLibraries {
		result.Status = "WARNING"
		result.FailReason = "shared_preload_libraries does not contain pg_stat_statements"
	}
	return result, nil // Placeholder, replace with actual implementation
}

func SharedBuffer(ctx context.Context, store *sql.DB) (*model.ConfigAuditResult, error) {
	result := &model.ConfigAuditResult{
		Name:       "SharedBuffer",
		Status:     "Pass",
		FailReason: "", // Placeholder, replace with actual implementation when implemented in CheckFsyncFlag function.
	}

	// If fsync is set to off - CRITICAL
	query := `SELECT name, setting
	FROM pg_settings
	WHERE name = 'shared_buffers';`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}

	// check is still pending
	_ = data
	return result, nil // Placeholder, replace with actual implementation
}

func AutoVacumeCheck(ctx context.Context, store *sql.DB) (*model.ConfigAuditResult, error) {

	result := &model.ConfigAuditResult{
		Name:       "AutoVacumeCheck",
		Status:     "Pass",
		FailReason: "", // Placeholder, replace with actual implementation when implemented in CheckFsyncFlag function.
	}

	// If fsync is set to off - CRITICAL
	query := `SELECT name, setting
	FROM pg_settings
	WHERE name = 'autovacuum';`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}

	for _, obj := range data {
		if obj["setting"] != nil && fmt.Sprint(obj["setting"]) == "off" {
			result.Status = "Critical"
			result.FailReason = "autovacuum is off for this server"
			return result, nil
		}
	}

	return result, nil // Placeholder, replace with actual implementation
}

func TempFileLimit(ctx context.Context, store *sql.DB) (*model.ConfigAuditResult, error) {

	result := &model.ConfigAuditResult{
		Name:       "TempFileLimit",
		Status:     "Pass",
		FailReason: "", // Placeholder, replace with actual implementation when implemented in CheckFsyncFlag function.
	}

	// If fsync is set to off - CRITICAL
	query := `SELECT name, setting
	FROM pg_settings
	WHERE name = 'temp_file_limit';`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}

	containsPreloadLibraries := false
	for _, obj := range data {
		if obj["setting"] != nil && fmt.Sprint(obj["setting"]) == "-1" {
			containsPreloadLibraries = true
		}
	}

	if !containsPreloadLibraries {
		result.Status = "WARNING"
		result.FailReason = "temp_file_limit is set -1"
	}
	return result, nil // Placeholder, replace with actual implementation
}

func FullPageWrites(ctx context.Context, store *sql.DB) (*model.ConfigAuditResult, error) {

	result := &model.ConfigAuditResult{
		Name:       "FullPageWrites",
		Status:     "Pass",
		FailReason: "", // Placeholder, replace with actual implementation when implemented in CheckFsyncFlag function.
	}

	// If full_page_writes is set to off - CRITICAL
	query := `SELECT name, setting
	FROM pg_settings
	WHERE name = 'full_page_writes';`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}

	for _, obj := range data {
		if obj["setting"] != nil && fmt.Sprint(obj["setting"]) == "off" {
			result.Status = "Critical"
			result.FailReason = "full_page_writes is set to off for this server"
			return result, nil
		}
	}

	return result, nil // Placeholder, replace with actual implementation
}

func MaxWalSize(ctx context.Context, store *sql.DB) (*model.ConfigAuditResult, error) {

	result := &model.ConfigAuditResult{
		Name:       "MaxWalSize",
		Status:     "Pass",
		FailReason: "", // Placeholder, replace with actual implementation when implemented in CheckFsyncFlag function.
	}

	// If max_wal_size is set to default - WARNING
	query := `SELECT name, setting
	FROM pg_settings
	WHERE name = 'max_wal_size';`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}

	for _, obj := range data {
		if obj["setting"] != nil && fmt.Sprint(obj["setting"]) == "1024" {
			result.Status = "WARNING"
			result.FailReason = "max_wal_size is set to default value i.e 1GB"
			return result, nil
		}
	}

	return result, nil // Placeholder, replace with actual implementation
}

func LogLinePrefix(ctx context.Context, store *sql.DB) (*model.ConfigAuditResult, error) {

	result := &model.ConfigAuditResult{
		Name:       "LogLinePrefix",
		Status:     "Pass",
		FailReason: "", // Placeholder, replace with actual implementation when implemented in CheckFsyncFlag function.
	}

	// If log_line_prefix doesn't contains expected letters - CRITICAL
	query := `SELECT name, setting
	FROM pg_settings
	WHERE name = 'log_line_prefix';`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}

	for _, obj := range data {
		if obj["setting"] != nil {
			logLinePrefix := fmt.Sprint(obj["setting"])
			missing := []string{}

			for _, sub := range LogLinePrefixSubstrings {
				if !strings.Contains(logLinePrefix, sub) {
					missing = append(missing, sub)
				}
			}

			if len(missing) > 0 {
				result.Status = "Critical"
				result.FailReason = fmt.Sprintf("log_line_prefix must contain %v, Missing values : %v", LogLinePrefixSubstrings, missing)
				return result, nil
			}
		}
	}

	return result, nil // Placeholder, replace with actual implementation
}

func LogConnections(ctx context.Context, store *sql.DB) (*model.ConfigAuditResult, error) {

	result := &model.ConfigAuditResult{
		Name:       "LogConnections",
		Status:     "Pass",
		FailReason: "", // Placeholder, replace with actual implementation when implemented in CheckFsyncFlag function.
	}

	// If log_connections or log_disconnections is set to off - CRITICAL
	query := `SELECT name, setting
	FROM pg_settings
	WHERE name IN ('log_connections', 'log_disconnections');`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}

	for _, obj := range data {
		if obj["setting"] != nil && fmt.Sprint(obj["setting"]) == "off" {
			result.Status = "Critical"
			result.FailReason = fmt.Sprintf("%s is set to off for this server", obj["name"])
			return result, nil
		}
	}

	return result, nil // Placeholder, replace with actual implementation
}

func StatementTimeout(ctx context.Context, store *sql.DB) (*model.ConfigAuditResult, error) {

	result := &model.ConfigAuditResult{
		Name:       "StatementTimeout",
		Status:     "Pass",
		FailReason: "", // Placeholder, replace with actual implementation when implemented in CheckFsyncFlag function.
	}

	// If statement_timeout is set to 0 (default) - CRITICAL
	query := `SELECT name, setting
	FROM pg_settings
	WHERE name = 'statement_timeout';`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}

	for _, obj := range data {
		if obj["setting"] != nil && fmt.Sprint(obj["setting"]) == "0" {
			result.Status = "Critical"
			result.FailReason = "statement_timeout is set to 0 (default) for this server"
			return result, nil
		}
	}

	return result, nil // Placeholder, replace with actual implementation
}

func IdleInTransationSessionTimeout(ctx context.Context, store *sql.DB) (*model.ConfigAuditResult, error) {

	result := &model.ConfigAuditResult{
		Name:       "IdleInTransationSessionTimeout",
		Status:     "Pass",
		FailReason: "", // Placeholder, replace with actual implementation when implemented in CheckFsyncFlag function.
	}

	// If idle_in_transaction_session_timeout is set to 0 (default) - CRITICAL
	query := `SELECT name, setting
	FROM pg_settings
	WHERE name = 'idle_in_transaction_session_timeout';`

	data, err := utils.GetJSON(store, query)
	if err != nil {
		result.Status = "Fail"
		result.FailReason = err.Error()
		return result, nil
	}

	for _, obj := range data {
		if obj["setting"] != nil && fmt.Sprint(obj["setting"]) == "0" {
			result.Status = "Critical"
			result.FailReason = "idle_in_transaction_session_timeout is set to 0 (default) for this server"
			return result, nil
		}
	}

	return result, nil // Placeholder, replace with actual implementation
}
