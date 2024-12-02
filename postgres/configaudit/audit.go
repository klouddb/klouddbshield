package configaudit

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/klouddb/klouddbshield/model"
	"github.com/klouddb/klouddbshield/pkg/utils"
)

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
