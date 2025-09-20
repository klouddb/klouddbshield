package postgresconfig

import (
	"fmt"
	"slices"

	"github.com/klouddb/klouddbshield/pkg/postgresdb"
	"github.com/klouddb/klouddbshield/pkg/utils"
)

type GroupedServers struct {
	GroupName string
	Servers   []string
}

type GroupedServersList []GroupedServers

func (g GroupedServersList) FindGroupForServer(serverName string) *GroupedServers {
	for _, group := range g {
		if slices.Contains(group.Servers, serverName) {
			return &group
		}
	}
	return nil
}

// AllConfigValues holds the result of comparing configurations across multiple databases
type AllConfigValues struct {
	AllSettings     []ConfigSetting
	AllUniqueFields []string
}

type ConfigCompareResult struct {
	One2OneComparison *ConfigCompareOne2OneResult
}

type ConfigCompareOne2OneResult struct {
	BaseServer                   string
	One2OneComparisonNotMatching map[string]map[string][]string
	One2OneComparisonMatching    []string
}

// ConfigSetting represents the configuration settings for a single database
type ConfigSetting struct {
	Name   string
	Values map[string]string
}

// CompareConfig compares the configuration settings of multiple PostgreSQL databases
// It takes an array of connection strings and returns a CompareConfigResult
func GetAllConfigValues(connectionStrings []string) (*AllConfigValues, error) {
	if len(connectionStrings) < 2 {
		return nil, fmt.Errorf("at least two connection strings are required for comparison")
	}

	result := &AllConfigValues{
		AllSettings:     make([]ConfigSetting, 0),
		AllUniqueFields: make([]string, 0),
	}

	uniqueFields := make(map[string]bool)
	// Iterate through each connection string and fetch configuration values
	for _, connectionString := range connectionStrings {
		configValues, err := GetAllConfigValuesFromConnectionString(connectionString)
		if err != nil {
			return nil, fmt.Errorf("error getting config values: %v", err)
		}

		// Add the configuration settings for this database to the result
		result.AllSettings = append(result.AllSettings, ConfigSetting{
			Name:   connectionString,
			Values: configValues,
		})

		// Keep track of all unique configuration fields across all databases
		for field := range configValues {
			uniqueFields[field] = true
		}
	}

	for field := range uniqueFields {
		result.AllUniqueFields = append(result.AllUniqueFields, field)
	}

	return result, nil
}

// GetAllConfigValuesFromConnectionString fetches all configuration values from a single PostgreSQL database
func GetAllConfigValuesFromConnectionString(connectionString string) (map[string]string, error) {
	db, err := postgresdb.ConnectDatabaseUsingConnectionString(connectionString, true)
	if err != nil {
		return nil, fmt.Errorf("error opening postgres connection: %v", err)
	}
	defer db.Close()

	configValues, err := utils.GetConfigValueFromPostgres(db)
	if err != nil {
		return nil, fmt.Errorf("error getting config values: %v", err)
	}

	return configValues, nil
}

// DifferentConfigValue represents a configuration value that differs across databases
type DifferentConfigValue struct {
	Field  string
	Values map[string][]string
}

// NewDifferentConfigValue creates a new DifferentConfigValue instance
func NewDifferentConfigValue(field string) *DifferentConfigValue {
	return &DifferentConfigValue{
		Field:  field,
		Values: make(map[string][]string),
	}
}

// CompareAllServersWithBase compares all the servers with base server provided by user
// from *postgresconfig.AllConfigValues.AllSettings consider first as base and compare all
// other servers with this base server
func CompareAllServersWithBase(allConfigValues *AllConfigValues) *ConfigCompareOne2OneResult {
	if len(allConfigValues.AllSettings) < 2 {
		return nil
	}

	result := &ConfigCompareOne2OneResult{
		BaseServer:                   allConfigValues.AllSettings[0].Name,
		One2OneComparisonNotMatching: make(map[string]map[string][]string),
		One2OneComparisonMatching:    make([]string, 0),
	}

	baseSettings := allConfigValues.AllSettings[0]
	for i := 1; i < len(allConfigValues.AllSettings); i++ {
		compareSettings := allConfigValues.AllSettings[i]
		m := make(map[string][]string)
		for _, field := range allConfigValues.AllUniqueFields {
			if baseSettings.Values[field] != compareSettings.Values[field] {
				m[field] = []string{baseSettings.Values[field], compareSettings.Values[field]}
			}
		}

		if len(m) > 0 {
			result.One2OneComparisonNotMatching[compareSettings.Name] = m
		} else {
			result.One2OneComparisonMatching = append(result.One2OneComparisonMatching, compareSettings.Name)
		}
	}

	return result
}
