package postgresconfig

import (
	_ "embed"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"text/template"
)

//go:embed summary.txt
var summaryTemplate string

var EmptySkipFunc = func(m map[string]string) (bool, error) { return false, nil }
var EmptyValidationfunc = func(m map[string]string, val string) error { return nil }

var validateBool = func(_ map[string]string, val string) error {
	if val == "" {
		return nil
	}

	if simplifyBoolVal(val) == "" {
		return fmt.Errorf("invalid value. enter yes or no")
	}

	return nil
}

var validateIntRange = func(i, j int) func(m map[string]string, val string) error {
	return func(m map[string]string, val string) error {
		val = strings.TrimSpace(val)
		if val == "" {
			return fmt.Errorf("The input value is empty. Please provide a valid integer") //lint:ignore ST1005 Error message formatting
		}

		numb, err := strconv.Atoi(val)
		if err != nil {
			return fmt.Errorf("'%v' is not a valid integer", val)
		}

		if i <= numb && numb <= j {
			return nil
		}

		return fmt.Errorf("entered value is out of range [%d , %d] ", i, j)
	}
}

var validateIntRangeAllowEmpty = func(i, j int) func(m map[string]string, val string) error {
	f := validateIntRange(i, j)

	return func(m map[string]string, val string) error {
		if val == "" {
			return nil
		}
		return f(m, val)
	}
}

var validateInt = func(m map[string]string, val string) error {
	val = strings.TrimSpace(val)
	if val == "" {
		return fmt.Errorf("input value is empty. please provide a valid integer")
	}

	_, err := strconv.Atoi(val)
	if err != nil {
		return fmt.Errorf("'%v' is not a valid integer", val)
	}

	return nil
}

var validateRegExp = func(r *regexp.Regexp, errMsg string) func(m map[string]string, val string) error {
	return func(m map[string]string, val string) error {
		if !r.MatchString(val) {
			return fmt.Errorf("%s", errMsg)
		}

		return nil
	}
}

var validateSize = func(m map[string]string, val string) error {
	if !regexp.MustCompile(`^\s*[1-9]\d*\s*(?:MB|GB|TB|M|G|T|Mb|Gb|Tb|mB|gB|tB|mb|gb|tb)$`).MatchString(val) {
		return fmt.Errorf("input data is not a valid size")
	}

	return nil
}

var validIP = func(m map[string]string, ip string) error {
	if ip = strings.TrimSpace(ip); ip == "*" || ip == "" {
		return nil
	}

	if net.ParseIP(ip) == nil {
		return fmt.Errorf("input value '%s' is not a valid IP", ip)
	}

	return nil
}

func simplifyBoolVal(val string) string {
	val = strings.ToLower(val)
	for _, v := range []string{"y", "yes"} {
		if v == val {
			return "yes"
		}
	}

	for _, v := range []string{"n", "no"} {
		if v == val {
			return "no"
		}
	}

	return ""
}

var fieldSetFunction = func(fieldName string) func(m map[string]string, val string) error {
	return func(m map[string]string, val string) error {
		m[fieldName] = val
		return nil
	}
}

var fieldSetFunctionDefault = func(fieldName, defaultVal string) func(m map[string]string, val string) error {
	return func(m map[string]string, val string) error {
		m[fieldName] = val
		if m[fieldName] == "" {
			m[fieldName] = defaultVal
		}
		return nil
	}
}

var fieldSetSize = func(fieldName string) func(m map[string]string, val string) error {
	return func(m map[string]string, val string) error {
		normalized := regexp.MustCompile(`\s+`).ReplaceAllString(val, "") // Remove whitespaces
		normalized = strings.ToUpper(normalized)
		m[fieldName] = normalized
		return nil
	}
}

var fieldSetSizeDefault = func(fieldName, defaultVal string) func(m map[string]string, val string) error {
	return func(m map[string]string, val string) error {
		if val == "" {
			m[fieldName] = defaultVal
			return nil
		}
		return fieldSetSize(fieldName)(m, val)
	}
}

var fieldSetSizeInMB = func(fieldName string, args ...string) func(m map[string]string, val string) error {
	return func(m map[string]string, val string) error {

		// Check if a default value is provided
		defaultVal := ""
		if len(args) > 0 {
			defaultVal = args[0]
		}

		// Use default value if val is empty
		if val == "" {
			if defaultVal != "" {
				m[fieldName] = defaultVal
				return nil
			}
			return fmt.Errorf("value is empty and no default provided")
		}

		normalized := regexp.MustCompile(`\s+`).ReplaceAllString(val, "") // Remove whitespaces
		normalized = strings.ToUpper(normalized)

		// Regular expression to match value followed by units (MB, GB, TB, etc.)
		re := regexp.MustCompile(`^(\d+(\.\d+)?)\s*(MB|GB|TB|M|G|T|Mb|Gb|Tb|mB|gB|tB|mb|gb|tb)?$`)
		matches := re.FindStringSubmatch(normalized)
		if len(matches) == 0 {
			return errors.New("invalid size format")
		}

		// Extract the numeric value and unit
		valueStr := matches[1]
		unit := matches[3]

		// Parse the numeric value
		value, err := strconv.ParseFloat(valueStr, 64)
		if err != nil {
			return err
		}

		// Convert based on the unit
		switch unit {
		case "T", "TB", "Tb", "tB", "tb":
			value = value * 1024 * 1024 // TB to MB
		case "G", "GB", "Gb", "gB", "gb":
			value = value * 1024 // GB to MB
		case "M", "MB", "Mb", "mB", "mb":
			// No conversion needed if it's already in MB
		default:
			// Return error if unrecognized unit
			return errors.New("unrecognized unit")
		}

		// Store the converted value
		m[fieldName] = strconv.Itoa(int(value))
		return nil
	}
}

var fieldSetSizeInKB = func(fieldName string, args ...string) func(m map[string]string, val string) error {
	return func(m map[string]string, val string) error {

		// Check if a default value is provided
		defaultVal := ""
		if len(args) > 0 {
			defaultVal = args[0]
		}

		// Use default value if val is empty
		if val == "" {
			if defaultVal != "" {
				m[fieldName] = defaultVal
				return nil
			}
			return fmt.Errorf("value is empty and no default provided")
		}

		normalized := regexp.MustCompile(`\s+`).ReplaceAllString(val, "") // Remove whitespaces
		normalized = strings.ToUpper(normalized)

		// Regular expression to match value followed by units (MB, GB, TB, etc.)
		re := regexp.MustCompile(`^(\d+(\.\d+)?)\s*(KB|MB|GB|TB|K|M|G|T|Kb|Mb|Gb|Tb|kB|mB|gB|tB|kb|mb|gb|tb)?$`)
		matches := re.FindStringSubmatch(normalized)
		if len(matches) == 0 {
			return errors.New("invalid size format")
		}

		// Extract the numeric value and unit
		valueStr := matches[1]
		unit := matches[3]

		// Parse the numeric value
		value, err := strconv.ParseFloat(valueStr, 64)
		if err != nil {
			return err
		}

		// Convert based on the unit
		switch unit {
		case "T", "TB", "Tb", "tB", "tb":
			value = value * 1024 * 1024 * 1024 // TB to MB
		case "G", "GB", "Gb", "gB", "gb":
			value = value * 1024 * 1024 // GB to MB
		case "M", "MB", "Mb", "mB", "mb":
			value = value * 1024
		case "K", "KB", "Kb", "kB", "kb":
			// No conversion needed if it's already in KB
		default:
			// Return error if unrecognized unit
			return errors.New("unrecognized unit")
		}

		// Store the converted value
		m[fieldName] = strconv.Itoa(int(value))
		return nil
	}
}

var skipIfSetFieldFunction = func(fieldName string) func(m map[string]string) (bool, error) {
	return func(m map[string]string) (bool, error) {
		_, ok := m[fieldName]
		return ok, nil
	}
}

func GenerateSummary(inputMap map[string]string) (string, error) {
	tmpl, err := template.New("summary").Parse(summaryTemplate)
	if err != nil {
		return "", err
	}

	var b strings.Builder
	err = tmpl.Execute(&b, inputMap)
	if err != nil {
		return "", err
	}

	return b.String(), nil
}
