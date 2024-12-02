package postgresconfig

import (
	_ "embed"
	"fmt"
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
		numb, err := strconv.Atoi(val)
		if err != nil {
			return err
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
	_, err := strconv.Atoi(val)

	return err
}

var validateRegExp = func(r *regexp.Regexp) func(m map[string]string, val string) error {
	return func(m map[string]string, val string) error {
		if !r.MatchString(val) {
			return fmt.Errorf("input data is not matching with pattern")
		}

		return nil
	}
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
