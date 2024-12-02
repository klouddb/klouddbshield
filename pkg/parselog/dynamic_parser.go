package parselog

import (
	"regexp"
)

/*
itertate over logPattern and replace %m, %p, %q, %u, %d, %a, %h, %v, %l, %e, %x, %c, %b, %t, %s
for each character in logPattern if char is % then with next char check in regexMap if it is metching or not
if matching then replace with corresponding regex else replace with char

if it is %a check second char if it is space or comma then replace with corresponding regex else replace with char

	if second charecter is \ then check third char if it is ] then replace with corresponding regex else replace with char

if that matching is %q then instead %q use (?: and at the end of logPattern use )? for optional
*/

const (
	//                       `(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3} [\-+]?\w+)`
	RegExp_Date                        = `\d{4}-\d{2}-\d{2}`
	RegExp_Time                        = `\d{2}:\d{2}:\d{2}`
	RegExp_Timezone                    = `[\-+]?\w+`
	Regexp_Miliseconds                 = `\.\d+`
	RegExp_TimestampWithMicrosecond    = `(` + RegExp_Date + ` ` + RegExp_Time + Regexp_Miliseconds + ` ` + RegExp_Timezone + `)`
	RegExp_TimestampWithoutMicrosecond = `(` + RegExp_Date + ` ` + RegExp_Time + ` ` + RegExp_Timezone + `)`
	RegExp_Int                         = `(\d+)`
	RegExp_IntWithSlace                = `(\d+\/\d+)?`
	RegExp_String                      = `(\S*)`
	RegExp_StringWithSpace             = `([\w ]+)`
	RegExp_StringWithDot               = `(\w+\.\w+)?`
	RegExp_HostWithoutPort             = `(\S+)?`
	RegExp_HostWithPort                = `(\S+\(.*?\))?`
	RegExp_Level                       = `(DEBUG5|DEBUG4|DEBUG3|DEBUG2|DEBUG1|INFO|NOTICE|LOG|WARNING|ERROR|FATAL|PANIC|DETAIL|HINT|STATEMENT|CONTEXT|LOCATION):`
	RegExp_Content                     = `\s+(.*)$`
	RegExp_ErrorCode                   = `(\w{5})`
)

// GenerateRegexString generates a regular expression string from a log line prefix
func GenerateRegexString(logPattern string) (string, map[string]int) {

	// Define a map of placeholders and their corresponding regular expressions
	regexMap := map[string]string{
		"%m": RegExp_TimestampWithMicrosecond,
		"%t": RegExp_TimestampWithoutMicrosecond,
		"%s": RegExp_TimestampWithoutMicrosecond,
		"%p": RegExp_Int,
		"%u": RegExp_String,
		"%d": RegExp_String,
		"%a": RegExp_String,
		"%h": RegExp_HostWithoutPort,
		"%r": RegExp_HostWithPort,
		"%v": RegExp_IntWithSlace,
		"%l": RegExp_Int,
		"%e": RegExp_ErrorCode,
		"%x": RegExp_Int,
		"%c": RegExp_StringWithDot,
		"%b": RegExp_StringWithSpace,
	}

	// escape all special characters
	logPattern = regexp.QuoteMeta(logPattern)

	regexpString := ""

	foundQ := false

	indexMap := map[string]int{}
	crtInd := 2

	// Iterate over the log pattern
	for i := 0; i < len(logPattern); i++ {
		if logPattern[i] != '%' {
			regexpString += string(logPattern[i])
			continue
		}

		// if second char is q
		if logPattern[i+1] == 'q' {
			regexpString += `(?:`
			foundQ = true
			i++
			continue
		}

		if regexMap[logPattern[i:i+2]] == "" {
			i++
			continue
		}

		regexpString += regexMap[logPattern[i:i+2]]
		indexMap[logPattern[i:i+2]] = crtInd
		crtInd++
		i++

		// unknown placeholder
	}

	if foundQ {
		regexpString += `)?`
	}

	// Add the necessary anchors and flags for the regular expression
	regexpString = `(\s*)` + regexpString + `(\s*)` + RegExp_Level + RegExp_Content

	// Compile and return the regular expression
	return regexpString, indexMap
}

// GetDynamicBaseParser will return base parser for dynamic log line prefix
func GetDynamicBaseParser(logPattern string) BaseParser {
	regexString, indexMap := GenerateRegexString(logPattern)
	regex := regexp.MustCompile(regexString)

	b := NewBaseParserFromRegex(regex)

	for k, v := range indexMap {
		switch k {
		case "%m":
			b.SetTimeIndex(v)
		case "%t":
			b.SetTimeIndex(v)
		case "%s":
			b.SetTimeIndex(v)
		case "%u":
			b.SetUserIndex(v)
		case "%d":
			b.SetDatabaseIndex(v)
		case "%h":
			b.SetHostIndex(v)
		case "%r":
			b.SetHostIndex(v)
		case "%e":
			b.SetErrorCodeIndex(v)
		}
	}

	b.SetLogLevelIndex(len(indexMap) + 3)

	return b
}
