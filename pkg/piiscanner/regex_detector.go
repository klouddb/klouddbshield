package piiscanner

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

type RegexWithWeight struct {
	Regexp *regexp.Regexp
	Weight float64
}

// baseRegexDetector is a base helper for regex detectors.
// It contains a map of PIILabel for list of regexes. And also check
// all regexes for each PIILabel and return the first match.
//
// To Create Any new regex detector, you can embed this struct and
// implement Init() method which populate the map with PIILabel and
// list of regexes.
type baseRegexDetector struct {
	m map[PIILabel][]RegexWithWeight
}

func (r *baseRegexDetector) Name() string {
	return "regex"
}

// Detect checks the word against all regexes for each PIILabel and
// returns the first match.
func (r *baseRegexDetector) Detect(ctx context.Context, word string) ([]PiiLabelWithWeight, error) {
	if r.m == nil {
		return nil, fmt.Errorf("regex detector not initialized")
	}

	word = strings.ToLower(word)

	var out []PiiLabelWithWeight
	for label, regexes := range r.m {
		for _, v := range regexes {
			if v.Regexp.MatchString(word) {
				out = append(out, PiiLabelWithWeight{
					PIILabel: label,
					Weight:   v.Weight,
				})
				break
			}
		}
	}

	return out, nil
}

// regexColumnDetector is a detector which uses regexes to detect
// PIILabels for columns.
//
// It uses some common regexes for some known column name patterns.
type regexColumnDetector struct {
	*baseRegexDetector
}

// NewRegexColumnDetector returns a new regex column detector
func NewRegexColumnDetector() Detector {
	return &regexColumnDetector{
		baseRegexDetector: &baseRegexDetector{},
	}
}

// Init populates the map with PIILabel and list of regexes for
// known column name patterns.
func (r *regexColumnDetector) Init() error {
	r.m = map[PIILabel][]RegexWithWeight{
		PIILabel_Username: {
			{
				Regexp: regexp.MustCompile(`(?i)^(user[\s_-]?name|user)$`),
				Weight: 1.0,
			},
			{
				Regexp: regexp.MustCompile(`(?i)^.*(user|login).*$`),
				Weight: 0.3,
			},
		},
		PIILabel_Name: {
			{
				Regexp: regexp.MustCompile(`(?i)^(first[\s_-]?name|f[\s_-]?name|last[\s_-]?name|l[\s_-]?name|full[\s_-]?name|full[\s_-]?name|maiden[\s_-]?name|nick[\s_-]?name|person)$`),
				Weight: 1.0,
			},
			{
				// because exact match with column name "name" is low confidence match
				Regexp: regexp.MustCompile(`(?i)^(name)$`),
				Weight: 0.3,
			},
			{
				Regexp: regexp.MustCompile(`(?i)(first[\s_-]?name|f[\s_-]?name|last[\s_-]?name|l[\s_-]?name|full[\s_-]?name|full[\s_-]?name|maiden[\s_-]?name|nick[\s_-]?name|person)`),
				Weight: 0.5,
			},
			{
				Regexp: regexp.MustCompile(`(?i)^.*(_name|name).*$`),
				Weight: 0.3,
			},
		},
		PIILabel_Email: {
			{
				Regexp: regexp.MustCompile(`(?i)^(mail|email|email[\s_-]?address|e[\s_-]?mail)$`),
				Weight: 1.0,
			},
			{
				Regexp: regexp.MustCompile(`(?i)^.*(mail).*$`),
				Weight: 0.5,
			},
		},
		PIILabel_Phone: {
			{
				Regexp: regexp.MustCompile(`(?i)^(phone|phone[\s_-]?number|phone[\s_-]?no|phone[\s_-]?num|tele[\s_-]?phone|tele[\s_-]?phone[\s_-]?num|tele[\s_-]?phone[\s_-]?no)$`),
				Weight: 1.0,
			},
			{
				Regexp: regexp.MustCompile(`(?i)(phone[\s_-]?number|phone[\s_-]?no|phone[\s_-]?num|tele[\s_-]?phone|tele[\s_-]?phone[\s_-]?num|tele[\s_-]?phone[\s_-]?no)`),
				Weight: 0.5,
			},
			{
				Regexp: regexp.MustCompile(`(?i)^.*(phone).*$`),
				Weight: 0.3,
			},
		},
		PIILabel_IPAddress: {
			{
				Regexp: regexp.MustCompile(`(?i)^(ip|ip[\s_-]?address|ip[\s_-]?address[\s_-]?v4|ip[\s_-]?address[\s_-]?v6)$`),
				Weight: 1.0,
			},
			{
				Regexp: regexp.MustCompile(`(?i)(ip[\s_-]?address|ip[\s_-]?address[\s_-]?v4|ip[\s_-]?address[\s_-]?v6)`),
				Weight: 0.5,
			},
			{
				Regexp: regexp.MustCompile(`(?i)^.*([\s_-]ip[\s_-]).*$`),
				Weight: 0.3,
			},
		},
		PIILabel_MacAddress: {
			{
				Regexp: regexp.MustCompile(`(?i)^(mac|mac[\s_-]?address)$`),
				Weight: 1.0,
			},
			{
				Regexp: regexp.MustCompile(`(?i)^.*([\s_-]?mac[\s_-]?).*$`),
				Weight: 0.3,
			},
		},
		PIILabel_Address: {
			{
				Regexp: regexp.MustCompile(`(?i)^(address|city|state|county|country|zone|borough)$`),
				Weight: 0.8,
			},
			{
				Regexp: regexp.MustCompile(`(?i)^.*(address|city|state|county|country|zone|borough).*$`),
				Weight: 0.3,
			},
		},
		PIILabel_PANNumber: {
			{
				Regexp: regexp.MustCompile(`(?i)\b(pan|permanent|tax|taxpayer|personal|unique)[-_\s]?(num|identification|number|code|no|card|#|id)?\b`),
				Weight: 0.8,
			},
			{
				Regexp: regexp.MustCompile(`(?i)\b(pan|permanent|tax|taxpayer|personal|unique)[-_\s]?(account|num|payer|identification|number|code|no|card|id|#)[-_\s]?(num|identification|number|id|code|no|card|#|id)?[-_\s]?(pan)?\b`),
				Weight: 0.9,
			},
			{
				Regexp: regexp.MustCompile(`(?i)\bpermanent[-_\s]?account[-_\s]?(num|number|code|no|card|#|id)[-_\s]?(pan)?\b`),
				Weight: 0.9,
			},
			{
				Regexp: regexp.MustCompile(`(?i)\b(num|number|account)[-_\s]?(PAN|pan)\b`),
				Weight: 0.5,
			},
			{
				Regexp: regexp.MustCompile(`(?i)^.*[-_\s]pan[-_\s].*$`),
				Weight: 0.4,
			},
			{
				Regexp: regexp.MustCompile(`(?i)(tax)[-_\s]?(number|id|no|#|num)`),
				Weight: 0.4,
			},
			{
				Regexp: regexp.MustCompile(`(?i)(^pan|pan$)`),
				Weight: 0.3,
			},
		},
		PIILabel_AdharcardNumber: {
			{
				Regexp: regexp.MustCompile(`(?i)\b(adhar|adhaar|aadhar|uid)[\s_-]?(identity|number|id|no|card|#)?\b`),
				Weight: 0.8,
			},
			{
				Regexp: regexp.MustCompile(`(?i)(adhar|adhaar|aadhar|uid)[\s_-]?(identity|number|id|no|card|#)?`),
				Weight: 0.5,
			},
			{
				Regexp: regexp.MustCompile(`(?i)[^\s_-](adhar|adhaar|aadhar|uid)[$\s_-]`),
				Weight: 0.4,
			},
		},
		PIILabel_DrivingLicenceNumber: {
			{
				Regexp: regexp.MustCompile(`(?i)\b(driver|driving|licence|license|dl)[\s_-]?(identity|number|id|no|card|#)?\b`),
				Weight: 0.8,
			},
			{
				Regexp: regexp.MustCompile(`(?i)(driver|driving)[\s_-]?(licence|license)`),
				Weight: 0.8,
			},
			{
				Regexp: regexp.MustCompile(`(?i)(driver|driving|licence|license|dl)[\s_-]?(identity|number|id|no|card|#)?`),
				Weight: 0.5,
			},
		},
		PIILabel_Password: {
			{
				Regexp: regexp.MustCompile(`(?i)^(password|pass|passphrase|passkey)$`),
				Weight: 1.0,
			},
			{
				Regexp: regexp.MustCompile(`(?i)(password|passphrase|passkey)`),
				Weight: 0.5,
			},
			{
				Regexp: regexp.MustCompile(`(?i)^.*pass.*$`),
				Weight: 0.3,
			},
		},
		PIILabel_CreditCard: {
			{
				Regexp: regexp.MustCompile(`(?i)^(credit[\s-_]?card|cc[\s-_]?number|cc[\s-_]?num|credit[\s-_]?card[\s-_]?num|credit[\s-_]?card[\s-_]?number)$`),
				Weight: 1.0,
			},
			{
				Regexp: regexp.MustCompile(`(?i)\b(credit[\s-_]?card|cc[\s-_]?number|cc[\s-_]?num|credit[\s-_]?card[\s-_]?num|credit[\s-_]?card[\s-_]?number)\b`),
				Weight: 0.8,
			},
		},
		PIILabel_SSN: {
			{
				Regexp: regexp.MustCompile(`(?i)^(ssn|social[\s-_]?number|social[\s-_]?security|social[\s-_]?security[\s-_]?number|social[\s-_]?security[\s-_]?no)$`),
				Weight: 1.0,
			},
			{
				Regexp: regexp.MustCompile(`(?i)^.*(social[\s-_]?number|social[\s-_]?security|social[\s-_]?security[\s-_]?number|social[\s-_]?security[\s-_]?no).*$`),
				Weight: 0.8,
			},
			{
				Regexp: regexp.MustCompile(`(?i)^.*(ssn).*$`),
				Weight: 0.3,
			},
		},
		PIILabel_PoBox: {
			{
				Regexp: regexp.MustCompile(`(?i)^.*(po[\s-_]?box).*$`),
				Weight: 1.0,
			},
		},
		PIILabel_ZipCode: {
			{
				Regexp: regexp.MustCompile(`(?i)^(zip[\s-_]?code|postal|postal[\s-_]?code|zip)$`),
				Weight: 1.0,
			},
			{
				Regexp: regexp.MustCompile(`(?i)^.*(postal|zip).*$`),
				Weight: 0.3,
			},
		},
		PIILabel_BirthDate: {
			{
				Regexp: regexp.MustCompile(`(?i)^.*(date[\s-_]?of[\s-_]?birth|dob|birth[\s-_]?day|date[\s-_]?of[\s-_]?death|birth[\s-_]?date).*$`),
				Weight: 1.0,
			},
		},
		PIILabel_Location: {
			{
				Regexp: regexp.MustCompile(`(?i)^(lat|long|lng|latitude|longitude|location)$`),
				Weight: 1.0,
			},
			{
				Regexp: regexp.MustCompile(`(?i)^.*(location|latitude|longitude).*$`),
				Weight: 0.8,
			},
			{
				Regexp: regexp.MustCompile(`(?i)^.*(geo|lat|long|lng).*$`),
				Weight: 0.3,
			},
		},
		PIILabel_OAuthToken: {
			{
				Regexp: regexp.MustCompile(`(?i)^(oauth|oauth[\s-_]?token|oauth[\s-_]?token[\s-_]?secret|oauth[\s-_]?token[\s-_]?secret|oauth[\s-_]?verifier|oauth[\s-_]?verifier|oauth[\s-_]?verifier[\s-_]?secret|oauth[\s-_]?verifier[\s-_]?secret)$`),
				Weight: 1.0,
			},
			{
				Regexp: regexp.MustCompile(`(?i)(oauth|oauth[\s-_]?token|oauth[\s-_]?token[\s-_]?secret|oauth[\s-_]?token[\s-_]?secret|oauth[\s-_]?verifier|oauth[\s-_]?verifier|oauth[\s-_]?verifier[\s-_]?secret|oauth[\s-_]?verifier[\s-_]?secret)`),
				Weight: 0.8,
			},
			{
				Regexp: regexp.MustCompile(`(?i)(token|oauth)`),
				Weight: 0.4,
			},
		},
		PIILabel_NHSNumber: {
			{
				Regexp: regexp.MustCompile(`(?i)\b((patient|reg|record|healthcare)?[\s-_]?(nhs|nh[\s-_]?service)[\s-_]?(healthcare|reference|patient|reg|record|healthcare|id)?[\s-_]?(record|identification|number|num|id))\b`),
				Weight: 0.5,
			},
			{
				Regexp: regexp.MustCompile(`(?i)\b((national)?[\s-_]?health[\s-_]?(service)?[\s-_]?(number|num|id))\b`),
				Weight: 0.3,
			},
			{
				Regexp: regexp.MustCompile(`(?i)\b(healthcare[\s-_]?(record|identification|number|num|id)[\s-_]?(record|identification|number|num|id)?)\b`),
				Weight: 0.1,
			},
		},
		PIILabel_Nationality: {
			{
				Regexp: regexp.MustCompile(`(?i)^.*(nationality).*$`),
				Weight: 1.0,
			},
		},
		PIILabel_Gender: {
			{
				Regexp: regexp.MustCompile(`(?i)^.*(gender).*$`),
				Weight: 1.0,
			},
		},
		PIILabel_BankAccountNumber: {
			{
				Regexp: regexp.MustCompile(`(?i)\b(?:bank|checking|savings)?[-_\s]?(?:account|acct|acnt|ac|acc)[-_\s]?(?:number|num|no|#)?[-_\s]?(?:#)?\b`),
				Weight: 0.7,
			},
		},
		PIILabel_GSTIN: {
			{
				Regexp: regexp.MustCompile(`(?i)^.*(gstin|gst).*$`),
				Weight: 0.5,
			},
		},
	}
	return nil
}

// regexValueDetector is a detector which uses regexes to detect
// PIILabels for values.
//
// It uses some common regexes for some known value patterns.
type regexValueDetector struct {
	*baseRegexDetector
}

// NewRegexValueDetector returns a new regex value detector
func NewRegexValueDetector() Detector {
	return &regexValueDetector{
		baseRegexDetector: &baseRegexDetector{},
	}
}

// Init populates the map with PIILabel and list of regexes for
// known value patterns.
func (r *regexValueDetector) Init() error {
	r.m = map[PIILabel][]RegexWithWeight{
		PIILabel_Email: {
			{
				Regexp: regexp.MustCompile(`\b[\w][\w+.-]+(@|%40)[a-z\d-]+(\.[a-z\d-]+)*\.[a-z]+\b`),
				Weight: 1.0,
			},
			{
				Regexp: regexp.MustCompile(`(?i)([A-Za-z0-9!#$%&'*+\/=?^_{|.}~-]+@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)`),
				Weight: 1.0,
			},
		},
		PIILabel_PANNumber: {
			{
				Regexp: regexp.MustCompile(`\b([A-Za-z]{3}[AaBbCcFfGgHhJjLlPpTt]{1}[A-Za-z]{1}[0-9]{4}[A-Za-z]{1})\b`),
				Weight: 0.85,
			},
			{
				Regexp: regexp.MustCompile(`\b([A-Za-z]{5}[0-9]{4}[A-Za-z]{1})\b`),
				Weight: 0.85,
			},
			// {
			// 	Regexp: regexp.MustCompile(`\b((?=.*?[a-zA-Z])(?=.*?[0-9]{4})[\w@#$%^?~-]{10})\b`),
			// 	Weight: 0.05,
			// },
		},
		PIILabel_DrivingLicenceNumber: {
			{
				// indian driving license regex
				Regexp: regexp.MustCompile(`(?i)\b([a-z]{2}[\s_-]?[0-9]{2}[\s_-]?(?:19|20)[0-9]{2}[\s_-]?[0-9]{7})\b`),
				Weight: 1,
			},
			{
				// Montana driving license regex
				Regexp: regexp.MustCompile(`\b(?:0[1-9]|1[0-2])[0-9]{3}[1-9][0-9]{3}41(?:0[1-9]|1[0-9]|2[0-9]|3[0-1])\b`),
				Weight: 1,
			},
			{
				// New Hampshire driving license regex
				Regexp: regexp.MustCompile(`(?i)\b(?:0[1-9]|1[0-2])[A-Z]{3}[0-9]{2}(?:0[1-9]|1[0-9]|2[0-9]|3[0-1])[0-9]\b`),
				Weight: 1,
			},
			{
				// Washington driving license regex
				Regexp: regexp.MustCompile(`(?i)\b(?:[A-Z]{5}|[A-Z]{4}[*]{1}|[A-Z]{3}[*]{2}|[A-Z]{2}[*]{3})[A-Z]{2}[0-9]{3}[A-Z0-9]{2}\b`),
				Weight: 1,
			},
			{
				// West Virginia and california driving license regex
				Regexp: regexp.MustCompile(`(?i)\b[A-Z][0-9]{6,7}\b`),
				Weight: 1,
			},
			{
				// Washington, Sept 2018 onwards driving license regex
				Regexp: regexp.MustCompile(`(?i)\bWDL[A-Z0-9]{9}\b`),
				Weight: 1,
			},
			{
				Regexp: regexp.MustCompile(`(?i)\b([A-Z]{2}[0-9]{6}[A-Z]?)|([A-Z]{3}[\s_-][0-9]{2}[\s_-][0-9]{4})|([0-9]{3}[A-Z]{2}[0-9]{4})\b`),
				Weight: 0.7,
			},
			{
				Regexp: regexp.MustCompile(`(?i)\b(([0-9]{7}[A-Z])|([1-9]{2}[0-9]{5}))\b`),
				Weight: 0.7,
			},
			{
				// Minnesota driving license regex
				Regexp: regexp.MustCompile(`(?i)\b[A-Z][0-9]{12}\b`),
				Weight: 0.5,
			},
			{
				// Missouri driving license regex
				Regexp: regexp.MustCompile(`(?i)\b[A-Z][0-9]{9}\b`),
				Weight: 0.5,
			},
			{
				Regexp: regexp.MustCompile(`(?i)\b[A-Z][0-9]{2}[\s_-]?(?:(?:[0-9]{3}[\s_-]?[0-9]{3})|(?:[0-9]{2}[\s_-]?[0-9]{4}))\b`),
				Weight: 0.5,
			},
			{
				Regexp: regexp.MustCompile(`(?i)\b[A-Z][\s_-]?[0-9]{3}[\s_-][0-9]{3}[\s_-](?:(?:[0-9]{2}[\s_-][0-9]{3}[\s_-][0-9])|(?:[0-9]{3}[\s_-][0-9]{3}))\b`),
				Weight: 0.5,
			},
			{
				Regexp: regexp.MustCompile(`(?i)\b[A-Z][0-9]{3}[\s_-][0-9]{4}[\s_-][0-9]{4}(?:[\s_-][0-9]{2})?\b`),
				Weight: 0.5,
			},
			{
				// Pennsylvania driving license regex
				Regexp: regexp.MustCompile(`\b[0-9]{2}[\s_-][0-9]{3}[\s_-][0-9]{3}\b`),
				Weight: 0.5,
			},
			{
				Regexp: regexp.MustCompile(`(?i)\b[A-Z][0-9]{4}[\s_-][0-9]{5}[\s_-][0-9]{5}\b`),
				Weight: 0.5,
			},
			{
				// Arkansas driving license regex
				Regexp: regexp.MustCompile(`(?i)\b9[0-9]{8}\b`),
				Weight: 0.5,
			},
			{
				Regexp: regexp.MustCompile(`(?i)\b(?:(?:[0-9]{2}[\s_-][0-9]{3})|(?:[0-9]{3}[\s_-][0-9]{2}))[\s_-][0-9]{4}\b`),
				Weight: 0.3,
			},
			{
				// \b[0-9]{7}\b => Alabama, Alaska, Delaware, Georgia, Maine, Montana, Oregon, South Carolina, Washington, D.C., West Virginia
				// \b[0-9]{8}\b => South Dakota, Rhode Island, Tennessee, Texas, Vermont
				// \b[0-9]{9}\b => Connecticut, Louisiana, New Mexico, Idaho, Iowa, Mississippi, Oklahoma, South Dakota, Tennessee, Utah
				Regexp: regexp.MustCompile(`(?i)\b[0-9]{7,9}\b`),
				Weight: 0.3,
			},
			{
				// Canada
				Regexp: regexp.MustCompile(`(?i)\b(([0-9]{4}-[0-9]{2}-[0-9]{4})|(?i:\b[A-Z][0-9]{4}[\s_-]?[0-9]{5}[\s_-][0-9]{5}\b))\b`),
				Weight: 0.3,
			},
			{
				Regexp: regexp.MustCompile(`(?i)\b[0-9]{6}[\s_-][0-9]{3}\b`),
				Weight: 0.3,
			},
			{
				// North Carolina driving license regex
				Regexp: regexp.MustCompile(`(?i)\b[0-9]{12}\b`),
				Weight: 0.3,
			},
		},
		PIILabel_ITIN: {
			{
				Regexp: regexp.MustCompile(`(?i)\b9\d{2}[-\s](5\d|6[0-5]|7\d|8[0-8]|9([0-2]|[4-9]))[-\s]\d{4}\b`),
				Weight: 0.7,
			},
			{
				Regexp: regexp.MustCompile(`(?i)\b9\d{2}(5\d|6[0-5]|7\d|8[0-8]|9([0-2]|[4-9]))\d{4}\b`),
				Weight: 0.3,
			},
			{
				Regexp: regexp.MustCompile(`(?i)\b9\d{2}[-\s](5\d|6[0-5]|7\d|8[0-8]|9([0-2]|[4-9]))\d{4}\b|\b9\d{2}(5\d|6[0-5]|7\d|8[0-8]|9([0-2]|[4-9]))[-s]\d{4}\b`),
				Weight: 0.05,
			},
		},
		PIILabel_Gender: {
			{
				Regexp: regexp.MustCompile(`(?i)^(male|female|girl|boy|other|prefer[\s-_]?not[\s-_]?to[\s-_]?say|prefer[\s-_]?not[\s-_]?to[\s-_]?disclose|not[\s-_]?specified|transgender|non[\s-_]?binary)$`),
				Weight: 1.0,
			},
			{
				Regexp: regexp.MustCompile(`(?i)^.*(gender).*$`),
				Weight: 0.5,
			},
			{
				Regexp: regexp.MustCompile(`(?i)^(m|f|n)$`),
				Weight: 0.3,
			},
		},
		PIILabel_Phone: {
			{
				Regexp: regexp.MustCompile(`(\b(\+\d{1,2}\s)?\(?\d{3}\)?[\s+.-]\d{3}[\s+.-]\d{4}\b)|((?:\+|%2B)[1-9]\d{6,14}\b)`),
				Weight: 0.9,
			},
			{
				Regexp: regexp.MustCompile(`^\+?(\d{1,3})?[\s.-]?\(?\d{4}\)?[\s.-]?\d{3}[\s.-]?\d{3}$`),
				Weight: 0.7,
			},
			{
				Regexp: regexp.MustCompile(`^\+?(\d{1,3})?[\s.-]?\(?\d{5}\)?[\s.-]?\d{5}$`),
				Weight: 0.8,
			},
			{
				Regexp: regexp.MustCompile(`^((?:\+?\d{1,3}[-.\s*]?)?(?:\(?\d{3}\)?[-.\s*]?)?\d{3}[-.\s*]?\d{4}|(?:\+?\d{2}\s*\d{2}\s*\d{3}\s*\d{4}))$`),
				Weight: 0.5,
			},
			{
				Regexp: regexp.MustCompile(`(?i)^\+?(\d{1,3})?[\s.-]?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}$`),
				Weight: 0.5,
			},
		},
		PIILabel_CreditCard: {
			{
				Regexp: regexp.MustCompile(`\b([3456]\d{3}[\s+-]\d{4}[\s+-]\d{4}[\s+-]\d{4})|([3456]\d{15})\b`),
				Weight: 1.0,
			},
			// {
			// 	Regexp: regexp.MustCompile(`((?:(?:\\d{4}[- ]?){3}\\d{4}|\\d{15,16}))(?![\\d])`),
			// 	Weight: 1.0,
			// },
		},
		PIILabel_VoterID: {
			{
				Regexp: regexp.MustCompile(`(?i)\b[A-Z]{3}\d{7}\b`),
				Weight: 0.8,
			},
		},
		PIILabel_GSTIN: {
			{
				Regexp: regexp.MustCompile(`(?i)\b[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[1-9A-Z]{1}Z[0-9A-Z]{1}\b`),
				Weight: 0.5,
			},
		},
		PIILabel_VehicleNumber: {
			{
				Regexp: regexp.MustCompile(`(?i)\b[A-Z]{2}[\\ -]?[0-9]{2}[\\ -]?[A-Z]{1,2}[\\ -]?[0-9]{4}\b`),
				Weight: 0.8,
			},
		},
		PIILabel_SSN: {
			{
				Regexp: regexp.MustCompile(`\b\d{3}[\s+-]\d{2}[\s+-]\d{4}\b`),
				Weight: 0.5,
			},
		},
		PIILabel_ZipCode: {
			{
				// instead of \b we are using ^ and $ to match the whole string to avoid false positives
				// e.g => 12345 67890 value is invalid for zip code but it matches if we use \b
				Regexp: regexp.MustCompile(`^\d{5}(?:[-\s]\d{4})?$`),
				Weight: 1.0,
			},
		},
		PIILabel_IPAddress: {
			{
				Regexp: regexp.MustCompile(`\b(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)(:\d{1,5})?\b`), //ipv4
				Weight: 1.0,
			},
			// regexp.MustCompile(`^(([0-9a-fA-F]{1,4}:){7}([0-9a-fA-F]{1,4})|(([0-9a-fA-F]{1,4}:){1,7}|:):((:[0-9a-fA-F]{1,4}){1,7}|:))$`),
		},
		PIILabel_MacAddress: {
			{
				Regexp: regexp.MustCompile(`\b[0-9a-fA-F]{2}(?:(?::|%3A)[0-9a-fA-F]{2}){5}\b`),
				Weight: 1.0,
			},
		},
		PIILabel_OAuthToken: {
			{
				Regexp: regexp.MustCompile(`ya29\..{60,200}`), // google oauth token
				Weight: 0.3,
			},
		},
		PIILabel_NHSNumber: {
			{
				Regexp: regexp.MustCompile(`\b[A-CEGHJ-PR-TW-Z]{1}[A-CEGHJ-NPR-TW-Z]{1}[0-9]{6}[A-DFM]{0,1}\b`),
				Weight: 0.3,
			},
		},
		PIILabel_Address: {
			{
				Regexp: regexp.MustCompile(`(?i)\b\d+\b.{4,60}\b(st|street|ave|avenue|road|rd|drive|dr)\b`),
				Weight: 0.8,
			},
			{
				Regexp: regexp.MustCompile(`\d{1,4} [\w\s]{1,20}(street|st|avenue|ave|road|rd|highway|hwy|square|sq|trail|trl|drive|dr|court|ct|park|parkway|pkwy|circle|cir|boulevard|blvd)\W?(\s|$)`),
				Weight: 0.8,
			},
		},
		PIILabel_PoBox: {
			{
				Regexp: regexp.MustCompile(`(?i)P\.? ?O\.? Box \d+`),
				Weight: 0.8,
			},
		},
	}
	return nil
}
