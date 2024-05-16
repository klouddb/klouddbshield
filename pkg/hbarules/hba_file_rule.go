package hbarules

import "sort"

/*
	HBA file rule will be like a map
	[database] => [user] => []hbaline

	hbalie => {
		linenumber: 1,
		addressParser
		matchingEntrycount: 1,
	}
*/

type HbaRuleValidator interface {
	ValidateEntry(database, username, address string)
}

type hbaFileRule struct {
	m map[string] /*database*/ map[string] /*username*/ []*hbaLine
}

func NewHBAFileRule() *hbaFileRule {
	return &hbaFileRule{
		m: make(map[string]map[string][]*hbaLine),
	}
}

func (h *hbaFileRule) Add(database, username string, line *hbaLine) {
	if _, ok := h.m[database]; !ok {
		h.m[database] = make(map[string][]*hbaLine)
	}

	if _, ok := h.m[database][username]; !ok {
		h.m[database][username] = make([]*hbaLine, 0)
	}

	h.m[database][username] = append(h.m[database][username], line)
}

func (h *hbaFileRule) ValidateEntry(database, username, address string) {
	var lines []*hbaLine

	if _, ok := h.m[database]; ok {
		lines = append(lines, h.m[database][username]...)
		lines = append(lines, h.m[database]["all"]...)
	}

	if _, ok := h.m["sameuser"]; ok && database == username {
		lines = append(lines, h.m["sameuser"][username]...)
		lines = append(lines, h.m["sameuser"]["all"]...)
	}

	if _, ok := h.m["samerole"]; ok && database == username {
		lines = append(lines, h.m["samerole"][username]...)
		lines = append(lines, h.m["samerole"]["all"]...)
	}

	if _, ok := h.m["all"]; ok {
		lines = append(lines, h.m["all"][username]...)
		lines = append(lines, h.m["all"]["all"]...)
	}

	// short lines by line number
	sort.Slice(lines, func(i, j int) bool {
		return lines[i].lineNumber < lines[j].lineNumber
	})

	for _, line := range lines {
		if line.addressParser.IsValid(address) {
			line.FoundMatchingEntry()
			return
		}
	}
}

func (h *hbaFileRule) GetUnusedLines() []int {
	unusedLineMap := map[int]bool{}

	for _, db := range h.m {
		for _, user := range db {
			for _, line := range user {
				unusedLineMap[line.lineNumber] = unusedLineMap[line.lineNumber] || line.matchingEntrycount != 0
			}
		}
	}

	// map to int
	unusedLines := sort.IntSlice{}
	for k, used := range unusedLineMap {
		if !used {
			unusedLines = append(unusedLines, k)
		}
	}

	unusedLines.Sort()
	return unusedLines
}

type hbaLine struct {
	lineNumber         int
	addressParser      AddressValidator
	matchingEntrycount int
}

func NewHBALine(lineNumber int, addressParser AddressValidator) *hbaLine {
	return &hbaLine{
		lineNumber:    lineNumber,
		addressParser: addressParser,
	}
}

// FoundMatchingEntry will increment the matching entry count
func (h *hbaLine) FoundMatchingEntry() {
	h.matchingEntrycount++
}
