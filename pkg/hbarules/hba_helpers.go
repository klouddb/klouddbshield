package hbarules

import (
	"bufio"
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/klouddb/klouddbshield/model"
	"github.com/klouddb/klouddbshield/pkg/utils"
)

var addressMapping = map[string]string{
	"all":       "0.0.0.0/0",
	"localhost": "127.0.0.1/32",
}

// ScanHBAFile will scan the hba file from filepath and return []model.HBAFIleRules
func ScanHBAFile(ctx context.Context, store *sql.DB, hbaFilePath string) ([]model.HBAFIleRules, error) {
	file, err := os.Open(hbaFilePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var rules []model.HBAFIleRules
	scanner := bufio.NewScanner(file)

	// Regular expression to match HBA rule lines
	re := regexp.MustCompile(`^\s*(host|hostssl|hostnossl|hostgssenc|hostnogssenc)\s+(\S+)\s+(\S+)\s+(\S+)?\s+([\d.:]+)?\s+(.+)\s*$`)

	// Read the file line by line and extract the HBA rules
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "#") || len(line) == 0 || strings.HasPrefix(line, "local") {
			// ignore comments
			continue
		}

		rule, err := ParseHBALine(ctx, store, re, lineNumber, line, hbaFilePath)
		if err != nil {
			fmt.Printf("WARN: Skipping this line (%v) at linenumber %d, because we got error while parsing (%v) \n", line, lineNumber, err)
			continue
		}

		rules = append(rules, *rule)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return rules, nil

}

func ParseHBALine(ctx context.Context, store *sql.DB, re *regexp.Regexp, lineNumber int, line, hbaFilePath string) (*model.HBAFIleRules, error) {
	match := re.FindStringSubmatch(line)
	if len(match) == 0 {
		// ignore invalid lines
		return nil, fmt.Errorf("invalid line")
	}

	username, err := updateStringWithFilenameOrRolename(ctx, store, match[3], hbaFilePath)
	if err != nil {
		return nil, err
	}

	db, err := updateStringWithFilenameOrRolename(ctx, store, match[2], hbaFilePath)
	if err != nil {
		return nil, err
	}

	return &model.HBAFIleRules{
		LineNumber: lineNumber,
		Database:   db,
		UserName:   username,
		Address:    match[4],
		NetMask:    match[5],
		Raw:        line,
	}, nil
}

func updateStringWithFilenameOrRolename(ctx context.Context, store *sql.DB, str, hbaFilePath string) (string, error) {
	list := strings.Split(str, ",")

	var updatedList []string

	for _, item := range list {
		if item == "" {
			continue
		}

		switch item[0] {
		case '@':
			filename := strings.TrimPrefix(item, "@")
			usersFromFile, err := loadListFile(filepath.Join(filepath.Dir(hbaFilePath), filename))
			if err != nil {
				return "", fmt.Errorf("error while reading users file (%v): err = (%v)", filename, err)
			}

			updatedList = append(updatedList, usersFromFile...)
		case '+':
			if store == nil {
				return "", fmt.Errorf("there is role in hba file, to get users from role we need database connection.")
			}
			roleName := strings.TrimPrefix(item, "+")
			users, err := utils.GetUserForGivenRole(ctx, store, roleName)
			if err != nil {
				return "", fmt.Errorf("error while fetching users for role (%v): err = (%v)", roleName, err)
			}

			updatedList = append(updatedList, roleName)
			updatedList = append(updatedList, users...)
		default:
			updatedList = append(updatedList, item)
		}

	}

	return strings.Join(updatedList, ","), nil
}

func loadListFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var list []string
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)

		if line == "" {
			continue
		}

		list = append(list, line)
	}

	return list, scanner.Err()
}

// ParseHBAFileRules will parse the hba file rules and return the HbaRuleValidator
func ParseHBAFileRules(rules []model.HBAFIleRules) (*hbaFileRule, error) {
	hbaFileRule := NewHBAFileRule()

	re := regexp.MustCompile(`^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[0-9a-fA-F:]+)(/\d+)$`)

	for _, r := range rules {
		if r.Address == "" {
			continue
		}

		if v, ok := addressMapping[r.Address]; ok {
			r.Address = v
			r.NetMask = ""
		}

		var addressValidator AddressValidator

		switch {
		case r.NetMask != "":

			ipnet, err := GetIPnetFromIPAndMask(r.Address, r.NetMask)
			if err != nil {
				return nil, err
			}
			addressValidator = NewIPAddressValidator(ipnet)

		case re.MatchString(r.Address):

			ipnet, err := GetIPnetFromSubnet(r.Address)
			if err != nil {
				return nil, err
			}
			addressValidator = NewIPAddressValidator(ipnet)

		default:
			addressValidator = NewHostAddressValidator(r.Address)
		}
		hbaLine := NewHBALine(r.LineNumber, addressValidator)

		hbaFileRule.lineMap[r.LineNumber] = r.Raw

		for _, db := range strings.Split(r.Database, ",") {
			for _, user := range strings.Split(r.UserName, ",") {
				if db == "" || user == "" {
					continue
				}
				hbaFileRule.Add(db, user, hbaLine)
			}
		}
	}

	return hbaFileRule, nil
}
