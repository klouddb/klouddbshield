package passwordmanager

import (
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

var (
	ErrPasswordIsPwned = errors.New("password is pwned")
)

func IsPasswordPwned(password, dir string) (int, error) {
	hash := sha1.New()
	_, err := hash.Write([]byte(password))
	if err != nil {
		return 0, err
	}

	sha1Hash := strings.ToUpper(hex.EncodeToString(hash.Sum(nil)))
	partOne := sha1Hash[:5]
	partTwo := sha1Hash[5:40]

	filename := filepath.Join(dir, fmt.Sprintf("%s.txt", partOne))
	content, err := os.ReadFile(filename)
	if err != nil {
		return 0, nil
	}

	pwnedHashes := strings.Split(string(content), "\n")
	for _, pwnedHash := range pwnedHashes {
		parts := strings.Split(pwnedHash, ":")
		if len(parts) >= 2 && parts[0] == partTwo {
			times, _ := strconv.Atoi(strings.TrimSpace(parts[1]))
			return times, ErrPasswordIsPwned
		}
	}

	return 0, nil
}
