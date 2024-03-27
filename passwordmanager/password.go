package passwordmanager

import (
	"math/rand"
	"time"
)

const (
	lowercaseChars string = "abcdefghijklmnopqrstuvwxyz"
	uppercaseChars string = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digitChars     string = "0123456789"
	specialChars   string = "~`!@#$%^&*()_+-=:;\"',.<>/?"
)

// GeneratePassword generates a random password
func GeneratePassword(passwordLength, digitsCount, uppercaseCount, specialCount int) string {
	rand.New(rand.NewSource(time.Now().UnixNano()))

	digits := extract(digitChars, digitsCount)
	uppercaseChars := extract(uppercaseChars, uppercaseCount)
	specialChars := extract(specialChars, specialCount)

	remainingChars := extract(lowercaseChars, passwordLength-(digitsCount+uppercaseCount+specialCount))

	rawPassword := digits + uppercaseChars + specialChars + remainingChars
	finalPassword := shuffle(rawPassword)

	return finalPassword
}

// extract returns random characters of input length from the input chars
func extract(chars string, length int) (str string) {
	for i := 0; i < length; i++ {
		id := rand.Intn(len(chars))
		str += string(chars[id])
	}

	return
}

// shuffle shuffles the input string
func shuffle(s string) string {
	r := []rune(s)
	rand.Shuffle(len(r), func(i, j int) { r[i], r[j] = r[j], r[i] })
	return string(r)
}
