package utils

import "strings"

func AraryToHumanReadableString(arr []string) string {
	if len(arr) < 2 {
		return strings.Join(arr, "")
	}

	allButLast := arr[:len(arr)-1]
	last := arr[len(arr)-1]

	return strings.Join(allButLast, ", ") + " and " + last
}

func Chunks(v string, maxChunkSize int) []string {

	words := strings.Fields(v)

	var chunks []string
	var currentChunk string

	for _, word := range words {
		if len(currentChunk)+len(word)+1 > maxChunkSize {
			chunks = append(chunks, currentChunk)
			currentChunk = ""
		}
		if currentChunk == "" {
			currentChunk = word
		} else {
			currentChunk += " " + word
		}
	}
	if currentChunk != "" {
		chunks = append(chunks, currentChunk)
	}

	return chunks
}

func TrimSpaceArray(arr []string) []string {
	var result []string
	for _, v := range arr {
		result = append(result, strings.TrimSpace(v))
	}
	return result
}
