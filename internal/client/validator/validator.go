package validator

import (
	"log"
	"os"
)

// CheckStringToken - check string token
func CheckStringToken(token string, length int) bool {
	return len(token) >= length
}

// CheckFileExistence - check that given file exists
func CheckFileExistence(path string) bool {
	if _, err := os.OpenFile(path, os.O_RDONLY, 0777); err != nil {
		log.Println(err)
		return false
	}
	return true
}
