package validator

func CheckStringToken(token string, length int) bool {
	if len(token) < length {
		return false
	}
	return true
}
