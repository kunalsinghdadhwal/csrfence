package randomstrings

import (
	"crypto/rand"
	"encoding/base64"
)

func GenerateRandomBytes(len int) ([]byte, error) {
	b := make([]byte, len)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func GenerateRamdonString(len int) (string, error) {
	b, err := GenerateRandomBytes(len)
	return base64.URLEncoding.EncodeToString(b), err
}