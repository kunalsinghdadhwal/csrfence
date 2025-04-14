package db

import (
	"github.com/kunalsinghdadhwal/csrfence/db/models"
	"github.com/kunalsinghdadhwal/csrfence/randomstrings"
)

var users = map[string]models.User{}

var refreshTokens map[string]string

func InitDB() {
	refreshTokens = make(map[string]string)
}

func StoreUser(username string, password string, role string) (uuid string, err error) {
	uuid, err = randomstrings.GenerateRamdonString(32)
	if err != nil {
		return "", err
	}

	u := models.User{}
	for u != users[uuid] {
		uuid, err = randomstrings.GenerateRamdonString(32)
		if err != nil {
			return "", err
		}
	}

	passwordHash, hashErr := generateBcryptHash(password)
	if err != nil {
		err = hashErr
		return
	}
	users[uuid] = models.User{username, passwordHash, role}

	return uuid, err
}
