package db

import (
	"errors"
	"log"

	"github.com/kunalsinghdadhwal/csrfence/db/models"
	"github.com/kunalsinghdadhwal/csrfence/randomstrings"
	"golang.org/x/crypto/bcrypt"
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

func DeleteUser(uuid string) {
	delete(users, uuid)
}

func FetchUserById(uuid string) (models.User, error) {
	user := users[uuid]
	blankUser := models.User{}
	if blankUser != user {
		return user, nil
	}

	return user, errors.New("User not Found with this UUID")
}

func FetchUserByUsername(username string) (models.User, string, error) {
	for k, v := range users {
		if v.Username == username {
			return v, k, nil
		}
	}

	return models.User{}, "", errors.New("User not Found with this username")
}

func StoreRefreshToken() (jti string, err error) {
	jti, err = randomstrings.GenerateRamdonString(32)
	if err != nil {
		return jti, err
	}

	for refreshTokens[jti] != "" {
		jti, err = randomstrings.GenerateRamdonString(32)
		if err != nil {
			return jti, err
		}
	}

	refreshTokens[jti] = "valid"
	return jti, err
}

func DeleteRefreshToken(jti string) {
	delete(refreshTokens, jti)
}

func CheckRefreshToken(jti string) bool {
	return refreshTokens[jti] != ""
}

func LogUserIn(username string, password string) (models.User, string, error) {
	user, uuid, err := FetchUserByUsername(username)
	log.Println(user, uuid, err)
	if err != nil {
		return models.User{}, "", err
	}

	return user, uuid, checkPasswordAgainstHash(user.PasswordHash, password)
}

func generateBcryptHash(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hash[:]), err
}

func checkPasswordAgainstHash(hash string, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}
