package models

import (
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/kunalsinghdadhwal/csrfence/randomstrings"
)

type User struct {
	Username,
	PasswordHash,
	Role string
}

type TokenClaims struct {
	jwt.StandardClaims
	Role string `json:"role"`
	Csrf string `json:"csrf"`
}

const RefreshTokenValidTime = time.Hour * 72
const AuthTokenValidTime = time.Hour

func GenerateCSRFSecret() (string, error) {
	return randomstrings.GenerateRamdonString(32)
}
