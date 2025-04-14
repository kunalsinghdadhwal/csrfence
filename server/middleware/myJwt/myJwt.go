package myJwt

import (
	"crypto/rsa"
	"os"

	"github.com/dgrijalva/jwt-go"
	"github.com/kunalsinghdadhwal/csrfence/db/models"
)

const (
	privKeyPath = "keys/app.rsa.pem"
	pubKeyPath  = "keys/app.rsa_pub.pem"
)

var (
	verifyKey *rsa.PublicKey
	signKey   *rsa.PrivateKey
)

func InitJWT() error {
	signBytes, err := os.ReadFile(privKeyPath)
	if err != nil {
		return err
	}

	signKey, err = jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	if err != nil {
		return err
	}

	verifyBytes, err := os.ReadFile(pubKeyPath)
	if err != nil {
		return err
	}

	verifyKey, err = jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
	if err != nil {
		return err
	}

	return nil
}

func CreateNewTokens(uuid string, role string) (authTokenString, refreshTokenString, csrfSecret string, err error) {
	csrfSecret, err = models.GenerateCSRF()
}