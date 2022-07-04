package utils

import (
	"golang.org/x/crypto/bcrypt"
	"github.com/golang-jwt/jwt"
	"github.com/xlzd/gotp"
	"encoding/base64"
	"time"
	"os"
	"fmt"
)

var secretLength int = 16
var totp *gotp.TOTP = gotp.NewDefaultTOTP(gotp.RandomSecret(secretLength))

type JWT_TOKEN struct {
	TokenString string
	ExpireTime time.Time
}

func HashPassword(password string) (string, error) {
	const HASH_ROUNDS = 10
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), HASH_ROUNDS)
	return string(bytes), err
}

func ComparePasswords(hashedPassword, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}

func CreateToken(displayName, tokenType string) (JWT_TOKEN, error) {
	var jwtToken JWT_TOKEN
	b64String := os.Getenv(JWT_SECRET_KEY)
	signingKey, err := base64.StdEncoding.DecodeString(b64String)
	if err != nil {
		return jwtToken, err
	}
	claims := jwt.MapClaims{}
	claims["displayName"] = displayName
	claims["tokenType"] = tokenType
	if tokenType == "refresh" {
		jwtToken.ExpireTime = time.Now().Add(time.Hour * 24 * REFRESH_TOKEN_DURATION)
	} else {
		jwtToken.ExpireTime = time.Now().Add(time.Minute * ACCESS_TOKEN_DURATION)
	}
	claims["exp"] = jwtToken.ExpireTime.Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(signingKey)
	if err != nil {
		return jwtToken, err
	}
	jwtToken.TokenString = tokenString
	return jwtToken, nil
}

func GetVerificationCode() string {
	return totp.Now()
}

func GenerateBanMessage(banExpAt time.Time) string {
	diff := banExpAt.Sub(time.Now())
	timeLeft := int(diff.Round(time.Minute).Minutes())
	errorMessage := fmt.Sprintf("Try again in %d minutes.", timeLeft)
	if timeLeft <= 1 {
		errorMessage = fmt.Sprintf("Try again in 1 minute.")
	}
	return errorMessage
}