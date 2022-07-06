package utils

import (
	"golang.org/x/crypto/bcrypt"
	"github.com/golang-jwt/jwt"
	"github.com/xlzd/gotp"
	"encoding/base64"
	"time"
	"os"
	"fmt"
	"errors"
)

var secretLength int = 16
var totp *gotp.TOTP = gotp.NewDefaultTOTP(gotp.RandomSecret(secretLength))

func HashPassword(password string) (string, error) {
	const HASH_ROUNDS = 10
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), HASH_ROUNDS)
	return string(bytes), err
}

func ComparePasswords(hashedPassword, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}

func _GetJWTSecret(tokenType string, getOldKey bool) ([]byte, error) {
	var b64String string
	if tokenType == REFRESH_TYPE {
		b64String = os.Getenv(JWT_SECRET_KEY_REFRESH)
		if getOldKey {
			b64String = os.Getenv(JWT_SECRET_KEY_REFRESH_OLD)	
		}
	} else {
		b64String = os.Getenv(JWT_SECRET_KEY_ACCESS)
		if getOldKey {
			b64String = os.Getenv(JWT_SECRET_KEY_ACCESS_OLD)	
		}
	}
	return base64.StdEncoding.DecodeString(b64String)
}

func CreateJWTToken(displayName, tokenType string) (string, error) {
	signingKey, err := _GetJWTSecret(tokenType, false)
	if err != nil {
		return "", err
	}
	claims := jwt.MapClaims{}
	claims["displayName"] = displayName
	claims["tokenType"] = tokenType
	if tokenType == REFRESH_TYPE {
		claims["exp"] = time.Now().Add(time.Hour * 24 * REFRESH_TOKEN_DURATION).Unix()
	} else {
		claims["exp"] = time.Now().Add(time.Minute * ACCESS_TOKEN_DURATION).Unix()
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(signingKey)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func _ParseJWTToken(tokenString string, signingKey []byte) (*jwt.Token, error) {
	return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New(JWT_TOKEN_PARSING_ERROR)
		}
		return signingKey, nil
	})
}

func VerifyJWTToken(tokenType, tokenString string) (jwt.MapClaims, error, string) {
	signingKey, err := _GetJWTSecret(tokenType, false)
	if err != nil {
		return jwt.MapClaims{}, err, SERVER_DOWN
	}
	oldSigningKey, err := _GetJWTSecret(tokenType, true)
	if err != nil {
		return jwt.MapClaims{}, err, SERVER_DOWN
	}
	token1, errCurrentSecret := _ParseJWTToken(tokenString, signingKey)
	token2, errOldSecret := _ParseJWTToken(tokenString, oldSigningKey)
	if errCurrentSecret != nil && errOldSecret != nil {
		return jwt.MapClaims{}, errCurrentSecret, JWT_TOKEN_PARSING_ERROR
	}
	if claims, ok := token1.Claims.(jwt.MapClaims); ok && token1.Valid {
		return claims, nil, ""
	}
	if claims, ok := token2.Claims.(jwt.MapClaims); ok && token2.Valid {
		return claims, nil, ""
	}
	return jwt.MapClaims{}, errors.New(JWT_TOKEN_EXPIRED_ERROR), JWT_TOKEN_EXPIRED_ERROR
}

func GetVerificationCode() string {
	return totp.Now()
}

func GenerateBanMessage(banExpAt time.Time) string {
	diff := banExpAt.Sub(time.Now())
	timeLeft := int(diff.Round(time.Minute).Minutes())
	errorMessage := fmt.Sprintf("Please try again in %d minutes.", timeLeft)
	if timeLeft <= 1 {
		errorMessage = fmt.Sprintf("Please try again in 1 minute.")
	}
	return errorMessage
}